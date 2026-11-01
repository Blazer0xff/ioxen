import os
import re
import threading
import time
from dataclasses import dataclass
from datetime import datetime

from ioxen.agent_loader import load_agent_script, load_hook_config
from ioxen.filters import FilterManager
from ioxen.logging_ui import log_debug, log_error, log_info, log_success, log_warning
from ioxen.platforms import (
    IOS_LABEL,
    PLATFORM_PROBE_SCRIPT,
    detect_device_platform,
    unsupported_target_reason,
)
from ioxen.rendering import payload_to_filter_context, render_intercept_block


# Upper bounds for blocking Frida calls. A target that crashed can stay
# frozen (e.g. while iOS collects its crash report); without limits a call
# into it blocks the connect thread for good and the leftover app instance
# prevents every later spawn/attach until ioxen is restarted.
TIMEOUTS = {
    "enumerate": 15,
    "kill": 10,
    "spawn": 30,
    "attach": 20,
    "load": 30,
    "proxy": 120,
    "resume": 15,
    "rpc": 5,
    "detach": 5,
}


class FridaTimeout(Exception):
    pass


class TargetExited(Exception):
    pass


def call_with_timeout(fn, timeout: float, what: str, abort: threading.Event | None = None):
    """Run a blocking Frida call with an upper bound.

    On timeout the call keeps running in a daemon thread (Frida calls cannot
    be interrupted), but the caller is released and can recover. If `abort`
    is set while waiting (the target exited), TargetExited is raised at once.
    """
    result = {}

    def target():
        try:
            result["value"] = fn()
        except BaseException as e:  # noqa: BLE001 - re-raised in the caller
            result["error"] = e

    thread = threading.Thread(target=target, daemon=True, name=f"ioxen-{what}")
    thread.start()
    deadline = time.monotonic() + timeout
    while thread.is_alive():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise FridaTimeout(f"{what} did not finish within {timeout:.0f} s")
        if abort is not None and abort.is_set():
            raise TargetExited(f"the target exited while {what[0].lower() + what[1:]}")
        thread.join(min(0.1, remaining))
    if "error" in result:
        raise result["error"]
    return result.get("value")


@dataclass
class SessionConfig:
    spawn_package: str | None = None
    attach_name: str | None = None
    attach_pid: int | None = None
    custom_hooks: str | None = None
    extra_script: str | None = None

    def target_label(self) -> str:
        if self.spawn_package:
            return self.spawn_package
        if self.attach_name:
            return self.attach_name
        if self.attach_pid is not None:
            return f"PID {self.attach_pid}"
        return ""


class FridaSession:
    def __init__(
        self,
        config: SessionConfig,
        filter_manager: FilterManager,
        log_cb: callable,
        intercept_cb: callable,
        get_stack: callable,
        history_cb: callable = None,
        outcome_cb: callable = None,
        intercept_log_cb: callable = None,
        initial_intercept: bool = True,
    ):
        self._config = config
        self.filter_manager = filter_manager
        self.log_cb = log_cb
        self.intercept_cb = intercept_cb
        self.get_stack = get_stack
        self.history_cb = history_cb
        self.outcome_cb = outcome_cb
        self.intercept_log_cb = intercept_log_cb
        self.initial_intercept = initial_intercept
        self.platform_cb = None
        self.connected_cb = None
        self.disconnected_cb = None

        self._script = None
        self._session = None
        self._device = None
        self._target_pid = None
        self._detached = threading.Event()
        self._device_id = None
        self._connect_thread = None
        self._lock = threading.Lock()
        self._generation = 0
        self._blocking_enabled = True
        self._intercept_counter = 0
        self._history_counter = 0
        self._stale_messages = 0

    def connect(self, device_id):
        with self._lock:
            self._device_id = device_id
            self._generation += 1
            generation = self._generation
            self._connect_thread = threading.Thread(
                target=self._start_session,
                args=(generation, device_id),
                daemon=True,
            )
            self._connect_thread.start()

    def _start_session(self, generation, device_id):
        try:
            import frida
            if self._is_stale(generation):
                return
            client_version = getattr(frida, "__version__", "unknown")
            self.log_cb(log_info(f"Connecting to device {device_id} (frida {client_version})", "frida"))
            device = frida.get_device(device_id, timeout=5)
        except Exception as e:
            if self._is_stale(generation):
                return
            self.log_cb(log_error(f"Connection failed: {e}", "frida"))
            return

        device_info = detect_device_platform(device)

        try:
            pid = None
            should_resume = False
            session = None
            def close_local(script=None):
                self._detach_stale_session(
                    session,
                    script,
                    device=device,
                    spawned_pid=pid if should_resume else None,
                )

            if self._config.spawn_package:
                package = self._config.spawn_package
                self._kill_running_instance(device, package)
                pid = call_with_timeout(lambda: device.spawn([package]), TIMEOUTS["spawn"], f"Spawning {package}")
                try:
                    session = call_with_timeout(lambda: device.attach(pid), TIMEOUTS["attach"], f"Attaching to PID {pid}")
                except Exception:
                    # The app is suspended at launch; never leave it behind.
                    self._kill_async(device, pid)
                    self._log_spawn_terminated(pid)
                    raise
                session.on("detached", self._on_detached)
                should_resume = True
                self.log_cb(log_success(f"Spawned {package} (PID {pid})", "frida"))
            elif self._config.attach_name:
                name = self._config.attach_name
                session = call_with_timeout(lambda: device.attach(name), TIMEOUTS["attach"], f"Attaching to {name}")
                session.on("detached", self._on_detached)
                pid = getattr(session, 'pid', None)
                pid_str = f" (PID {pid})" if pid else ""
                self.log_cb(log_success(f"Attached to \"{name}\"{pid_str}", "frida"))
            elif self._config.attach_pid:
                target_pid = self._config.attach_pid
                session = call_with_timeout(lambda: device.attach(target_pid), TIMEOUTS["attach"], f"Attaching to PID {target_pid}")
                session.on("detached", self._on_detached)
                self.log_cb(log_success(f"Attached to PID {target_pid}", "frida"))
            else:
                self.log_cb(log_error("No target specified", "frida"))
                return

            if not self._keep_if_current(generation, session=session):
                close_local()
                return
            with self._lock:
                self._device = device
                self._target_pid = pid if pid is not None else self._config.attach_pid

        except Exception as e:
            if self._is_stale(generation):
                return
            self.log_cb(log_error(f"Connection failed: {e}", "frida"))
            if isinstance(e, FridaTimeout):
                self.log_cb(log_warning(
                    "The device did not answer in time. If the app just crashed, iOS may still be "
                    "collecting its crash report; wait a few seconds and connect again",
                    "frida",
                ))
            return

        self._check_target_platform(session, device_info)
        hooks_result = load_hook_config(self._config.custom_hooks)
        hooks_data = hooks_result.hooks
        for message in hooks_result.messages:
            self.log_cb(message)

        try:
            if self._is_stale(generation):
                close_local()
                return
            script_result = load_agent_script(self._config.extra_script)
            code = script_result.code
            for message in script_result.messages:
                self.log_cb(message)
        except Exception as e:
            self._clear_if_current(generation, session=session)
            close_local()
            self.log_cb(log_error(f"Failed to load agent script: {e}", "frida"))
            self._log_spawn_terminated(pid if should_resume else None)
            return

        try:
            script = session.create_script(code)
            script.on("message", lambda message, data, source=script: self._on_script_message(source, message, data))
            if not self._keep_if_current(generation, session=session, script=script):
                close_local(script)
                return

            call_with_timeout(script.load, TIMEOUTS["load"], "Loading the agent", self._detached)
            if self._is_stale(generation):
                close_local(script)
                return

            self._push_filters(script)

            call_with_timeout(lambda: script.exports_sync.proxy(hooks_data), TIMEOUTS["proxy"], "Installing hooks", self._detached)
            if self._is_stale(generation):
                close_local(script)
                return

            self._log_process_info(script)

            if not self.initial_intercept:
                self._blocking_enabled = False
                call_with_timeout(lambda: self._release_held(script), TIMEOUTS["rpc"], "Switching interception off", self._detached)

            if self._is_stale(generation):
                close_local(script)
                return

            if should_resume:
                call_with_timeout(lambda: device.resume(pid), TIMEOUTS["resume"], f"Resuming PID {pid}")

            if not self._is_stale(generation) and self.connected_cb:
                self.connected_cb()


        except Exception as e:
            if self._is_stale(generation):
                close_local(locals().get("script"))
                return
            self._clear_if_current(generation, session=session, script=locals().get("script"))
            close_local(locals().get("script"))
            self.log_cb(log_error(f"Failed to start session: {e}", "frida"))
            if isinstance(e, TargetExited) or self._detached.is_set():
                self._explain_exit_during_setup()
            self._log_spawn_terminated(pid if should_resume else None)

    def _explain_exit_during_setup(self) -> None:
        label = getattr(self, "_platform_label", None) or IOS_LABEL
        self.log_cb(log_error(
            f"The app exited while ioxen was loading its agent ({label}). See any 'Native exception' "
            "lines above; try examples/ios/no-hooks.json to check whether a hook is responsible",
            "frida",
        ))

    def _log_spawn_terminated(self, pid) -> None:
        if pid is None:
            return
        self.log_cb(log_error(
            f"Terminated the spawned app (PID {pid}) because session setup failed; "
            "it would otherwise stay suspended. This is not a crash of the app itself",
            "frida",
        ))

    def _probe_process_platform(self, session) -> str | None:
        """Return Frida's Process.platform of the target (e.g. "darwin"), or None."""
        def probe_platform():
            probe = session.create_script(PLATFORM_PROBE_SCRIPT)
            probe.load()
            try:
                return probe.exports_sync.platform()
            finally:
                try:
                    probe.unload()
                except Exception:
                    pass

        try:
            value = call_with_timeout(probe_platform, TIMEOUTS["load"], "Probing the target", self._detached)
            return str(value).lower() if value else None
        except Exception:
            return None

    def _kill_running_instance(self, device, identifier: str) -> None:
        """Kill an already running instance before spawning a fresh one.

        A previous instance can be left frozen by a crash or a failed session;
        spawning or attaching next to it fails or hangs.
        """
        def find_pid():
            try:
                apps = device.enumerate_applications(identifiers=[identifier])
            except TypeError:
                apps = device.enumerate_applications()
            for app in apps:
                if getattr(app, "identifier", None) == identifier and getattr(app, "pid", 0):
                    return app.pid
            return None

        try:
            pid = call_with_timeout(find_pid, TIMEOUTS["enumerate"], "Checking for a running instance")
        except Exception:
            return
        if not pid:
            return
        self.log_cb(log_warning(f"{identifier} is already running (PID {pid}); killing it before spawning", "frida"))
        try:
            call_with_timeout(lambda: device.kill(pid), TIMEOUTS["kill"], f"Killing PID {pid}")
            time.sleep(0.5)
        except Exception as e:
            self.log_cb(log_warning(f"Could not kill PID {pid}: {e}", "frida"))

    def _kill_async(self, device, pid) -> None:
        def kill():
            try:
                call_with_timeout(lambda: device.kill(pid), TIMEOUTS["kill"], f"Killing PID {pid}")
            except Exception:
                pass
        threading.Thread(target=kill, daemon=True, name="ioxen-kill").start()

    def _check_target_platform(self, session, device_info) -> None:
        """Label the session and warn when the target is not an Apple process."""
        process_platform = self._probe_process_platform(session)
        label = device_info.label or IOS_LABEL
        self._platform_label = label
        reason = unsupported_target_reason(device_info, process_platform)
        if reason:
            self.log_cb(log_warning(
                f"ioxen only supports iOS and other Apple targets, but {reason}; the agent will not work",
                "frida",
            ))
        else:
            self.log_cb(log_info(f"Platform: {label}", "frida"))
        if self.platform_cb:
            self.platform_cb(label)

    def _on_detached(self, reason, crash=None):
        self._detached.set()
        msg = reason.replace("-", " ") if reason else "unknown reason"
        self.log_cb(log_warning(f"Session detached: {msg}", "frida"))
        if crash is not None:
            self._report_crash(crash)
        elif reason in ("connection-terminated", "device-lost"):
            self.log_cb(log_warning(
                "Lost the connection to frida-server; check USB and that frida-server is still running",
                "frida",
            ))
        with self._lock:
            self._script = None
            self._session = None
        if self.disconnected_cb:
            self.disconnected_cb()

    # How long to wait for a target that reported a native exception to exit
    # before telling the user it is still around.
    CRASH_GRACE_SECONDS = 5.0

    def _handle_agent_crash(self, payload: dict) -> None:
        """The agent saw a native exception in the target.

        It is only reported, never acted on: some code raises and handles its
        own exceptions (anti-debugging, crash reporters, JavaScript engines),
        and a process that froze after a real crash cannot be told apart
        from one that recovered (its agent keeps answering). A real crash
        ends the session through Frida's detach event; a frozen leftover is
        cleaned up by /kill or by the next spawn.
        """
        memory = payload.get("memory") or {}
        where = f" at {payload['address']}" if payload.get("address") else ""
        access = f" ({memory.get('operation')} {memory.get('address')})" if memory else ""
        self.log_cb(log_error(
            f"Native exception in target: {payload.get('type', 'unknown')}{where}{access} "
            f"on thread {payload.get('threadId')}",
            "crash",
        ))
        for frame in (payload.get("stackTrace") or [])[:12]:
            self.log_cb(log_error(f"  {frame}", "crash"))

        def follow_up():
            if self._detached.wait(self.CRASH_GRACE_SECONDS):
                return
            self.log_cb(log_warning(
                "The target is still running after the exception, so the app either handled it "
                "or is frozen. If it is frozen, run /kill or connect again (Spawn kills the old "
                "instance first)",
                "crash",
            ))

        threading.Thread(target=follow_up, daemon=True, name="ioxen-crash-follow-up").start()

    def kill_target(self) -> int | None:
        """Kill the target process. Returns its PID, or None if unknown."""
        with self._lock:
            device = self._device
            pid = self._target_pid
        if device is None or pid is None:
            return None
        call_with_timeout(lambda: device.kill(pid), TIMEOUTS["kill"], f"Killing PID {pid}")
        return pid

    def _report_crash(self, crash) -> None:
        process = getattr(crash, "process_name", None) or "target"
        pid = getattr(crash, "pid", None)
        summary = (getattr(crash, "summary", None) or "").strip()
        self.log_cb(log_error(f"{process} (PID {pid}) crashed: {summary or 'no summary'}", "crash"))
        report = getattr(crash, "report", None)
        if not report:
            return
        safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", str(process))
        filename = f"crash_{safe_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write(str(report))
            self.log_cb(log_info(f"Crash report saved to {os.path.abspath(filename)}", "crash"))
        except OSError as e:
            self.log_cb(log_warning(f"Could not save crash report: {e}", "crash"))

    def _is_stale(self, generation) -> bool:
        with self._lock:
            return generation != self._generation

    def _keep_if_current(self, generation, session=None, script=None) -> bool:
        with self._lock:
            if generation != self._generation:
                return False
            if session is not None:
                self._session = session
            if script is not None:
                self._script = script
            return True

    def _clear_if_current(self, generation, session=None, script=None) -> None:
        with self._lock:
            if generation != self._generation:
                return
            if session is not None and self._session is session:
                self._session = None
            if script is not None and self._script is script:
                self._script = None

    def _push_filters(self, script) -> bool:
        ignore_list, focus_list = self.filter_manager.get_active()
        try:
            script.exports_sync.set_filters(ignore_list, focus_list)
            return True
        except Exception as e:
            self.log_cb(log_warning(f"Could not push intercept filters to agent: {e}", "frida"))
            return False

    def _log_process_info(self, script) -> None:
        try:
            info = script.exports_sync.get_process_info() or {}
        except Exception:
            return
        missing = []
        if info.get("xpc") is False:
            missing.append("XPC block support")
        if info.get("objc") is False:
            missing.append("Objective-C runtime")
        if missing:
            self.log_cb(log_warning(f"Agent limited: {', '.join(missing)} unavailable", "agent"))

    def sync_filters(self) -> bool:
        """Push the active intercept filters into the agent.

        The agent evaluates them before holding a thread, so filtered
        events never wait for a host round trip.
        """
        with self._lock:
            script = self._script
        if script is None:
            return False
        return self._push_filters(script)

    @staticmethod
    def _wake(script, decision_id) -> None:
        # The agent parks held threads in recv("ioxen-wake:<id>").wait().
        if script is None or not isinstance(decision_id, str) or not decision_id:
            return
        try:
            script.post({"type": f"ioxen-wake:{decision_id}"})
        except Exception:
            pass

    @classmethod
    def _release_held(cls, script) -> None:
        released = script.exports_sync.interceptoff()
        cls._wake(script, released)

    @classmethod
    def _detach_stale_session(cls, session, script=None, device=None, spawned_pid=None) -> None:
        """Tear down a session in the background; each step is time-limited."""
        def teardown():
            if script:
                try:
                    call_with_timeout(lambda: cls._release_held(script), TIMEOUTS["rpc"], "Releasing held events")
                except Exception:
                    pass
            if session:
                try:
                    call_with_timeout(session.detach, TIMEOUTS["detach"], "Detaching")
                except Exception:
                    pass
            if device and spawned_pid is not None:
                try:
                    call_with_timeout(lambda: device.kill(spawned_pid), TIMEOUTS["kill"], f"Killing PID {spawned_pid}")
                except Exception:
                    try:
                        call_with_timeout(lambda: device.resume(spawned_pid), TIMEOUTS["resume"], f"Resuming PID {spawned_pid}")
                    except Exception:
                        pass

        thread = threading.Thread(target=teardown, daemon=True, name="ioxen-teardown")
        thread.start()
        thread.join(timeout=1.0)

    def _on_script_message(self, source, message, data):
        """Deliver a message only while its script is the current one.

        After Disconnect (or a new Connect) Frida may still hand over messages
        that were already queued; they belong to a closed session.
        """
        with self._lock:
            current = self._script is source
        if not current:
            self._stale_messages += 1
            return
        self.on_message(message, data)

    def on_message(self, message, data):
        show_stack, stack_depth = self.get_stack()

        if message["type"] == "send":
            payload = message["payload"]
            if isinstance(payload, dict):
                if payload.get("ioxenEvent") == "crash":
                    self._handle_agent_crash(payload)
                    return

                self._history_counter += 1
                db_id = None
                if self.history_cb:
                    try:
                        db_id = self.history_cb(payload, self._history_counter)
                    except Exception as e:
                        self.log_cb(log_warning(f"History callback failed: {e}", "history"))

                decision = payload.get("decision") if isinstance(payload.get("decision"), dict) else {}
                requires_decision = bool(decision.get("required")) if "required" in decision else self._blocking_enabled
                decision_id = decision.get("id")
                is_visible = self.filter_manager.is_visible(payload_to_filter_context(payload))

                if not requires_decision:
                    if self.outcome_cb and db_id:
                        self.outcome_cb(db_id, "forwarded")
                elif not is_visible or not self._blocking_enabled:
                    self._forward_async(decision_id, db_id)
                else:
                    self._intercept_counter += 1
                    rendered = render_intercept_block(
                        payload,
                        self._intercept_counter,
                        show_stack,
                        stack_depth,
                    )
                    if self.intercept_log_cb:
                        self.intercept_log_cb(rendered, db_id, decision_id)
                    else:
                        self.log_cb(rendered)
                    self.intercept_cb(True)
            else:
                self.log_cb(self._format_js_message(payload))
        elif message["type"] == "error":
            self.log_cb(log_error(f"JavaScript error: {message['description']}", "agent"))

    def _resume(self, action: str, decision_id) -> bool:
        script = self._script
        if action == "forward":
            resumed = bool(script.exports_sync.forward(decision_id))
        else:
            resumed = bool(script.exports_sync.drop(decision_id))
        if resumed:
            self._wake(script, decision_id)
        return resumed

    def _forward_async(self, decision_id, db_id):
        def _resume():
            try:
                resumed = self._resume("forward", decision_id)
            except Exception as e:
                self.log_cb(log_warning(f"Auto-forward failed: {e}", "frida"))
                return
            if resumed and self.outcome_cb and db_id:
                self.outcome_cb(db_id, "forwarded")

        threading.Thread(target=_resume, daemon=True).start()

    @staticmethod
    def _format_js_message(text):
        if text.startswith("[!]"):
            return log_error(text[3:].strip(), "agent")
        if text.startswith("[*]") or text.startswith("[+]"):
            return log_success(text[3:].strip(), "agent")
        if text.startswith("[~]"):
            return log_warning(text[3:].strip(), "agent")
        return log_debug(text, "agent")

    def forward(self, decision_id=None):
        return self._resume("forward", decision_id)

    def drop(self, decision_id=None):
        return self._resume("drop", decision_id)

    def stage_mod(self, mod_type, key, val, extra_type, decision_id=None):
        return bool(self._script.exports_sync.stage_mod(mod_type, key, val, extra_type, decision_id))

    def intercept_on(self):
        self._blocking_enabled = True
        self._script.exports_sync.intercepton()

    def intercept_off(self):
        self._blocking_enabled = False
        self._release_held(self._script)

    def get_attack_surface(self) -> dict:
        return self._script.exports_sync.get_attack_surface() or {}

    def is_ready(self) -> bool:
        with self._lock:
            return self._script is not None

    def cleanup(self):
        with self._lock:
            script = self._script
            session = self._session
            self._script = None
            self._session = None
            self._generation += 1

        def perform_cleanup():
            if script:
                try:
                    call_with_timeout(lambda: self._release_held(script), TIMEOUTS["rpc"], "Releasing held events")
                except Exception:
                    pass
            if session:
                try:
                    call_with_timeout(session.detach, TIMEOUTS["detach"], "Detaching")
                except Exception:
                    pass

        cleanup_thread = threading.Thread(target=perform_cleanup, daemon=True)
        cleanup_thread.start()
        cleanup_thread.join(timeout=0.5)
