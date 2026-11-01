"""Recovery after target crashes and hung Frida calls.

A crashed iOS app can stay frozen while its crash report is collected, so
Frida calls into it may never return. These tests check that ioxen bounds
every blocking call, never leaves a spawned app suspended, and reports
crashes.
"""

import os
import sys
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from ioxen.agent_loader import HooksLoadResult, ScriptLoadResult
from ioxen.filters import FilterManager
from ioxen.frida_session import FridaSession, FridaTimeout, SessionConfig, TargetExited, call_with_timeout

FAST = {"enumerate": 0.3, "kill": 0.3, "spawn": 0.3, "attach": 0.3, "load": 0.3,
        "proxy": 0.3, "resume": 0.3, "rpc": 0.3, "detach": 0.3}
FOREVER = threading.Event()  # never set: used to simulate hung Frida calls


class CallWithTimeoutTests(unittest.TestCase):
    def test_returns_value_and_reraises_errors(self):
        self.assertEqual(call_with_timeout(lambda: 42, 1, "x"), 42)
        with self.assertRaises(ValueError):
            call_with_timeout(lambda: (_ for _ in ()).throw(ValueError("boom")), 1, "x")

    def test_times_out(self):
        started = time.monotonic()
        with self.assertRaises(FridaTimeout) as ctx:
            call_with_timeout(lambda: FOREVER.wait(), 0.2, "Hanging call")
        self.assertLess(time.monotonic() - started, 1.5)
        self.assertIn("Hanging call did not finish", str(ctx.exception))


class _Script:
    def __init__(self, device):
        self.device = device
        outer = self

        class Exports:
            def platform(self):
                return "darwin"

            def proxy(self, _hooks):
                if outer.device.hang_proxy:
                    FOREVER.wait()

            def set_filters(self, *_args):
                return True

            def get_process_info(self):
                return {}

            def interceptoff(self):
                return None

        self.exports_sync = Exports()

    def on(self, *_args):
        pass

    def load(self):
        pass

    def unload(self):
        pass

    def post(self, _message):
        pass


class _Session:
    def __init__(self, device):
        self.device = device
        self.callbacks = {}
        self.detached = False

    def on(self, name, cb):
        self.callbacks[name] = cb

    def create_script(self, _code):
        return _Script(self.device)

    def detach(self):
        self.detached = True


class _Device:
    def __init__(self, running_pid=0, attach="ok", hang_proxy=False):
        self.running_pid = running_pid
        self.attach_mode = attach
        self.hang_proxy = hang_proxy
        self.killed = []
        self.resumed = []
        self.spawned = []
        self.session = None

    def query_system_parameters(self):
        return {"os": {"id": "ios", "name": "iOS", "version": "17.0"}}

    def enumerate_applications(self, identifiers=None):
        return [SimpleNamespace(identifier="com.example.app", name="Example", pid=self.running_pid)]

    def spawn(self, argv):
        self.spawned.append(argv)
        return 4242

    def attach(self, _pid):
        if self.attach_mode == "fail":
            raise RuntimeError("unable to attach")
        if self.attach_mode == "hang":
            FOREVER.wait()
        self.session = _Session(self)
        return self.session

    def kill(self, pid):
        self.killed.append(pid)

    def resume(self, pid):
        self.resumed.append(pid)


def run_connect(device, spawn="com.example.app", timeout=5):
    logs = []
    connected = threading.Event()
    session = FridaSession(
        SessionConfig(spawn_package=spawn),
        FilterManager(),
        log_cb=logs.append,
        intercept_cb=lambda _s: None,
        get_stack=lambda: (False, 0),
    )
    session.connected_cb = connected.set
    with patch.dict(sys.modules, {"frida": SimpleNamespace(get_device=lambda _id, timeout=5: device, __version__="17.16.4")}), \
            patch("ioxen.frida_session.TIMEOUTS", FAST), \
            patch("ioxen.frida_session.load_hook_config", return_value=HooksLoadResult([], [])), \
            patch("ioxen.frida_session.load_agent_script", return_value=ScriptLoadResult("agent", [])):
        session.connect("usb-1")
        session._connect_thread.join(timeout=timeout)
        time.sleep(0.6)  # background teardown / kill threads
    return session, "\n".join(logs), connected.is_set()


class SessionRecoveryTests(unittest.TestCase):
    def test_happy_path_spawns_and_resumes(self):
        device = _Device()
        session, _logs, connected = run_connect(device)
        self.assertTrue(connected)
        self.assertEqual(device.resumed, [4242])
        self.assertEqual(device.killed, [])
        self.assertFalse(session._connect_thread.is_alive())

    def test_running_instance_is_killed_before_spawning(self):
        device = _Device(running_pid=777)
        _session, logs, connected = run_connect(device)
        self.assertTrue(connected)
        self.assertEqual(device.killed, [777])
        self.assertIn("already running (PID 777); killing it before spawning", logs)

    def test_failed_attach_after_spawn_kills_the_suspended_app(self):
        device = _Device(attach="fail")
        _session, logs, connected = run_connect(device)
        self.assertFalse(connected)
        self.assertEqual(device.killed, [4242])
        self.assertIn("Connection failed: unable to attach", logs)
        self.assertIn("Terminated the spawned app (PID 4242)", logs)

    def test_hung_attach_times_out_and_kills_the_suspended_app(self):
        device = _Device(attach="hang")
        session, logs, connected = run_connect(device)
        self.assertFalse(connected)
        self.assertFalse(session._connect_thread.is_alive())
        self.assertEqual(device.killed, [4242])
        self.assertIn("did not finish within", logs)
        self.assertIn("collecting its crash report", logs)

    def test_hung_hook_installation_times_out_and_cleans_up(self):
        device = _Device(hang_proxy=True)
        session, logs, connected = run_connect(device)
        self.assertFalse(connected)
        self.assertFalse(session._connect_thread.is_alive())
        self.assertIn("Installing hooks did not finish", logs)
        self.assertEqual(device.killed, [4242])
        self.assertTrue(device.session.detached)

    def test_crash_is_reported_and_saved(self):
        logs = []
        disconnected = []
        session = FridaSession(SessionConfig(attach_pid=1), FilterManager(), log_cb=logs.append,
                               intercept_cb=lambda _s: None, get_stack=lambda: (False, 0))
        session.disconnected_cb = lambda: disconnected.append(True)
        crash = SimpleNamespace(pid=4242, process_name="DVIA-v2", summary="EXC_BAD_ACCESS (SIGSEGV)",
                                report="Exception Type: EXC_BAD_ACCESS\nThread 0 Crashed")
        with tempfile.TemporaryDirectory() as tmp:
            cwd = os.getcwd()
            os.chdir(tmp)
            try:
                session._on_detached("process-terminated", crash)
                files = os.listdir(tmp)
                with open(files[0], encoding="utf-8") as f:
                    content = f.read()
            finally:
                os.chdir(cwd)
        text = "\n".join(logs)
        self.assertIn("DVIA-v2 (PID 4242) crashed: EXC_BAD_ACCESS (SIGSEGV)", text)
        self.assertIn("Crash report saved to", text)
        self.assertTrue(files[0].startswith("crash_DVIA-v2_"))
        self.assertIn("Thread 0 Crashed", content)
        self.assertEqual(disconnected, [True])

    def test_lost_device_connection_is_explained(self):
        logs = []
        session = FridaSession(SessionConfig(attach_pid=1), FilterManager(), log_cb=logs.append,
                               intercept_cb=lambda _s: None, get_stack=lambda: (False, 0))
        session._on_detached("connection-terminated", None)
        self.assertIn("frida-server", "\n".join(logs))

    def test_cleanup_does_not_block_on_a_frozen_target(self):
        session = FridaSession(SessionConfig(attach_pid=1), FilterManager(), log_cb=lambda _t: None,
                               intercept_cb=lambda _s: None, get_stack=lambda: (False, 0))
        frozen = SimpleNamespace(exports_sync=SimpleNamespace(interceptoff=lambda: FOREVER.wait()), post=lambda _m: None)
        session._script = frozen
        session._session = SimpleNamespace(detach=lambda: FOREVER.wait())
        started = time.monotonic()
        with patch("ioxen.frida_session.TIMEOUTS", FAST):
            session.cleanup()
        self.assertLess(time.monotonic() - started, 1.0)
        self.assertFalse(session.is_ready())


if __name__ == "__main__":
    unittest.main()


class AgentExceptionEventTests(unittest.TestCase):
    def _session(self, logs, device):
        session = FridaSession(SessionConfig(attach_pid=99), FilterManager(), log_cb=logs.append,
                               intercept_cb=lambda _s: None, get_stack=lambda: (False, 0))
        session._device = device
        session._target_pid = 99
        session.CRASH_GRACE_SECONDS = 0.2
        return session

    def test_exception_is_reported_but_target_is_never_killed(self):
        logs = []
        device = _Device()
        session = self._session(logs, device)
        session.on_message({"type": "send", "payload": {
            "ioxenEvent": "crash", "pid": 99, "type": "access-violation", "address": "MyApp!0x1234",
            "memory": {"operation": "read", "address": "0x0"}, "threadId": 7,
            "stackTrace": ["MyApp!0x1234", "Foundation!0x99"],
        }}, None)
        time.sleep(0.6)
        text = "\n".join(logs)
        self.assertIn("Native exception in target: access-violation at MyApp!0x1234 (read 0x0) on thread 7", text)
        self.assertIn("Foundation!0x99", text)
        self.assertIn("still running after the exception", text)
        self.assertIn("/kill", text)
        self.assertEqual(device.killed, [])

    def test_no_follow_up_when_the_target_exits(self):
        logs = []
        device = _Device()
        session = self._session(logs, device)
        session.on_message({"type": "send", "payload": {"ioxenEvent": "crash", "type": "abort"}}, None)
        session._on_detached("process-terminated", None)
        time.sleep(0.5)
        self.assertEqual(device.killed, [])
        self.assertNotIn("still running after the exception", "\n".join(logs))

    def test_exception_event_does_not_reach_history(self):
        history = []
        session = FridaSession(SessionConfig(attach_pid=1), FilterManager(), log_cb=lambda _t: None,
                               intercept_cb=lambda _s: None, get_stack=lambda: (False, 0),
                               history_cb=lambda p, c: history.append(p))
        session.CRASH_GRACE_SECONDS = 0.05
        session.on_message({"type": "send", "payload": {"ioxenEvent": "crash", "type": "abort"}}, None)
        self.assertEqual(history, [])

    def test_kill_target(self):
        device = _Device()
        session = self._session([], device)
        with patch("ioxen.frida_session.TIMEOUTS", FAST):
            self.assertEqual(session.kill_target(), 99)
        self.assertEqual(device.killed, [99])
        session._device = None
        self.assertIsNone(session.kill_target())



class TargetExitDuringSetupTests(unittest.TestCase):
    def test_call_with_timeout_aborts_when_the_target_exits(self):
        abort = threading.Event()
        threading.Timer(0.2, abort.set).start()
        started = time.monotonic()
        with self.assertRaises(TargetExited) as ctx:
            call_with_timeout(lambda: FOREVER.wait(), 30, "Installing hooks", abort)
        self.assertLess(time.monotonic() - started, 1.5)
        self.assertIn("the target exited while installing hooks", str(ctx.exception))

    def _connect_and_die_during_proxy(self):
        device = _Device(hang_proxy=True)
        logs = []
        session = FridaSession(
            SessionConfig(spawn_package="com.example.app"),
            FilterManager(), log_cb=logs.append, intercept_cb=lambda _s: None, get_stack=lambda: (False, 0),
        )

        def die_later():
            while device.session is None:
                time.sleep(0.02)
            time.sleep(0.2)
            device.session.callbacks["detached"]("process-terminated", None)

        threading.Thread(target=die_later, daemon=True).start()
        slow = dict(FAST, proxy=30, load=30)
        started = time.monotonic()
        with patch.dict(sys.modules, {"frida": SimpleNamespace(get_device=lambda _id, timeout=5: device, __version__="17.16.4")}), \
                patch("ioxen.frida_session.TIMEOUTS", slow), \
                patch("ioxen.frida_session.load_hook_config", return_value=HooksLoadResult([], [])), \
                patch("ioxen.frida_session.load_agent_script", return_value=ScriptLoadResult("agent", [])):
            session.connect("usb-1")
            session._connect_thread.join(timeout=10)
        return "\n".join(logs), time.monotonic() - started

    def test_app_dying_during_setup_is_explained_promptly(self):
        logs, elapsed = self._connect_and_die_during_proxy()
        self.assertLess(elapsed, 5)
        self.assertIn("Connecting to device usb-1 (frida 17.16.4)", logs)
        self.assertIn("Failed to start session: the target exited while installing hooks", logs)
        self.assertIn("The app exited while ioxen was loading its agent (iOS 17.0)", logs)
        self.assertIn("no-hooks.json", logs)
        self.assertNotIn("must match", logs)
