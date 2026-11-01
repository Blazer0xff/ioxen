import base64
import os
import plistlib
import sqlite3
import sys
import tempfile
import threading
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from ioxen.agent_loader import (
    PASSTHROUGH_AGENT,
    HooksLoadResult,
    load_agent_script,
    load_hook_config,
)
from ioxen.commands import HELP_MENU, INTERCEPT_COMPLETIONS, HISTORY_COMPLETIONS, parse_surface_command
from ioxen.db import ProjectDB
from ioxen.filters import FilterManager
from ioxen.frida_session import FridaSession, SessionConfig
from ioxen.intent_mods import apply_mods_to_entry, ios_editable_type, parse_intent_mod_command, validate_mod_for_entry
from ioxen.ios_surface import build_surface, parse_entitlements, render_surface_report, summarize_observed
from ioxen.platforms import (
    IOS,
    detect_device_platform,
    PlatformInfo,
    platform_from_system_parameters,
    unsupported_target_reason,
)
from ioxen.rendering import (
    entry_to_filter_context,
    history_search_matches,
    payload_to_filter_context,
    payload_to_history_entry,
    render_intercept_block,
    render_intent_detail,
)


IOS_PARAMS = {"os": {"id": "ios", "name": "iOS", "version": "17.4.1"}, "platform": "darwin", "arch": "arm64"}
ANDROID_PARAMS = {"os": {"id": "android", "name": "Android", "version": "14"}, "platform": "linux"}


def xpc_payload(**overrides):
    payload = {
        "platform": "ios",
        "eventId": "ev-1-3",
        "className": "MyApp",
        "methodName": "xpc_connection_send_message_with_reply",
        "stackTrace": ["0x1 MyApp!-[Client fetch]"],
        "infoIntent": {
            "component": "com.example.helper",
            "action": "fetchItem:withReply:",
            "data": None,
            "extras": {
                "root": {"type": "data", "value": "40 bytes bplist16 6270…"},
                "request/id": {"type": "int64", "value": "7"},
                "request/name": {"type": "string", "value": "alice"},
            },
        },
        "attackSurface": {"platform": "ios", "direction": "outgoing", "serviceKind": "mach"},
        "ipc": {
            "kind": "xpc",
            "direction": "outgoing",
            "connection": {"name": "com.example.helper", "kind": "mach", "listener": False, "privileged": False},
            "peer": {"pid": 321, "euid": 501, "path": "/usr/libexec/helperd"},
            "messageType": "dictionary",
            "expectsReply": True,
            "nsxpc": {"encoding": "bplist16", "selector": "fetchItem:withReply:", "strings": []},
            "selectorSource": "nsxpc",
            "blobs": [{"path": "root", "length": 40, "format": "bplist16", "strings": ["fetchItem:withReply:", "NSString"]}],
            "description": "<dictionary: 0x1> { count = 3 }",
        },
        "decision": {"required": True, "id": "decision-1-1", "reason": None, "mods": ["extra_add", "extra_rem"]},
    }
    payload.update(overrides)
    return payload


class PlatformTests(unittest.TestCase):
    def test_system_parameters_map_to_platforms(self):
        info = platform_from_system_parameters(IOS_PARAMS)
        self.assertEqual((info.platform, info.label), (IOS, "iOS 17.4.1"))
        android = platform_from_system_parameters(ANDROID_PARAMS)
        self.assertEqual((android.platform, android.os_id), (None, "android"))
        self.assertEqual(platform_from_system_parameters({"os": {"id": "macos"}}).platform, IOS)
        self.assertEqual(platform_from_system_parameters({"platform": "darwin"}).platform, IOS)
        self.assertEqual(platform_from_system_parameters({"platform": "darwin"}).label, "iOS")
        self.assertIsNone(platform_from_system_parameters({"os": {"id": "linux"}}).platform)
        self.assertIsNone(platform_from_system_parameters(None).platform)

    def test_detect_handles_devices_without_query_support(self):
        self.assertIsNone(detect_device_platform(SimpleNamespace()).platform)

        def boom():
            raise RuntimeError("no")

        self.assertIsNone(detect_device_platform(SimpleNamespace(query_system_parameters=boom)).platform)

    def test_unsupported_target_reason_prefers_process_then_device(self):
        unknown = PlatformInfo(None, "")
        ios = platform_from_system_parameters(IOS_PARAMS)
        android = platform_from_system_parameters(ANDROID_PARAMS)
        self.assertIsNone(unsupported_target_reason(unknown, "darwin"))
        self.assertIsNone(unsupported_target_reason(android, "darwin"))
        self.assertIsNone(unsupported_target_reason(ios, None))
        self.assertIsNone(unsupported_target_reason(unknown, None))
        self.assertEqual(unsupported_target_reason(ios, "linux"), "the target process runs on linux")
        self.assertEqual(unsupported_target_reason(android, None), "the device runs Android 14")


class IOSLoaderTests(unittest.TestCase):
    def test_default_ios_assets_resolve(self):
        hooks = load_hook_config()
        self.assertEqual(hooks.messages, [])
        kinds = {hook["kind"] for hook in hooks.hooks}
        self.assertTrue({"xpc", "nsxpc", "url", "notify"} <= kinds)
        self.assertFalse(any("clazz" in hook for hook in hooks.hooks))

        script = load_agent_script()
        self.assertEqual(script.messages, [])
        self.assertIn("ioxen-wake:", script.code)
        self.assertIn("xpc_connection_send_message", script.code)
        self.assertNotIn("frida-java-bridge", script.code)

    def test_missing_ios_bundle_uses_passthrough_and_appends_extra(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "ios_script_bundle.js"
            extra = Path(tmp) / "extra.js"
            extra.write_text("extra", encoding="utf-8")
            with patch("ioxen.agent_loader.BUNDLE_SCRIPT_FILE", missing), patch(
                "ioxen.agent_loader.SOURCE_BUNDLE_SCRIPT_FILE", missing
            ), patch("ioxen.agent_loader.PACKAGED_BUNDLE_SCRIPT_FILE", missing):
                result = load_agent_script(str(extra))

        self.assertEqual(result.code, PASSTHROUGH_AGENT + "\n\nextra")
        self.assertIn("ios_script_bundle.js not found", result.messages[0])

    def test_custom_hooks_are_appended_for_ios(self):
        with tempfile.TemporaryDirectory() as tmp:
            custom = Path(tmp) / "custom.json"
            custom.write_text('[{"kind": "objc", "method": "-[Svc handle:reply:]"}]', encoding="utf-8")
            result = load_hook_config(str(custom))
        self.assertEqual(result.hooks[-1], {"kind": "objc", "method": "-[Svc handle:reply:]"})


class _FakeExports:
    def __init__(self, released=None):
        self.calls = []
        self.released = released

    def forward(self, decision_id=None):
        self.calls.append(("forward", decision_id))
        return True

    def drop(self, decision_id=None):
        self.calls.append(("drop", decision_id))
        return decision_id == "decision-1"

    def interceptoff(self):
        self.calls.append(("interceptoff",))
        return self.released

    def set_filters(self, ignore, focus):
        self.calls.append(("set_filters", ignore, focus))
        return True


class _FakeScript:
    def __init__(self, released=None):
        self.exports_sync = _FakeExports(released)
        self.posted = []

    def post(self, message):
        self.posted.append(message)


def make_session(filters=None, **kwargs):
    return FridaSession(
        SessionConfig(attach_pid=1),
        filters or FilterManager(),
        log_cb=lambda _text: None,
        intercept_cb=lambda _state: None,
        get_stack=lambda: (False, 0),
        **kwargs,
    )


class IOSSessionTests(unittest.TestCase):
    def test_resume_posts_wake_only_when_resumed(self):
        session = make_session()
        session._script = _FakeScript()

        self.assertTrue(session.forward("decision-1"))
        self.assertTrue(session.drop("decision-1"))
        self.assertFalse(session.drop("decision-2"))

        self.assertEqual(session._script.posted, [
            {"type": "ioxen-wake:decision-1"},
            {"type": "ioxen-wake:decision-1"},
        ])

    def test_intercept_off_wakes_released_decision(self):
        session = make_session()
        session._script = _FakeScript(released="decision-9")
        session.intercept_off()
        self.assertEqual(session._script.posted, [{"type": "ioxen-wake:decision-9"}])

        session._script = _FakeScript(released=None)
        session.intercept_off()
        self.assertEqual(session._script.posted, [])

    def test_auto_forward_of_filtered_event_wakes(self):
        filters = FilterManager()
        filters.add("focus", ["direction=incoming"])
        outcomes = []
        done = threading.Event()
        session = make_session(
            filters,
            history_cb=lambda _payload, _counter: 5,
            outcome_cb=lambda db_id, outcome: outcomes.append((db_id, outcome)) or done.set(),
        )
        session._script = _FakeScript()

        session.on_message({"type": "send", "payload": xpc_payload()}, None)

        self.assertTrue(done.wait(timeout=1))
        self.assertEqual(outcomes, [(5, "forwarded")])
        self.assertEqual(session._script.posted, [{"type": "ioxen-wake:decision-1-1"}])

    def test_sync_filters_pushes_active_rules(self):
        filters = FilterManager()
        filters.add("ignore", ["component=com.apple.cfprefsd*"])
        session = make_session(filters)
        self.assertFalse(session.sync_filters())

        session._script = _FakeScript()
        self.assertTrue(session.sync_filters())
        self.assertEqual(
            session._script.exports_sync.calls,
            [("set_filters", [{"component": "com.apple.cfprefsd*"}], [])],
        )

    def test_visible_ios_payload_renders_into_intercept_ui(self):
        logs = []
        session = make_session(
            history_cb=lambda _payload, _counter: 3,
            intercept_log_cb=lambda *args: logs.append(args),
        )
        session.on_message({"type": "send", "payload": xpc_payload()}, None)
        self.assertEqual(logs[0][1:], (3, "decision-1-1"))
        self.assertIn("INTERCEPTED", logs[0][0])
        self.assertIn("fetchItem:withReply:", logs[0][0])

    def _connect_with(self, device, agent_error="stop"):
        platforms = []
        loaded = {}
        logs = []

        def fake_hooks(custom):
            loaded["hooks"] = custom
            return HooksLoadResult([], [])

        def fake_agent(extra):
            loaded["agent"] = extra
            raise RuntimeError(agent_error)

        session = make_session()
        session._config.spawn_package = "com.example.app"
        session.platform_cb = platforms.append
        session.log_cb = logs.append
        with patch.dict(sys.modules, {"frida": SimpleNamespace(get_device=lambda _id, timeout=5: device)}), patch(
            "ioxen.frida_session.load_hook_config", side_effect=fake_hooks
        ), patch("ioxen.frida_session.load_agent_script", side_effect=fake_agent):
            session.connect("usb-1")
            session._connect_thread.join(timeout=2)
        return session, platforms, loaded, "\n".join(logs)

    def test_connect_probes_process_platform_and_explains_termination(self):
        device = _FakeDevice(process_platform="darwin", params=None)
        _session, platforms, loaded, logs = self._connect_with(device)

        self.assertEqual(platforms, ["iOS"])
        self.assertEqual(loaded, {"hooks": None, "agent": None})
        self.assertIn("(frida ", logs)
        self.assertNotIn("must match", logs)
        self.assertIn("Platform: iOS", logs)
        self.assertNotIn("only supports", logs)
        self.assertEqual(device.killed, [4242])
        self.assertIn("Terminated the spawned app (PID 4242)", logs)
        self.assertIn("not a crash", logs)

    def test_device_label_is_used_when_it_agrees_with_the_probe(self):
        _session, platforms, _loaded, _logs = self._connect_with(_FakeDevice("darwin", IOS_PARAMS))
        self.assertEqual(platforms, ["iOS 17.4.1"])

    def test_non_apple_target_is_reported(self):
        _session, platforms, _loaded, logs = self._connect_with(_FakeDevice("linux", ANDROID_PARAMS))
        self.assertEqual(platforms, ["Android 14"])
        self.assertIn("ioxen only supports iOS and other Apple targets, but the target process runs on linux", logs)

    def test_non_apple_device_is_reported_when_the_probe_fails(self):
        _session, _platforms, _loaded, logs = self._connect_with(_FakeDevice(None, ANDROID_PARAMS))
        self.assertIn("but the device runs Android 14", logs)


class _FakeScript2:
    def __init__(self, device, code):
        self._device = device
        self._code = code
        self.unloaded = False
        outer = self

        class Exports:
            def platform(self):
                return outer._device.process_platform

            def proxy(self, _hooks):
                raise RuntimeError(outer._device.agent_error)

            def interceptoff(self):
                return None

        self.exports_sync = Exports()

    def on(self, *_args):
        pass

    def load(self):
        pass

    def unload(self):
        self.unloaded = True


class _FakeSession2:
    def __init__(self, device):
        self._device = device

    def on(self, *_args):
        pass

    def create_script(self, code):
        return _FakeScript2(self._device, code)

    def detach(self):
        pass


class _FakeDevice:
    def __init__(self, process_platform, params):
        self.process_platform = process_platform
        self.params = params
        self.killed = []
        self.agent_error = "proxy failed"

    def query_system_parameters(self):
        if self.params is None:
            raise RuntimeError("unsupported")
        return self.params

    def spawn(self, _argv):
        return 4242

    def attach(self, _pid):
        return _FakeSession2(self)

    def kill(self, pid):
        self.killed.append(pid)

    def resume(self, _pid):
        pass


class IOSRenderingTests(unittest.TestCase):
    def test_history_entry_keeps_ios_metadata(self):
        entry = payload_to_history_entry(xpc_payload(), now=datetime(2026, 10, 30, tzinfo=timezone.utc))
        self.assertEqual(entry["platform"], "ios")
        self.assertEqual(entry["ipc"]["peer"]["path"], "/usr/libexec/helperd")
        self.assertEqual(entry["supportedMods"], ["extra_add", "extra_rem"])

    def test_filter_contexts_expose_direction_and_peer(self):
        payload = xpc_payload()
        entry = payload_to_history_entry(payload)
        self.assertEqual(payload_to_filter_context(payload)["direction"], "outgoing")
        self.assertEqual(entry_to_filter_context(entry)["peer"], "/usr/libexec/helperd")

        filters = FilterManager()
        self.assertIn("Added", filters.add("focus", ["direction=outgoing", "peer=/usr/libexec/*"]))
        self.assertTrue(filters.is_visible(payload_to_filter_context(payload)))

        entry["ipc"]["peer"] = {"pid": 44, "path": None}
        self.assertEqual(entry_to_filter_context(entry)["peer"], "44")
        self.assertFalse(filters.is_visible(entry_to_filter_context(entry)))

    def test_search_matches_peer(self):
        entry = payload_to_history_entry(xpc_payload())
        self.assertTrue(history_search_matches(entry, "helperd"))
        self.assertTrue(history_search_matches(entry, "alice"))

    def test_ios_detail_rendering(self):
        entry = payload_to_history_entry(xpc_payload())
        entry["id"] = 12
        text = render_intent_detail(entry, show_stack=True, stack_depth=5)

        self.assertIn("XPC MESSAGE", text)
        self.assertIn("[Outgoing]", text)
        self.assertIn("[Mach service]", text)
        self.assertIn("Selector", text)
        self.assertIn("fetchItem:withReply:", text)
        self.assertIn("pid 321  /usr/libexec/helperd  euid 501", text)
        self.assertIn("NSXPC (bplist16)", text)
        self.assertIn("request/name", text)
        self.assertIn("strings:", text)
        self.assertIn("STACK TRACE", text)
        self.assertNotIn("INTENT", text)

    def test_ios_detail_shows_changes_and_escapes_markup(self):
        entry = payload_to_history_entry(xpc_payload())
        entry["id"] = 1
        entry["intent"]["extras"]["request/name"]["value"] = "[red]x[/red]"
        apply_mods_to_entry(entry, [("extra_add", "request/name", "bob", "string"), ("extra_rem", "root", "", "")])
        text = render_intent_detail(entry)
        self.assertIn("CHANGES", text)
        self.assertIn("\\[red]x\\[/red]", text)
        self.assertIn("→ bob", text)
        self.assertIn("[-]", text)

    def test_bplist00_blobs_are_decoded(self):
        archive = plistlib.dumps({"$objects": ["$null", "secret-token"]}, fmt=plistlib.FMT_BINARY)
        payload = xpc_payload()
        payload["ipc"]["blobs"] = [{
            "path": "payload", "length": len(archive), "format": "bplist00", "strings": [],
            "base64": base64.b64encode(archive).decode(),
        }]
        entry = payload_to_history_entry(payload)
        entry["id"] = 2
        self.assertIn("secret-token", render_intent_detail(entry))

    def test_url_and_listener_labels(self):
        url = xpc_payload(
            methodName="-[AppDelegate application:openURL:options:]",
            infoIntent={"component": "com.apple.mobilesafari", "action": "openURL", "data": "myapp://reset?token=1",
                        "extras": {}},
            attackSurface={"platform": "ios", "direction": "incoming", "exposure": "declared_scheme"},
            ipc={"kind": "url", "direction": "incoming", "url": "myapp://reset?token=1"},
        )
        entry = payload_to_history_entry(url)
        entry["id"] = 3
        text = render_intent_detail(entry)
        self.assertIn("[URL scheme]", text)
        self.assertIn("Source", text)
        self.assertIn("myapp://reset?token=1", text)

        block = render_intercept_block(url, 4, False, 0)
        self.assertIn("INTERCEPTED", block)
        self.assertIn("[Incoming]", block)

    def test_legacy_entries_without_ipc_metadata_render(self):
        entry = {"id": 1, "class": "A", "method": "legacy", "intent": {"action": "x"}, "attackSurface": {}}
        text = render_intent_detail(entry)
        self.assertIn("legacy", text)
        self.assertIn("XPC MESSAGE", text)


class IOSModTests(unittest.TestCase):
    def test_parse_accepts_ios_value_types(self):
        mod, error = parse_intent_mod_command(["+x", "int64", "request/id", "9"])
        self.assertIsNone(error)
        self.assertEqual(mod, ("extra_add", "request/id", "9", "int64"))
        mod, _ = parse_intent_mod_command(["+x", "data", "blob", "00ff"])
        self.assertEqual(mod[3], "data")

    def test_validate_mod_for_entry(self):
        ios = payload_to_history_entry(xpc_payload())
        self.assertIsNone(validate_mod_for_entry(ios, ("extra_add", "k", "1", "uint64")))
        self.assertIsNone(validate_mod_for_entry(ios, ("extra_add", "k", "1", "int")))
        self.assertIn("not supported", validate_mod_for_entry(ios, ("data", "", "x", "")))
        self.assertIn("Supported: +x, -x", validate_mod_for_entry(ios, ("data", "", "x", "")))
        self.assertIn("Unsupported value type", validate_mod_for_entry(ios, ("extra_add", "k", "1", "char")))
        locked = dict(ios, supportedMods=[])
        self.assertIn("forward or drop only", validate_mod_for_entry(locked, ("data", "", "x", "")))

        unknown = {"intent": {}}
        self.assertIsNone(validate_mod_for_entry(unknown, ("data", "", "x", "")))

    def test_apply_mods_normalizes_ios_types(self):
        entry = payload_to_history_entry(xpc_payload())
        apply_mods_to_entry(entry, [("extra_add", "request/id", "8", "int"), ("extra_add", "flag", "1", "boolean")])
        self.assertEqual(entry["intent"]["extras"]["request/id"], {"type": "int64", "value": "8"})
        self.assertEqual(entry["intent"]["extras"]["flag"], {"type": "bool", "value": "1"})
        self.assertEqual(entry["original_intent"]["extras"]["request/id"]["value"], "7")

    def test_ios_editable_type(self):
        self.assertEqual(ios_editable_type("int64"), "int64")
        self.assertEqual(ios_editable_type("__NSCFString"), "string")
        self.assertEqual(ios_editable_type("NSURL"), "string")
        self.assertIsNone(ios_editable_type("data"))
        self.assertIsNone(ios_editable_type("block"))


class IOSDatabaseTests(unittest.TestCase):
    def test_ios_entries_roundtrip_and_legacy_rows_keep_shape(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "p.ioxen")
            db = ProjectDB(path)
            db.create("p")
            ios_entry = payload_to_history_entry(xpc_payload())
            db.save_intent(ios_entry)
            db.save_intent({"timestamp": "t", "class": "A", "method": "legacy", "intent": {}})
            db.save_ios_static_surface({"bundle": {"identifier": "com.example"}})
            db.close()

            reopened = ProjectDB(path)
            entries = reopened.open_existing()
            static = reopened.load_ios_static_surface()
            reopened.close()

        self.assertEqual(entries[0]["platform"], "ios")
        self.assertEqual(entries[0]["ipc"]["connection"]["name"], "com.example.helper")
        self.assertNotIn("platform", entries[1])
        self.assertNotIn("ipc", entries[1])
        self.assertEqual(static, {"bundle": {"identifier": "com.example"}})

    def test_legacy_database_gains_platform_columns(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "legacy.ioxen")
            conn = sqlite3.connect(path)
            conn.executescript("""
                CREATE TABLE project_info (key TEXT PRIMARY KEY, value TEXT);
                CREATE TABLE intents (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL,
                    class TEXT, method TEXT, action TEXT, component TEXT, data TEXT, flags TEXT,
                    categories TEXT, extras TEXT, stack_trace TEXT, pending_intent_flags INTEGER);
                INSERT INTO intents (timestamp, class) VALUES ('t', 'Old');
            """)
            conn.commit()
            conn.close()
            db = ProjectDB(path)
            entries = db.open_existing()
            db.close()
            conn = sqlite3.connect(path)
            columns = {row[1] for row in conn.execute("PRAGMA table_info(intents)")}
            conn.close()
        self.assertTrue({"platform", "ipc"} <= columns)
        self.assertNotIn("platform", entries[0])


ENTITLEMENTS = plistlib.dumps({
    "application-identifier": "TEAM.com.example.app",
    "com.apple.developer.associated-domains": ["applinks:example.com"],
    "com.apple.security.application-groups": ["group.com.example"],
    "com.apple.security.exception.mach-lookup.global-name": ["com.example.helper"],
    "com.apple.private.tcc.allow": ["kTCCServiceCamera"],
}).decode()


def surface_entries():
    entries = [payload_to_history_entry(xpc_payload())]
    entries.append(payload_to_history_entry(xpc_payload(
        methodName="-[Delegate listener:shouldAcceptNewConnection:]",
        infoIntent={"component": "com.example.app.service", "action": "accept connection", "extras": {}},
        ipc={"kind": "nsxpc_accept", "direction": "incoming", "peer": {"pid": 9, "path": "/usr/bin/evil"}},
    )))
    entries.append(payload_to_history_entry(xpc_payload(
        methodName="-[NSXPCConnection resume]",
        infoIntent={"component": "com.example.app.service", "action": "interface", "extras": {}},
        ipc={"kind": "nsxpc_interface", "direction": "incoming",
             "exported": {"name": "ServiceProtocol", "methods": ["runCommand:reply:"]}},
    )))
    entries.append(payload_to_history_entry(xpc_payload(
        methodName="-[AppDelegate application:openURL:options:]",
        infoIntent={"component": "com.apple.mobilesafari", "action": "openURL", "data": "myapp://x", "extras": {}},
        ipc={"kind": "url", "direction": "incoming"},
    )))
    entries.append(payload_to_history_entry(xpc_payload(
        methodName="-[UIApplication canOpenURL:]",
        infoIntent={"action": "canOpenURL", "data": "fb://profile", "extras": {}},
        ipc={"kind": "url", "direction": "outgoing"},
    )))
    entries.append(payload_to_history_entry(xpc_payload(
        methodName="notify_register_dispatch",
        infoIntent={"component": "com.example.reload", "action": "register", "extras": {}},
        ipc={"kind": "darwin_notification", "direction": "incoming"},
    )))
    entries.append({"class": "A", "method": "legacy", "intent": {"component": "x"}})
    return entries


class IOSSurfaceTests(unittest.TestCase):
    def test_parse_entitlements(self):
        parsed, error = parse_entitlements(ENTITLEMENTS)
        self.assertIsNone(error)
        self.assertEqual(parsed["com.apple.security.application-groups"], ["group.com.example"])
        self.assertEqual(parse_entitlements(None), ({}, None))
        self.assertIn("invalid", parse_entitlements("<nope")[1])

    def test_summarize_observed(self):
        observed = summarize_observed(surface_entries())
        self.assertEqual(observed["outgoing_services"]["com.example.helper"]["selectors"], ["fetchItem:withReply:"])
        self.assertEqual(observed["outgoing_services"]["com.example.helper"]["kinds"], ["mach"])
        self.assertEqual(observed["listeners"]["com.example.app.service"], {"api": "NSXPC", "peers": {"/usr/bin/evil": 1}})
        self.assertEqual(observed["nsxpc_interfaces"]["com.example.app.service"]["exported"]["name"], "ServiceProtocol")
        self.assertEqual(observed["urls_incoming"], [{"url": "myapp://x", "via": "-[AppDelegate application:openURL:options:]", "source": "com.apple.mobilesafari"}])
        self.assertEqual(observed["scheme_queries"], {"fb": 1})
        self.assertEqual(observed["darwin_listening"], {"com.example.reload": 1})

    def test_render_report(self):
        static = {
            "bundle": {"identifier": "com.example.app", "name": "Example", "version": "1.0", "build": "7",
                       "executable": "ExampleApp"},
            "urlTypes": [{"name": "main", "schemes": ["myapp"]}],
            "extensions": [{"bundleId": "com.example.app.share", "point": "com.apple.share-services"}],
            "queriedSchemes": ["fb"],
            "entitlements": ENTITLEMENTS,
        }
        surface = build_surface(static, surface_entries())
        self.assertNotIn("entitlements", surface["static"])
        text = render_surface_report(surface)
        for needle in (
            "myapp://", "applinks:example.com", "com.apple.share-services", "ServiceProtocol",
            "runCommand:reply:", "/usr/bin/evil", "com.example.helper", "fetchItem:withReply:",
            "com.example.reload", "canOpenURL fb://", "private entitlement", "group.com.example",
            "Executable", "class=ExampleApp",
        ):
            self.assertIn(needle, text)

    def test_render_report_without_static_data(self):
        text = render_surface_report(build_surface({}, []))
        self.assertIn("No static data yet", text)


class IOSCommandTests(unittest.TestCase):
    def test_surface_command(self):
        self.assertEqual(parse_surface_command(["/surface"]).action, "show")
        self.assertEqual(parse_surface_command(["/surface", "EXPORT"]).action, "export")
        self.assertIsNone(parse_surface_command(["/surface", "bogus"]))
        intercept = [template for template, _ in INTERCEPT_COMPLETIONS]
        history = [template for template, _ in HISTORY_COMPLETIONS]
        self.assertIn("/surface", intercept)
        self.assertIn("/surface export", history)
        self.assertIn("Event Modifications", HELP_MENU)


if __name__ == "__main__":
    unittest.main()


class NSXPCDecodingTests(unittest.TestCase):
    def call_payload(self):
        return xpc_payload(
            className="NSXPCConnection",
            methodName="-[HelperProtocol fetchItem:withReply:]",
            infoIntent={"component": "com.example.helper", "action": "fetchItem:withReply:", "data": None,
                        "extras": {"arg0": {"type": "__NSCFString", "value": "item-42"},
                                   "arg1": {"type": "block", "value": "<block>"}}},
            attackSurface={"platform": "ios", "direction": "outgoing"},
            ipc={"kind": "nsxpc_call", "direction": "outgoing", "protocol": "HelperProtocol",
                 "selector": "fetchItem:withReply:", "service": "com.example.helper", "peer": {"pid": 321}},
            decision={"required": True, "id": "decision-1-2", "reason": None, "mods": ["extra_add"]},
        )

    def test_outgoing_call_renders_decoded_arguments(self):
        entry = payload_to_history_entry(self.call_payload())
        entry["id"] = 1
        text = render_intent_detail(entry)
        self.assertIn("NSXPC CALL", text)
        self.assertIn("ARGUMENTS", text)
        self.assertIn("item-42", text)
        self.assertIn("HelperProtocol", text)
        self.assertIsNone(validate_mod_for_entry(entry, ("extra_add", "arg0", "other", "string")))
        self.assertIn("not supported", validate_mod_for_entry(entry, ("extra_rem", "arg0", "", "")))

    def test_reply_renders_and_links_request(self):
        reply = payload_to_history_entry(xpc_payload(
            className="NSXPCConnection",
            methodName="reply fetchItem:withReply:",
            infoIntent={"component": "com.example.helper", "action": "fetchItem:withReply:",
                        "extras": {"arg0": {"type": "__NSDictionaryI", "value": "{ secret = 1; }"}}},
            attackSurface={"platform": "ios", "direction": "reply"},
            ipc={"kind": "nsxpc_reply", "direction": "reply", "selector": "fetchItem:withReply:",
                 "correlation": "ev-1-9"},
        ))
        reply["id"] = 2
        text = render_intent_detail(reply)
        self.assertIn("NSXPC REPLY", text)
        self.assertIn("[Reply]", text)
        self.assertIn("request ev-1-9", text)
        self.assertIn("secret = 1", text)

    def test_raw_message_points_at_decoded_call(self):
        payload = xpc_payload()
        payload["ipc"]["nsxpcCall"] = "ev-1-9"
        entry = payload_to_history_entry(payload)
        entry["id"] = 3
        self.assertIn("decoded as NSXPC call ev-1-9", render_intent_detail(entry))

    def test_surface_merges_decoded_calls_without_double_counting(self):
        entries = [payload_to_history_entry(xpc_payload()), payload_to_history_entry(self.call_payload())]
        service = summarize_observed(entries)["outgoing_services"]["com.example.helper"]
        self.assertEqual(service["messages"], 1)
        self.assertEqual(service["kinds"], ["NSXPC", "mach"])
        self.assertEqual(service["selectors"], ["fetchItem:withReply:"])
        self.assertEqual(summarize_observed(entries)["exported_calls"], [])


class InterceptDefaultTests(unittest.TestCase):
    def test_intercept_is_off_by_default(self):
        from ioxen.settings import DEFAULT_SETTINGS, load_settings
        self.assertFalse(DEFAULT_SETTINGS["intercept"])
        with tempfile.TemporaryDirectory() as tmp:
            self.assertFalse(load_settings(os.path.join(tmp, "missing.txt"))["intercept"])
            path = os.path.join(tmp, "settings.txt")
            with open(path, "w") as f:
                f.write("intercept=on\n")
            self.assertTrue(load_settings(path)["intercept"])


class WebViewAndNetworkTests(unittest.TestCase):
    def web_payload(self, action, component=None, data=None, extras=None, direction="incoming", exposure=None, kind="webview",
                    method="-[ViewController userContentController:didReceiveScriptMessage:]"):
        surface = {"platform": "ios", "direction": direction}
        if exposure:
            surface["exposure"] = exposure
        return xpc_payload(
            className="ViewController", methodName=method,
            infoIntent={"component": component, "action": action, "data": data, "extras": extras or {}},
            attackSurface=surface,
            ipc={"kind": kind, "direction": direction},
            decision={"required": True, "id": "d-1", "reason": None, "mods": []},
        )

    def test_script_message_renders_as_js_bridge(self):
        entry = payload_to_history_entry(self.web_payload(
            "script message", component="nativeBridge", data="https://app.example.com/",
            extras={"name": {"type": "string", "value": "nativeBridge"},
                    "body": {"type": "json", "value": '{"cmd":"getToken"}'},
                    "frame/origin": {"type": "string", "value": "https://evil.example"}},
            exposure="js_bridge"))
        entry["id"] = 1
        text = render_intent_detail(entry)
        self.assertIn("WEB VIEW", text)
        self.assertIn("[JS bridge]", text)
        self.assertIn("Host", text)
        self.assertIn('{"cmd":"getToken"}', text)
        self.assertIn("https://evil.example", text)

    def test_network_request_renders(self):
        entry = payload_to_history_entry(self.web_payload(
            "POST", component="api.example.com", data="https://api.example.com/login", direction="outgoing",
            kind="network", method="-[NSURLSession dataTaskWithRequest:completionHandler:]",
            extras={"headers/Authorization": {"type": "string", "value": "Bearer abc"}}))
        entry["id"] = 2
        text = render_intent_detail(entry)
        self.assertIn("NETWORK REQUEST", text)
        self.assertIn("Bearer abc", text)
        self.assertIn("[Outgoing]", text)

    def test_surface_lists_bridges_web_activity_and_hosts(self):
        entries = [payload_to_history_entry(p) for p in (
            self.web_payload("register JS bridge", component="nativeBridge",
                             extras={"handler": {"type": "class", "value": "BridgeHandler"}}, exposure="js_bridge",
                             method="-[WKUserContentController addScriptMessageHandler:name:]"),
            self.web_payload("script message", component="nativeBridge", exposure="js_bridge"),
            self.web_payload("script message", component="legacyBridge", exposure="js_bridge"),
            self.web_payload("load request", component="app.example.com", data="https://app.example.com/", direction="outgoing"),
            self.web_payload("navigation", component="evil.example", data="https://evil.example/x"),
            self.web_payload("evaluate JavaScript", component="app.example.com", direction="outgoing"),
            self.web_payload("register URL scheme handler", component="app-assets",
                             extras={"handler": {"type": "class", "value": "AssetHandler"}}, exposure="webview_scheme"),
            self.web_payload("in-app browser", data="https://login.example.com", direction="outgoing"),
            self.web_payload("POST", component="api.example.com", data="https://api.example.com/login",
                             direction="outgoing", kind="network"),
        )]
        observed = summarize_observed(entries)
        self.assertEqual(observed["web"]["js_bridges"], {"nativeBridge": "BridgeHandler"})
        self.assertEqual(observed["web"]["bridge_messages"], {"legacyBridge": 1, "nativeBridge": 1})
        self.assertEqual(observed["network_hosts"], {"api.example.com": 1})
        text = render_surface_report(build_surface({}, entries))
        for needle in ("WEB VIEWS", "JS bridge", "nativeBridge", "BridgeHandler", "1 message(s)",
                       "registered before capture", "app-assets://", "loads https://app.example.com/",
                       "navigates to evil.example", "evaluates JavaScript in app.example.com",
                       "in-app browser: https://login.example.com", "NETWORK REQUESTS", "api.example.com"):
            self.assertIn(needle, text)
