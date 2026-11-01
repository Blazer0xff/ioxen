import os
import tempfile
import unittest
from types import SimpleNamespace

from textual.widgets import Input, Label, Select

from ioxen.app import IoxenApp
from ioxen.platforms import IOS, PlatformInfo
from ioxen.rendering import payload_to_history_entry

from tests.test_ios_support import xpc_payload


def project_args(path: str) -> SimpleNamespace:
    return SimpleNamespace(project=None, new_project=path, skip_device_scan=True)


class _Tmp:
    def __enter__(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._cwd = os.getcwd()
        os.chdir(self._tmp.name)
        return self._tmp.name

    def __exit__(self, *exc):
        os.chdir(self._cwd)
        self._tmp.cleanup()


class IOSAppTests(unittest.IsolatedAsyncioTestCase):
    async def test_home_tab_has_no_platform_selector_or_android_options(self):
        with _Tmp() as tmp:
            app = IoxenApp(project_args(os.path.join(tmp, "p")))
            async with app.run_test(size=(120, 40)):
                for removed in ("#home_platform", "#home_anr_row", "#home_system_anr_bypass"):
                    self.assertEqual(len(app.query(removed)), 0, removed)
                for removed in ("#ef_action_row", "#ef_categories_group", "#ef_flags_group"):
                    self.assertEqual(len(app.query(removed)), 0, removed)

    async def test_detected_device_updates_home_tab(self):
        with _Tmp() as tmp:
            app = IoxenApp(project_args(os.path.join(tmp, "p")))
            async with app.run_test(size=(120, 40)) as pilot:
                select = app.query_one("#home_device", Select)
                select.set_options([("iPhone  (usb)", "usb-1"), ("Pixel  (usb)", "usb-2")])
                select.value = "usb-1"
                app._device_platforms["usb-1"] = PlatformInfo(IOS, "iOS 17.4.1", "ios")
                app._device_platforms["usb-2"] = PlatformInfo(None, "Android 14", "android")
                app._refresh_platform_ui()
                await pilot.pause()
                self.assertIn("iOS 17.4.1", str(app.query_one("#home_platform_info", Label).render()))

                select.value = "usb-2"
                await pilot.pause()
                text = str(app.query_one("#home_platform_info", Label).render())
                self.assertIn("Android 14", text)
                self.assertIn("not supported", text)

    async def test_edit_form_adapts_to_ios_xpc_event(self):
        with _Tmp() as tmp:
            app = IoxenApp(project_args(os.path.join(tmp, "p")))
            async with app.run_test(size=(120, 40)) as pilot:
                entry = payload_to_history_entry(xpc_payload())
                entry["id"] = 1
                app._all_intents.append(entry)
                app._on_intercept_display("", 1, "decision-1-1")
                app.set_intercept_state(True)
                app.query_one("#main_tabs").active = "tab_intercept"
                await pilot.pause()

                app._enter_edit_mode()
                await pilot.pause()

                self.assertTrue(app._edit_mode)
                self.assertFalse(app.query_one("#ef_data_row").display)
                self.assertTrue(app.query_one("#ef_extras_group").display)

                rows = {info["key"]: n for n, info in app._edit_extra_rows.items()}
                self.assertEqual(set(rows), {"root", "request/id", "request/name"})
                self.assertTrue(app.query_one(f"#ef_xv_{rows['root']}", Input).disabled)
                self.assertFalse(app.query_one(f"#ef_xv_{rows['request/id']}", Input).disabled)

                app.query_one(f"#ef_xv_{rows['request/id']}", Input).value = "8"
                app._add_edit_extra_row("", None, "", is_new=True)
                await pilot.pause()
                new_n = max(app._edit_extra_rows)
                type_select = app.query_one(f"#ef_xt_{new_n}", Select)
                self.assertIn("uint64", [str(value) for _label, value in type_select._options])
                app.query_one(f"#ef_xk_{new_n}", Input).value = "debug"
                type_select.value = "bool"
                app.query_one(f"#ef_xv_{new_n}", Input).value = "true"

                mods = app._collect_edit_mods()
                self.assertEqual(mods, [
                    ("extra_add", "request/id", "8", "int64"),
                    ("extra_add", "debug", "true", "bool"),
                ])

    async def test_forward_only_event_refuses_edit_mode(self):
        with _Tmp() as tmp:
            app = IoxenApp(project_args(os.path.join(tmp, "p")))
            async with app.run_test(size=(120, 40)) as pilot:
                payload = xpc_payload()
                payload["decision"]["mods"] = []
                entry = payload_to_history_entry(payload)
                entry["id"] = 1
                app._all_intents.append(entry)
                app._on_intercept_display("", 1, "decision-1-1")
                await pilot.pause()
                app._enter_edit_mode()
                self.assertFalse(app._edit_mode)

    def test_surface_command_renders_stored_data_offline(self):
        pushed = []
        written = []
        entry = payload_to_history_entry(xpc_payload())
        fake_app = SimpleNamespace(
            db=SimpleNamespace(
                load_ios_static_surface=lambda: {"bundle": {"identifier": "com.example.app"}},
                save_ios_static_surface=lambda _s: None,
            ),
            frida_session=None,
            _all_intents=[entry],
            call_from_thread=lambda fn: fn(),
            push_screen=pushed.append,
        )
        IoxenApp._handle_surface_command(fake_app, ["/surface"], written.append)
        self.assertEqual(written, [])
        self.assertEqual(len(pushed), 1)
        self.assertIn("com.example.helper", pushed[0]._text)

        with _Tmp():
            IoxenApp._handle_surface_command(fake_app, ["/surface", "export"], written.append)
            self.assertIn("Exported attack surface", written[-1])

    def test_surface_command_refreshes_from_live_ios_session(self):
        saved = []
        session = SimpleNamespace(
            is_ready=lambda: True,
            get_attack_surface=lambda: {"bundle": {"identifier": "com.live"}},
        )
        pushed = []
        fake_app = SimpleNamespace(
            db=SimpleNamespace(load_ios_static_surface=lambda: {}, save_ios_static_surface=saved.append),
            frida_session=session,
            _all_intents=[],
            call_from_thread=lambda fn: fn(),
            push_screen=pushed.append,
        )
        IoxenApp._handle_surface_command(fake_app, ["/surface"], lambda _t: None)
        self.assertEqual(saved, [{"bundle": {"identifier": "com.live"}}])
        self.assertIn("com.live", pushed[0]._text)

    def test_platform_callback_labels_session(self):
        info = []
        posted = []
        session = object()
        fake_app = SimpleNamespace(
            frida_session=session,
            db=SimpleNamespace(set_info=lambda *args: info.append(args)),
            _session_config=SimpleNamespace(target_label=lambda: "com.example.app"),
            _session_device_id="usb-1",
            call_from_thread=posted.append,
        )
        IoxenApp._on_platform(fake_app, "iOS 17.4.1", session)
        self.assertEqual(info, [("platform", "ios")])
        self.assertEqual(len(posted), 1)

        IoxenApp._on_platform(fake_app, "iOS 17.4.1", object())
        self.assertEqual(len(posted), 1)

    async def test_url_event_edit_form_shows_url_row(self):
        with _Tmp() as tmp:
            app = IoxenApp(project_args(os.path.join(tmp, "p")))
            async with app.run_test(size=(120, 40)) as pilot:
                payload = xpc_payload(
                    infoIntent={"component": "com.apple.mobilesafari", "action": "openURL",
                                "data": "myapp://reset?token=1", "extras": {}},
                    ipc={"kind": "url", "direction": "incoming"},
                    decision={"required": True, "id": "d-9", "reason": None, "mods": ["data"]},
                )
                entry = payload_to_history_entry(payload)
                entry["id"] = 1
                app._all_intents.append(entry)
                app._on_intercept_display("", 1, "d-9")
                app.set_intercept_state(True)
                app.query_one("#main_tabs").active = "tab_intercept"
                await pilot.pause()

                app._enter_edit_mode()
                await pilot.pause()

                self.assertTrue(app._edit_mode)
                self.assertTrue(app.query_one("#ef_data_row").display)
                self.assertFalse(app.query_one("#ef_extras_group").display)
                self.assertEqual(app.query_one("#ef_data", Input).value, "myapp://reset?token=1")
                app.query_one("#ef_data", Input).value = "myapp://reset?token=2"
                self.assertEqual(app._collect_edit_mods(), [("data", "", "myapp://reset?token=2", "")])


if __name__ == "__main__":
    unittest.main()


class LogFileAndKillTests(unittest.TestCase):
    def test_log_tab_is_mirrored_to_project_log_file(self):
        from ioxen.app import append_project_log, project_log_path
        from ioxen.logging_ui import log_error
        with _Tmp() as tmp:
            project = os.path.join(tmp, "proj.ioxen")
            append_project_log(project, log_error("Native exception in target: [abort]", "crash"))
            append_project_log(None, "ignored")
            self.assertEqual(project_log_path(project), os.path.join(tmp, "proj.log"))
            with open(os.path.join(tmp, "proj.log"), encoding="utf-8") as f:
                content = f.read()
        self.assertIn("crash", content)
        self.assertIn("ERROR Native exception in target: [abort]", content)
        self.assertNotIn("[red]", content)

    def test_kill_command(self):
        written = []
        fake = SimpleNamespace(frida_session=SimpleNamespace(kill_target=lambda: 4242))
        IoxenApp._handle_slash_command(fake, "/kill", ["/kill"], written.append)
        self.assertIn("Killed target (PID 4242)", written[-1])
        fake.frida_session = None
        IoxenApp._handle_slash_command(fake, "/kill", ["/kill"], written.append)
        self.assertIn("No target to kill", written[-1])


class ProjectExtensionTests(unittest.TestCase):
    def test_new_projects_use_ioxen_extension_and_legacy_noxen_projects_open(self):
        from ioxen.db import ProjectDB
        with _Tmp() as tmp:
            app = IoxenApp(project_args(os.path.join(tmp, "fresh")))
            self.assertTrue(app.db.path.endswith("fresh.ioxen"))
            app.db.close()

            legacy = os.path.join(tmp, "old.noxen")
            db = ProjectDB(legacy)
            db.create("old")
            db.close()
            app = IoxenApp(SimpleNamespace(project=legacy, new_project=None, skip_device_scan=True))
            self.assertEqual(app.db.path, legacy)
            app.db.close()

            with self.assertRaises(FileNotFoundError):
                IoxenApp(SimpleNamespace(project=os.path.join(tmp, "old"), new_project=None, skip_device_scan=True))
