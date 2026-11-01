"""Event intake must keep up with chatty targets and stop at disconnect.

Previously every event made Frida's message thread wait for a full History
redraw, so intake dropped to a few events per second once History held
thousands of rows; the backlog kept draining after Disconnect or after the
app was killed.
"""

import asyncio
import os
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace

from ioxen.app import HISTORY_REFRESH_INTERVAL, IoxenApp
from ioxen.filters import FilterManager
from ioxen.frida_session import FridaSession, SessionConfig
from tests.test_ios_support import xpc_payload


def project_args(path):
    return SimpleNamespace(project=None, new_project=path, skip_device_scan=True)


class _Cwd:
    def __enter__(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._cwd = os.getcwd()
        os.chdir(self._tmp.name)
        return self._tmp.name

    def __exit__(self, *exc):
        os.chdir(self._cwd)
        self._tmp.cleanup()


def observed(**overrides):
    payload = xpc_payload()
    payload["decision"] = {"required": False, "id": None, "reason": "intercept_off", "mods": []}
    payload.update(overrides)
    return payload


class EventIntakeTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        asyncio.get_running_loop().slow_callback_duration = 1.0

    async def test_intake_does_not_wait_for_the_ui(self):
        with _Cwd() as tmp:
            app = IoxenApp(project_args(os.path.join(tmp, "p")))
            async with app.run_test(size=(120, 40)) as pilot:
                app.query_one("#main_tabs").active = "tab_history"
                await pilot.pause()
                count = [0]

                def producer():  # stands in for Frida's message thread
                    for _ in range(500):
                        app._on_history_intent(observed(), 0)
                        count[0] += 1

                started = time.monotonic()
                thread = threading.Thread(target=producer)
                thread.start()
                # The UI loop is idle (awaiting nothing else); a blocking
                # intake would take seconds here.
                while thread.is_alive():
                    await asyncio.sleep(0.01)
                elapsed = time.monotonic() - started
                self.assertEqual(count[0], 500)
                self.assertLess(elapsed, 3.0)

                await asyncio.sleep(HISTORY_REFRESH_INTERVAL * 3)
                await pilot.pause()
                table = app.query_one("#history_table")
                self.assertEqual(table.row_count, 500)

    async def test_history_table_is_rebuilt_when_the_tab_is_opened(self):
        with _Cwd() as tmp:
            app = IoxenApp(project_args(os.path.join(tmp, "p")))
            async with app.run_test(size=(120, 40)) as pilot:
                app.query_one("#main_tabs").active = "tab_intercept"
                await pilot.pause()
                threading.Thread(target=lambda: [app._on_history_intent(observed(), 0) for _ in range(20)]).start()
                await asyncio.sleep(HISTORY_REFRESH_INTERVAL * 3)
                await pilot.pause()
                self.assertTrue(app._history_dirty)

                app.query_one("#main_tabs").active = "tab_history"
                await pilot.pause()
                await pilot.pause()
                self.assertEqual(app.query_one("#history_table").row_count, 20)
                self.assertFalse(app._history_dirty)

    def test_events_that_were_never_held_store_their_outcome_with_the_row(self):
        with _Cwd() as tmp:
            app = IoxenApp(project_args(os.path.join(tmp, "p")))
            entry_id = app._on_history_intent(observed(), 0)
            entry = app._all_intents[-1]
            self.assertEqual(entry["outcome"], "forwarded")
            # A later "forwarded" outcome callback is a no-op (no second write).
            writes = []
            app.db.update_outcome = lambda *a: writes.append(a)
            app._update_outcome(entry_id, "forwarded")
            self.assertEqual(writes, [])
            app.db.close()
            reopened = __import__("ioxen.db", fromlist=["ProjectDB"]).ProjectDB(app.db.path)
            rows = reopened.open_existing()
            reopened.close()
            self.assertEqual(rows[-1]["outcome"], "forwarded")


class StaleMessageTests(unittest.TestCase):
    def test_messages_from_a_closed_session_are_ignored(self):
        history = []
        session = FridaSession(SessionConfig(attach_pid=1), FilterManager(), log_cb=lambda _t: None,
                               intercept_cb=lambda _s: None, get_stack=lambda: (False, 0),
                               history_cb=lambda p, c: history.append(p), outcome_cb=lambda *_: None)
        current, old = object(), object()
        session._script = current
        message = {"type": "send", "payload": observed()}

        session._on_script_message(current, message, None)
        session._on_script_message(old, message, None)
        session.cleanup()
        session._on_script_message(current, message, None)

        self.assertEqual(len(history), 1)
        self.assertEqual(session._stale_messages, 2)


if __name__ == "__main__":
    unittest.main()
