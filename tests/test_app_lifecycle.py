import unittest
from types import SimpleNamespace

from ioxen.app import IoxenApp


class AppLifecycleTests(unittest.TestCase):
    def test_target_detach_clears_session_and_intercept_state(self):
        target_session = object()
        intercept_states = []
        fake_app = SimpleNamespace(
            frida_session=target_session,
            set_intercept_state=intercept_states.append,
            call_from_thread=lambda _callback: None,
        )

        IoxenApp._on_disconnected(fake_app, target_session)

        self.assertIsNone(fake_app.frida_session)
        self.assertEqual(intercept_states, [False])

    def test_stale_detach_callback_does_not_change_current_session(self):
        current_session = object()
        stale_session = object()
        intercept_states = []
        fake_app = SimpleNamespace(
            frida_session=current_session,
            set_intercept_state=intercept_states.append,
            call_from_thread=lambda _callback: None,
        )

        IoxenApp._on_disconnected(fake_app, stale_session)

        self.assertIs(fake_app.frida_session, current_session)
        self.assertEqual(intercept_states, [])

    def test_intercept_display_uses_explicit_history_entry(self):
        first = {
            "id": 1,
            "class": "Example",
            "method": "xpc_connection_send_message",
            "intent": {},
            "stackTrace": [],
            "attackSurface": {},
        }
        second = {
            **first,
            "id": 2,
            "method": "notify_post",
        }
        fake_app = SimpleNamespace(
            _all_intents=[first, second],
            _staged_mods=[],
            show_stack=False,
            stack_depth=0,
            query_one=lambda *_args, **_kwargs: (_ for _ in ()).throw(Exception("no UI")),
        )

        IoxenApp._on_intercept_display(fake_app, "rendered", entry_id=1, decision_id="decision-1")

        self.assertIs(fake_app._current_intercepted_entry, first)
        self.assertEqual(fake_app._current_intercept_id, 1)
        self.assertEqual(fake_app._current_decision_id, "decision-1")

    def test_intercept_display_without_entry_does_not_keep_stale_current_intent(self):
        fake_app = SimpleNamespace(
            _all_intents=[],
            _current_intercept_id=99,
            _current_decision_id="old-decision",
            _current_intercepted_entry={"id": 99},
            _staged_mods=[("action", "", "old", "")],
            _write_rich=lambda *_args, **_kwargs: None,
        )

        IoxenApp._on_intercept_display(fake_app, "rendered", entry_id=None, decision_id="decision-2")

        self.assertIsNone(fake_app._current_intercept_id)
        self.assertIsNone(fake_app._current_intercepted_entry)
        self.assertEqual(fake_app._current_decision_id, "decision-2")
        self.assertEqual(fake_app._staged_mods, [])

    def test_history_table_applies_saved_column_widths(self):
        table = _FakeHistoryTable()
        fake_app = SimpleNamespace(
            _history_selected_entry=None,
            _history_visible_cols={"id", "time", "method", "class"},
            _history_column_widths={"time": 19, "method": 18, "class": 40},
            _sort_column="id",
            _sort_reverse=True,
            query_one=lambda *_args, **_kwargs: table,
            _get_filtered_sorted=lambda: [],
            _fill_table_rows=lambda _table, _filtered: None,
            _restore_cursor=lambda _table, _filtered, _saved: None,
        )

        IoxenApp._refresh_history_table(fake_app)

        self.assertEqual(table.columns["id"], None)
        self.assertEqual(table.columns["time"], 19)
        self.assertEqual(table.columns["method"], 18)
        self.assertEqual(table.columns["class"], 40)


class _FakeHistoryTable:
    def __init__(self):
        self.columns = {}

    def clear(self, columns=False):
        if columns:
            self.columns = {}

    def add_column(self, _label, *, key=None, width=None):
        self.columns[key] = width


if __name__ == "__main__":
    unittest.main()
