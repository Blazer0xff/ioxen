import unittest
from datetime import datetime, timezone

from rich.text import Text

from ioxen.rendering import (
    entry_to_filter_context,
    filter_sort_history_entries,
    history_row_values,
    history_search_matches,
    history_sort_key,
    payload_to_filter_context,
    payload_to_history_entry,
    render_intercept_block,
    render_intent_detail,
)
from ioxen.filters import FilterManager


class RenderingTests(unittest.TestCase):
    def test_entry_to_filter_context_normalizes_missing_values(self):
        entry = {
            "class": "MyApp",
            "method": "xpc_connection_send_message",
            "intent": {
                "action": "fetchItem:",
                "component": None,
            },
        }

        self.assertEqual(
            entry_to_filter_context(entry),
            {
                "class": "MyApp",
                "method": "xpc_connection_send_message",
                "action": "fetchItem:",
                "component": "",
                "data": "",
                "direction": "",
                "peer": "",
            },
        )

    def test_payload_to_filter_context_normalizes_frida_payload(self):
        payload = {
            "className": "MyApp",
            "methodName": "xpc_connection_send_message",
            "infoIntent": {
                "action": "fetchItem:",
                "component": None,
            },
            "ipc": {"direction": "outgoing", "peer": {"pid": 12, "path": None}},
        }

        self.assertEqual(
            payload_to_filter_context(payload),
            {
                "class": "MyApp",
                "method": "xpc_connection_send_message",
                "action": "fetchItem:",
                "component": "",
                "data": "",
                "direction": "outgoing",
                "peer": "12",
            },
        )

    def test_payload_to_history_entry_normalizes_frida_payload(self):
        payload = {
            "platform": "ios",
            "className": "MyApp",
            "methodName": "xpc_connection_send_message",
            "infoIntent": {"action": "fetchItem:"},
            "stackTrace": ["frame1"],
            "ipc": {"kind": "xpc", "direction": "outgoing"},
            "decision": {"required": True, "id": "d-1", "mods": ["extra_add"]},
        }

        entry = payload_to_history_entry(
            payload,
            now=datetime(2026, 4, 28, 10, 11, 12, tzinfo=timezone.utc),
        )

        self.assertEqual(entry, {
            "id": None,
            "timestamp": "2026-04-28T10:11:12+00:00",
            "class": "MyApp",
            "method": "xpc_connection_send_message",
            "intent": {"action": "fetchItem:"},
            "stackTrace": ["frame1"],
            "attackSurface": {},
            "platform": "ios",
            "ipc": {"kind": "xpc", "direction": "outgoing"},
            "supportedMods": ["extra_add"],
        })

    def test_payload_without_platform_or_decision_is_stored_as_ios(self):
        entry = payload_to_history_entry({"className": "MyApp", "methodName": "m"})
        self.assertEqual(entry["platform"], "ios")
        self.assertEqual(entry["ipc"], {})
        self.assertNotIn("supportedMods", entry)

    def test_history_sort_key(self):
        entry = {
            "id": 9,
            "timestamp": "2026-04-27T12:34:56+00:00",
            "class": "MyApp",
            "method": "XPC_Connection_Send_Message",
            "outcome": "forwarded",
            "intent": {
                "action": "FetchItem:",
                "component": "Com.Example.Helper",
                "extras": {"token": {"type": "string", "value": "abc"}},
            },
        }

        self.assertEqual(history_sort_key(entry, "id"), 9)
        self.assertEqual(history_sort_key(entry, "method"), "xpc_connection_send_message")
        self.assertEqual(history_sort_key(entry, "class"), "myapp")
        self.assertEqual(history_sort_key(entry, "component"), "com.example.helper")
        self.assertEqual(history_sort_key(entry, "action"), "fetchitem:")
        self.assertTrue(history_sort_key(entry, "extras"))
        self.assertEqual(history_sort_key(entry, "outcome"), "forwarded")
        self.assertEqual(history_sort_key(entry, "unknown"), "")

    def test_history_search_matches_core_fields_extras_and_ipc(self):
        entry = {
            "class": "MyApp",
            "method": "xpc_connection_send_message",
            "intent": {
                "action": "fetchItem:",
                "component": "com.example.helper",
                "data": "myapp://open",
                "extras": {"token": {"type": "string", "value": "secret-value"}},
            },
            "ipc": {"kind": "xpc", "direction": "outgoing", "peer": {"path": "/usr/libexec/helperd"}},
        }

        self.assertTrue(history_search_matches(entry, "MYAPP"))
        self.assertTrue(history_search_matches(entry, "myapp://"))
        self.assertTrue(history_search_matches(entry, "token"))
        self.assertTrue(history_search_matches(entry, "secret-value"))
        self.assertTrue(history_search_matches(entry, "helperd"))
        self.assertTrue(history_search_matches(entry, "outgoing"))
        self.assertFalse(history_search_matches(entry, "missing"))

    def test_filter_sort_history_entries_applies_filters_search_and_sort(self):
        entries = [
            {
                "id": 1,
                "timestamp": "2026-04-28T10:00:00+00:00",
                "class": "com.example.First",
                "method": "xpc_connection_send_message",
                "intent": {"component": "com.example.helper", "extras": {}},
            },
            {
                "id": 2,
                "timestamp": "2026-04-28T10:01:00+00:00",
                "class": "com.example.Second",
                "method": "notify_post",
                "intent": {"component": "com.example.reload", "extras": {}},
            },
            {
                "id": 3,
                "timestamp": "2026-04-28T10:02:00+00:00",
                "class": "com.example.Third",
                "method": "xpc_connection_send_message",
                "intent": {"component": "com.example.helper", "extras": {}},
            },
        ]
        filters = FilterManager()
        filters.add("focus", ["component=com.example.helper"])

        filtered = filter_sort_history_entries(
            entries,
            filters,
            search_text="example",
            sort_column="id",
            sort_reverse=True,
        )

        self.assertEqual([entry["id"] for entry in filtered], [3, 1])

    def test_history_row_values_respects_visible_columns(self):
        entry = {
            "id": 9,
            "timestamp": "2026-04-27T12:34:56+00:00",
            "class": "MyApp",
            "method": "xpc_connection_send_message",
            "outcome": "forwarded",
            "intent": {
                "action": "fetchItem:",
                "component": "com.example.helper",
                "extras": {"token": {"type": "string", "value": "abc"}},
            },
        }
        columns = [
            ("id", "#"),
            ("outcome", "->"),
            ("time", "Time"),
            ("method", "Method"),
            ("extras", "Extras"),
        ]

        values = history_row_values(entry, {"id", "outcome", "time", "extras"}, columns)

        self.assertEqual(values[0], "9")
        self.assertEqual(str(values[1]), "→")
        self.assertEqual(values[2], "2026-04-27 12:34:56")
        self.assertEqual(str(values[3]), "✓")

    def test_render_intercept_block_includes_stack_limit(self):
        payload = {
            "platform": "ios",
            "className": "MyApp",
            "methodName": "xpc_connection_send_message",
            "stackTrace": ["frame1", "frame2", "frame3"],
            "infoIntent": {
                "action": "fetchItem:",
                "component": "com.example.helper",
                "extras": {"x": {"type": "string", "value": "y"}},
            },
            "ipc": {"kind": "xpc", "direction": "outgoing"},
        }

        rendered = render_intercept_block(payload, 7, show_stack=True, stack_depth=2)

        self.assertIn("INTERCEPTED", rendered)
        self.assertIn("#7", rendered)
        self.assertIn("com.example.helper", rendered)
        self.assertIn("frame1", rendered)
        self.assertIn("frame2", rendered)
        self.assertIn("... (+1 more)", rendered)
        self.assertNotIn("frame3\n", rendered)

    def test_render_intercept_block_escapes_dynamic_markup(self):
        payload = {
            "className": "MyApp[Bad]",
            "methodName": "xpc_connection_send_message",
            "stackTrace": ["0x1 Foo!-[Bar baz:[/usr/lib/libxpc.dylib]]"],
            "infoIntent": {
                "action": "fetch[/usr/lib]:",
                "component": "com.example.helper[/usr/lib]",
                "data": "myapp://x/[abc]",
                "extras": {"token[/bad]": {"type": "string", "value": "value[/usr/lib]"}},
            },
            "ipc": {"kind": "xpc", "direction": "outgoing", "peer": {"path": "/usr/lib/[evil]"}},
        }

        rendered = render_intercept_block(payload, 1, show_stack=True, stack_depth=1)

        Text.from_markup(rendered)
        self.assertIn("\\[/usr/lib", rendered)

    def test_render_intercept_block_shows_surface_labels_inline(self):
        payload = {
            "className": "MyApp",
            "methodName": "-[Delegate listener:shouldAcceptNewConnection:]",
            "stackTrace": [],
            "attackSurface": {"direction": "incoming", "exposure": "listener", "privileged": True},
            "infoIntent": {"component": "com.example.app.service", "action": "accept connection"},
            "ipc": {"kind": "nsxpc_accept", "direction": "incoming"},
        }

        rendered = render_intercept_block(payload, 1, show_stack=False, stack_depth=1)

        self.assertIn(
            "[bold]Class[/bold]      [dim]MyApp[/dim]  [#C94A8A][Incoming][/#C94A8A] "
            "[#C94A8A][Listener][/#C94A8A] [#F2C94C][Privileged][/#F2C94C]",
            rendered,
        )
        self.assertIn("NSXPC LISTENER", rendered)

    def test_render_intent_detail_includes_changes(self):
        entry = {
            "id": 3,
            "timestamp": "2026-04-27T12:34:56+00:00",
            "class": "MyApp",
            "method": "-[AppDelegate application:openURL:options:]",
            "outcome": "modified_forwarded",
            "intent": {
                "action": "openURL",
                "component": "com.apple.mobilesafari",
                "data": "myapp://new",
                "extras": {
                    "changed": {"type": "string", "value": "new"},
                    "added": {"type": "string", "value": "value"},
                },
            },
            "original_intent": {
                "action": "openURL",
                "data": "myapp://old",
                "extras": {
                    "changed": {"type": "string", "value": "old"},
                    "removed": {"type": "string", "value": "gone"},
                },
            },
            "ipc": {"kind": "url", "direction": "incoming"},
            "stackTrace": ["frame1", "frame2"],
        }

        rendered = render_intent_detail(entry, show_stack=True, stack_depth=1)

        self.assertIn("forwarded (modified)", rendered)
        self.assertIn("CHANGES", rendered)
        self.assertIn("myapp://old", rendered)
        self.assertIn("myapp://new", rendered)
        self.assertIn("changed", rendered)
        self.assertIn("removed", rendered)
        self.assertIn("added", rendered)
        self.assertIn("frame1", rendered)
        self.assertIn("... (+1 more)", rendered)

    def test_render_intent_detail_escapes_dynamic_markup(self):
        entry = {
            "id": 9,
            "timestamp": "2026-04-27T12:34:56+00:00",
            "class": "MyApp[Bad]",
            "method": "xpc_connection_send_message",
            "intent": {
                "action": "action[/usr/lib]",
                "component": "component[abc]",
                "data": "myapp://x/[/usr/lib]",
                "extras": {"key[/bad]": {"type": "string", "value": "value[/usr/lib]"}},
            },
            "original_intent": {
                "data": "old-data[/usr/lib]",
                "extras": {"key[/bad]": {"type": "string", "value": "old[/usr/lib]"}},
            },
            "ipc": {"kind": "xpc", "description": "<dictionary> { k = [/usr/lib] }"},
            "stackTrace": ["frame[/usr/lib]"],
        }

        rendered = render_intent_detail(entry, show_stack=True, stack_depth=1)

        Text.from_markup(rendered)
        self.assertIn("\\[/usr/lib", rendered)

    def test_render_intent_detail_without_stack_trace(self):
        entry = {"id": 10, "class": "MyApp", "method": "m", "intent": {}, "stackTrace": []}

        rendered = render_intent_detail(entry, show_stack=True, stack_depth=1)

        self.assertIn("No stack trace captured.", rendered)
        self.assertIn("[dim]pending[/dim]", rendered)


if __name__ == "__main__":
    unittest.main()
