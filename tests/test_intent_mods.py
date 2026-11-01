import unittest

from ioxen.intent_mods import (
    apply_mods_to_entry,
    parse_intent_mod_command,
    value_type_display,
)


class IntentModsTests(unittest.TestCase):
    def test_apply_mods_to_entry_records_original_snapshot(self):
        entry = {
            "intent": {
                "action": "openURL",
                "data": "myapp://old",
                "extras": {
                    "token": {"type": "string", "value": "old"},
                    "remove_me": {"type": "string", "value": "gone"},
                },
            }
        }

        apply_mods_to_entry(entry, [
            ("data", "", "myapp://new", ""),
            ("extra_rem", "remove_me", "", ""),
            ("extra_add", "token", "new", "string"),
            ("extra_add", "added", "42", "int"),
        ])

        self.assertEqual(entry["original_intent"]["data"], "myapp://old")
        self.assertEqual(entry["original_intent"]["extras"]["token"]["value"], "old")
        self.assertEqual(entry["intent"]["action"], "openURL")
        self.assertEqual(entry["intent"]["data"], "myapp://new")
        self.assertNotIn("remove_me", entry["intent"]["extras"])
        self.assertEqual(entry["intent"]["extras"]["token"], {"type": "string", "value": "new"})
        self.assertEqual(entry["intent"]["extras"]["added"], {"type": "int64", "value": "42"})

    def test_apply_mods_without_mods_leaves_entry_untouched(self):
        entry = {"intent": {"data": "myapp://x"}}
        apply_mods_to_entry(entry, [])
        self.assertEqual(entry, {"intent": {"data": "myapp://x"}})

    def test_value_type_display(self):
        self.assertEqual(value_type_display("__NSCFString"), "__NSCFString")
        self.assertEqual(value_type_display("int64"), "int64")
        self.assertEqual(value_type_display(""), "-")

    def test_parse_intent_mod_command(self):
        self.assertEqual(
            parse_intent_mod_command(["data", "myapp://open?id=1"]),
            (("data", "", "myapp://open?id=1", ""), None),
        )
        self.assertEqual(
            parse_intent_mod_command(["+x", "string", "token", "hello", "world"]),
            (("extra_add", "token", "hello world", "string"), None),
        )
        self.assertEqual(
            parse_intent_mod_command(["+x", "token", "hello", "world"]),
            (("extra_add", "token", "hello world", "string"), None),
        )
        self.assertEqual(
            parse_intent_mod_command(["-x", "token"]),
            (("extra_rem", "token", "", ""), None),
        )

    def test_removed_android_commands_are_not_parsed(self):
        for parts in (["action", "x"], ["+cat", "x"], ["-cat", "x"], ["+flag", "1"], ["-flag", "1"]):
            self.assertEqual(parse_intent_mod_command(parts), (None, None))

    def test_parse_intent_mod_command_reports_usage_errors(self):
        self.assertEqual(
            parse_intent_mod_command(["data"]),
            (None, "[red]Usage: data <url>[/red]"),
        )
        self.assertEqual(
            parse_intent_mod_command(["+x"]),
            (None, "[red]Usage: +x (type) <key> <value>[/red]"),
        )
        self.assertEqual(
            parse_intent_mod_command(["-x"]),
            (None, "[red]Usage: -x <key>[/red]"),
        )


if __name__ == "__main__":
    unittest.main()
