import json
import os
import tempfile
import unittest
from datetime import datetime

from ioxen.exporting import (
    filter_rule_lines,
    history_entries_label,
    timestamped_filename,
    write_filter_export,
    write_history_export,
)


class ExportingTests(unittest.TestCase):
    def test_history_entries_label(self):
        self.assertEqual(history_entries_label(1), "entry")
        self.assertEqual(history_entries_label(2), "entries")
        self.assertEqual(history_entries_label(1, filtered=True), "filtered entry")
        self.assertEqual(history_entries_label(2, filtered=True), "filtered entries")

    def test_timestamped_filename(self):
        now = datetime(2026, 4, 28, 10, 11, 12)

        self.assertEqual(
            timestamped_filename("history", "json", now),
            "history_20260428_101112.json",
        )

    def test_filter_rule_lines(self):
        self.assertEqual(
            filter_rule_lines(
                [{"class": "*Wrapper", "method": "xpc_connection_send_message"}],
                [{"component": "com.example.helper"}],
            ),
            [
                "ignore class=*Wrapper method=xpc_connection_send_message",
                "focus component=com.example.helper",
            ],
        )

    def test_write_history_export(self):
        with tempfile.TemporaryDirectory() as tmp:
            previous = os.getcwd()
            os.chdir(tmp)
            try:
                result = write_history_export(
                    [{"id": 1, "timestamp": datetime(2026, 4, 28, 10, 11, 12)}],
                    datetime(2026, 4, 28, 10, 11, 12),
                )

                self.assertEqual(result.filename, "history_20260428_101112.json")
                self.assertEqual(result.item_count, 1)
                with open(result.filename) as f:
                    data = json.load(f)
                self.assertEqual(data[0]["id"], 1)
                self.assertEqual(data[0]["timestamp"], "2026-04-28 10:11:12")
            finally:
                os.chdir(previous)

    def test_write_filter_export(self):
        with tempfile.TemporaryDirectory() as tmp:
            previous = os.getcwd()
            os.chdir(tmp)
            try:
                result = write_filter_export(
                    [{"method": "xpc_connection_send_message"}],
                    [{"component": "com.example.helper"}],
                    "history_filters",
                    datetime(2026, 4, 28, 10, 11, 12),
                )

                self.assertEqual(result.filename, "history_filters_20260428_101112.txt")
                self.assertEqual(result.item_count, 2)
                with open(result.filename) as f:
                    self.assertEqual(
                        f.read(),
                        "ignore method=xpc_connection_send_message\nfocus component=com.example.helper\n",
                    )
            finally:
                os.chdir(previous)


if __name__ == "__main__":
    unittest.main()
