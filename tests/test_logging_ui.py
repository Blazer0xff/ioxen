import unittest

from rich.text import Text

from ioxen.logging_ui import log_debug, log_error, log_info, log_success, log_warning


class LoggingUiTests(unittest.TestCase):
    def test_log_lines_have_consistent_source_level_message_shape(self):
        self.assertEqual(log_info("Ready", "ioxen"), "[dim]ioxen        [/dim] [dim]INFO [/dim] Ready")
        self.assertEqual(log_debug("Loaded", "loader"), "[dim]loader       [/dim] [dim]DEBUG[/dim] Loaded")
        self.assertEqual(log_success("Attached", "frida"), "[dim]frida        [/dim] [#26a368]OK   [/#26a368] Attached")
        self.assertEqual(log_warning("Skipped", "agent"), "[dim]agent        [/dim] [yellow]WARN [/yellow] Skipped")
        self.assertEqual(log_error("Failed", "agent"), "[dim]agent        [/dim] [red]ERROR[/red] Failed")

    def test_dynamic_log_message_is_markup_escaped(self):
        message = (
            "Native exception: -[NSXPCConnection _decodeAndInvokeMessage:[/usr/lib/libxpc.dylib]],"
            "frames=[/usr/lib/system/libxpc.dylib, /System/Library/Frameworks/Foundation]]"
        )
        line = log_error(message, "agent")

        Text.from_markup(line)
        self.assertIn("\\[/usr/lib/system/libxpc.dylib", line)


if __name__ == "__main__":
    unittest.main()
