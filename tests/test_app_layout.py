import os
import re
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from ioxen.app import (
    HISTORY_COMMAND_OUTPUT_HEIGHT,
    INTERCEPT_COMMAND_OUTPUT_HEIGHT,
    MAX_COMMAND_OUTPUT_HEIGHT,
    MIN_PANEL_HEIGHT,
    IoxenApp,
    clamp_height,
    max_primary_panel_height,
)
from ioxen.logging_ui import log_debug, log_error, log_info, log_success, log_warning


def css_int_property(selector: str, property_name: str) -> int:
    css_path = Path(__file__).resolve().parents[1] / "src" / "ioxen" / "ioxen.tcss"
    css = css_path.read_text(encoding="utf-8")
    match = re.search(rf"{re.escape(selector)}\s*\{{[^}}]*{property_name}:\s*(\d+);", css, re.S)
    if match is None:
        raise AssertionError(f"{selector} {property_name} not found in ioxen.tcss")
    return int(match.group(1))


def css_property(selector: str, property_name: str) -> str:
    css_path = Path(__file__).resolve().parents[1] / "src" / "ioxen" / "ioxen.tcss"
    css = css_path.read_text(encoding="utf-8")
    match = re.search(rf"{re.escape(selector)}\s*\{{[^}}]*{property_name}:\s*([^;]+);", css, re.S)
    if match is None:
        raise AssertionError(f"{selector} {property_name} not found in ioxen.tcss")
    return match.group(1).strip()


def css_height(selector: str) -> int:
    return css_int_property(selector, "height")


class AppLayoutTests(unittest.TestCase):
    def test_command_output_defaults_match_tcss(self):
        self.assertEqual(css_height("#intercept_cmd_output"), INTERCEPT_COMMAND_OUTPUT_HEIGHT)
        self.assertEqual(css_height("#history_cmd_output"), HISTORY_COMMAND_OUTPUT_HEIGHT)

    def test_command_output_defaults_are_inside_resize_bounds(self):
        self.assertGreaterEqual(INTERCEPT_COMMAND_OUTPUT_HEIGHT, MIN_PANEL_HEIGHT)
        self.assertLessEqual(INTERCEPT_COMMAND_OUTPUT_HEIGHT, MAX_COMMAND_OUTPUT_HEIGHT)
        self.assertGreaterEqual(HISTORY_COMMAND_OUTPUT_HEIGHT, MIN_PANEL_HEIGHT)
        self.assertLessEqual(HISTORY_COMMAND_OUTPUT_HEIGHT, MAX_COMMAND_OUTPUT_HEIGHT)

    def test_intercept_toggle_width_fits_off_label(self):
        self.assertGreaterEqual(css_int_property("#intercept_header #intercept_toggle", "width"), 21)

    def test_clamp_height_applies_minimum_and_optional_maximum(self):
        self.assertEqual(clamp_height(1, minimum=3), 3)
        self.assertEqual(clamp_height(5, minimum=3), 5)
        self.assertEqual(clamp_height(30, minimum=3, maximum=20), 20)

    def test_max_primary_panel_height_preserves_secondary_minimum(self):
        self.assertEqual(max_primary_panel_height(10, 8, secondary_minimum=3), 15)
        self.assertEqual(max_primary_panel_height(1, 1, secondary_minimum=3), MIN_PANEL_HEIGHT)

    def test_every_log_level_reaches_the_console_and_the_project_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake = _FakeLogApp(os.path.join(tmp, "proj.ioxen"))
            lines = [
                log_debug("Hook detail", "agent"),
                log_info("Visible event", "frida"),
                log_success("Hooks ready", "agent"),
                log_warning("Hook skipped", "agent"),
                log_error("Hook failed", "agent"),
            ]
            for line in lines:
                IoxenApp.write_log(fake, line)

            with open(os.path.join(tmp, "proj.log"), encoding="utf-8") as f:
                mirrored = f.read().splitlines()

        self.assertEqual(fake.written, [("log_output", line) for line in lines])
        self.assertEqual(len(mirrored), len(lines))
        self.assertIn("DEBUG Hook detail", mirrored[0])


class _FakeLogApp:
    def __init__(self, project_path):
        self.db = SimpleNamespace(path=project_path)
        self.written = []

    def _write_rich(self, widget_id, text, _notify=False):
        self.written.append((widget_id, text))


if __name__ == "__main__":
    unittest.main()
