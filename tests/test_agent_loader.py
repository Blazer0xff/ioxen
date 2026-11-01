import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ioxen.agent_loader import (
    PASSTHROUGH_AGENT,
    load_agent_script,
    load_hook_config,
    load_json_hooks,
)


class AgentLoaderTests(unittest.TestCase):
    def test_load_json_hooks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "hooks.json")
            with open(path, "w") as f:
                f.write('[{"kind": "xpc", "function": "xpc_connection_send_message"}]')

            self.assertEqual(
                load_json_hooks(path),
                [{"kind": "xpc", "function": "xpc_connection_send_message"}],
            )

    def test_load_hook_config_combines_default_and_custom_hooks(self):
        with self._temp_cwd() as tmp:
            os.makedirs("config")
            default = os.path.join(tmp, "config", "ios_hooks.json")
            with open(default, "w") as f:
                f.write('[{"kind": "xpc", "function": "default"}]')
            custom = os.path.join(tmp, "custom.json")
            with open(custom, "w") as f:
                f.write('[{"kind": "xpc", "function": "custom"}]')

            with patch("ioxen.agent_loader.HOOKS_FILE", default):
                result = load_hook_config(custom)

            self.assertEqual([hook["function"] for hook in result.hooks], ["default", "custom"])
            self.assertEqual(result.messages, [])

    def test_load_hook_config_reports_invalid_custom_json(self):
        with self._temp_cwd():
            os.makedirs("config")
            default = os.path.abspath("config/ios_hooks.json")
            with open(default, "w") as f:
                f.write("[]")
            with open("bad.json", "w") as f:
                f.write("{bad-json")

            with patch("ioxen.agent_loader.HOOKS_FILE", default):
                result = load_hook_config("bad.json")

            self.assertEqual(result.hooks, [])
            self.assertIn("Invalid JSON in bad.json", result.messages[0])

    def test_load_agent_script_prefers_bundle_and_appends_extra(self):
        with self._temp_cwd():
            os.makedirs("agent")
            bundle = os.path.abspath("agent/ios_script_bundle.js")
            with open(bundle, "w") as f:
                f.write("bundle")
            with open("extra.js", "w") as f:
                f.write("extra")

            with patch("ioxen.agent_loader.BUNDLE_SCRIPT_FILE", bundle):
                result = load_agent_script("extra.js")

            self.assertEqual(result.code, "bundle\n\nextra")
            self.assertEqual(result.messages, ["[dim]loader       [/dim] [dim]DEBUG[/dim] Extra script loaded: extra.js"])

    def test_load_agent_script_uses_passthrough_when_no_bundle_exists(self):
        with self._temp_cwd():
            with patch("ioxen.agent_loader.BUNDLE_SCRIPT_FILE", os.path.abspath("agent/ios_script_bundle.js")):
                result = load_agent_script()

            self.assertEqual(result.code, PASSTHROUGH_AGENT)
            self.assertEqual(len(result.messages), 1)
            self.assertIn("running in passthrough mode", result.messages[0])

    def test_default_hooks_fall_back_to_packaged_runtime(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source" / "config" / "ios_hooks.json"
            packaged = root / "runtime" / "config" / "ios_hooks.json"
            packaged.parent.mkdir(parents=True)
            packaged.write_text('[{"kind": "xpc", "function": "packaged"}]', encoding="utf-8")

            with patch("ioxen.agent_loader.SOURCE_HOOKS_FILE", source):
                with patch("ioxen.agent_loader.HOOKS_FILE", source):
                    with patch("ioxen.agent_loader.PACKAGED_HOOKS_FILE", packaged):
                        result = load_hook_config()

            self.assertEqual([hook["function"] for hook in result.hooks], ["packaged"])
            self.assertEqual(result.messages, [])

    def test_agent_script_falls_back_to_packaged_runtime(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_bundle = root / "source" / "agent" / "ios_script_bundle.js"
            packaged_bundle = root / "runtime" / "agent" / "ios_script_bundle.js"
            packaged_bundle.parent.mkdir(parents=True)
            packaged_bundle.write_text("packaged bundle", encoding="utf-8")

            with patch("ioxen.agent_loader.SOURCE_BUNDLE_SCRIPT_FILE", source_bundle):
                with patch("ioxen.agent_loader.BUNDLE_SCRIPT_FILE", source_bundle):
                    with patch("ioxen.agent_loader.PACKAGED_BUNDLE_SCRIPT_FILE", packaged_bundle):
                        result = load_agent_script()

            self.assertEqual(result.code, "packaged bundle")
            self.assertEqual(result.messages, [])

    def test_default_paths_are_independent_from_current_directory(self):
        with self._temp_cwd():
            hooks = load_hook_config()
            script = load_agent_script()

        self.assertEqual(hooks.messages, [])
        self.assertTrue(hooks.hooks)
        self.assertEqual(script.messages, [])
        self.assertNotEqual(script.code, PASSTHROUGH_AGENT)

    def _temp_cwd(self):
        return _TempCwd()


class _TempCwd:
    def __enter__(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._previous = os.getcwd()
        os.chdir(self._tmp.name)
        return self._tmp.name

    def __exit__(self, exc_type, exc, tb):
        os.chdir(self._previous)
        self._tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
