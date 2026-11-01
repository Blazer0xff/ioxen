"""End-to-end test of the iOS agent decision protocol with a real Frida runtime.

The iOS agent holds a hooked thread in recv().wait() until the host posts a
wake message after the forward/drop RPC. That behavior is platform
independent, so this test runs agent/ios/decisions.js inside a local child
process (getuid() stands in for an XPC send) and drives it through
FridaSession exactly like a real iOS session.

Opt-in: requires IOXEN_FRIDA_INTEGRATION=1, a local Frida device that can
attach to child processes, and node_modules/ (npm install) for frida-compile.
"""

import os
import queue
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from ioxen.agent_loader import HooksLoadResult, ScriptLoadResult
from ioxen.filters import FilterManager
from ioxen.frida_session import FridaSession, SessionConfig

ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / "tests" / "frida" / "decision_harness.js"
FRIDA_COMPILE = ROOT / "node_modules" / ".bin" / "frida-compile"

CHILD = (
    "import os, sys, time\n"
    "while True:\n"
    "    print(os.getuid(), flush=True)\n"
    "    time.sleep(0.02)\n"
)


def _integration_enabled() -> str | None:
    if os.environ.get("IOXEN_FRIDA_INTEGRATION") != "1":
        return "set IOXEN_FRIDA_INTEGRATION=1 to run Frida integration tests"
    if not FRIDA_COMPILE.exists() or shutil.which("node") is None:
        return "frida-compile not installed (run npm install)"
    try:
        import frida  # noqa: F401
    except ImportError:
        return "frida not installed"
    return None


SKIP_REASON = _integration_enabled()


@unittest.skipIf(SKIP_REASON is not None, SKIP_REASON or "")
class IOSDecisionProtocolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        bundle = Path(cls._tmp.name) / "harness_bundle.js"
        subprocess.run(
            [str(FRIDA_COMPILE), str(HARNESS), "-o", str(bundle), "-T", "none", "--bundle-format", "iife"],
            cwd=ROOT,
            check=True,
            capture_output=True,
        )
        cls.code = bundle.read_text(encoding="utf-8")

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def setUp(self):
        import frida

        self.child = subprocess.Popen([sys.executable, "-u", "-c", CHILD], stdout=subprocess.PIPE, text=True)
        self.lines: queue.Queue[str] = queue.Queue()
        threading.Thread(target=self._pump, daemon=True).start()
        self.assertEqual(self._next_line(), str(os.getuid()))

        self.real_uid = str(os.getuid())
        self.decisions: queue.Queue = queue.Queue()
        self.connected = threading.Event()
        self.logs = []
        self.filters = FilterManager()
        self.session = FridaSession(
            SessionConfig(attach_pid=self.child.pid),
            self.filters,
            log_cb=self.logs.append,
            intercept_cb=lambda _state: None,
            get_stack=lambda: (False, 0),
            history_cb=lambda _payload, counter: counter,
            outcome_cb=lambda _db_id, _outcome: None,
            intercept_log_cb=lambda _text, db_id, decision_id: self.decisions.put(decision_id),
        )
        self.session.connected_cb = self.connected.set
        local = frida.get_local_device()
        with patch("ioxen.frida_session.load_agent_script", return_value=ScriptLoadResult(self.code, [])), patch(
            "ioxen.frida_session.load_hook_config", return_value=HooksLoadResult([], [])
        ):
            self.session.connect(local.id)
            self.assertTrue(self.connected.wait(timeout=15), self.logs)

    def tearDown(self):
        self.session.cleanup()
        self.child.kill()
        self.child.wait(timeout=5)

    def _pump(self):
        for line in self.child.stdout:
            self.lines.put(line.strip())

    def _next_line(self, timeout=5.0) -> str:
        return self.lines.get(timeout=timeout)

    def _drain(self):
        while not self.lines.empty():
            self.lines.get_nowait()

    def _held_decision(self) -> str:
        decision_id = self.decisions.get(timeout=5)
        self.assertTrue(decision_id.startswith("decision-"))
        # The child must be stuck inside getuid() while the decision is open.
        time.sleep(0.3)
        self._drain()
        time.sleep(0.3)
        self.assertTrue(self.lines.empty(), "hooked thread was not held")
        return decision_id

    def test_non_apple_harness_is_flagged_but_still_attached(self):
        # The harness is a local Linux process standing in for an iOS app.
        text = "\n".join(self.logs)
        self.assertIn("ioxen only supports iOS and other Apple targets", text)
        self.assertTrue(self.session.is_ready())

    def test_forward_drop_and_modify(self):
        decision_id = self._held_decision()
        self.assertFalse(self.session.forward("decision-unknown"))
        self.assertTrue(self.session.forward(decision_id))
        self.assertEqual(self._next_line(), self.real_uid)

        decision_id = self._held_decision()
        self.assertTrue(self.session.drop(decision_id))
        self.assertEqual(self._next_line(), "4242")

        decision_id = self._held_decision()
        self.assertFalse(self.session.stage_mod("data", "", "x", "", decision_id))
        self.assertTrue(self.session.stage_mod("extra_add", "uid", "777", "int64", decision_id))
        self.assertTrue(self.session.forward(decision_id))
        self.assertEqual(self._next_line(), "777")

    def test_agent_side_filters_skip_holding(self):
        self._held_decision()
        self.filters.add("focus", ["direction=incoming"])
        self.assertTrue(self.session.sync_filters())
        # Releasing the held event lets the loop continue unheld.
        self.session.intercept_off()
        self.session.intercept_on()
        self._drain()
        for _ in range(5):
            self.assertEqual(self._next_line(), self.real_uid)

    def test_intercept_off_releases_held_thread(self):
        self._held_decision()
        self.session.intercept_off()
        self.assertEqual(self._next_line(), self.real_uid)

    def test_cleanup_releases_held_thread(self):
        self._held_decision()
        self.session.cleanup()
        time.sleep(0.5)
        self._drain()
        self.assertEqual(self._next_line(), self.real_uid)


if __name__ == "__main__":
    unittest.main()
