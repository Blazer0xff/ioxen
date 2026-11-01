"""Runs the real iOS agent bundle against a mock libxpc on the local machine.

tests/frida/mock_libxpc.c implements the libxpc C API subset the agent uses
(dictionary/array/scalar objects, block-based event and reply handlers,
send/reply/sync calls) and prints what the "remote" side receives. This
exercises the agent's XPC layer end to end with real Frida: export lookup,
Interceptor.replace on the send functions, global-block wrapping of event and
reply handlers, message decoding, drop semantics and modifications.

Opt-in: IOXEN_FRIDA_INTEGRATION=1, clang with -fblocks and libBlocksRuntime.
"""

import os
import queue
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path

from ioxen.filters import FilterManager
from ioxen.frida_session import FridaSession, SessionConfig

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "frida"


def _skip_reason() -> str | None:
    if os.environ.get("IOXEN_FRIDA_INTEGRATION") != "1":
        return "set IOXEN_FRIDA_INTEGRATION=1 to run Frida integration tests"
    if shutil.which("clang") is None:
        return "clang not installed"
    if not (ROOT / "agent" / "ios_script_bundle.js").exists():
        return "iOS agent bundle missing (npm run build)"
    try:
        import frida  # noqa: F401
    except ImportError:
        return "frida not installed"
    return None


SKIP_REASON = _skip_reason()


@unittest.skipIf(SKIP_REASON is not None, SKIP_REASON or "")
class IOSAgentXpcTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        out = Path(cls._tmp.name)
        try:
            subprocess.run(
                ["clang", "-fblocks", "-shared", "-fPIC", str(FIXTURES / "mock_libxpc.c"),
                 "-o", str(out / "libmockxpc.so"), "-lBlocksRuntime", "-lpthread"],
                check=True, capture_output=True,
            )
            subprocess.run(
                ["clang", "-fblocks", str(FIXTURES / "xpc_driver.c"), "-o", str(out / "xpc_driver"),
                 f"-L{out}", "-lmockxpc", "-lBlocksRuntime", "-Wl,-rpath," + str(out)],
                check=True, capture_output=True,
            )
        except subprocess.CalledProcessError as e:
            cls._tmp.cleanup()
            raise unittest.SkipTest(f"cannot build mock libxpc: {e.stderr.decode(errors='replace')[:300]}")
        cls.driver = out / "xpc_driver"

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def setUp(self):
        import frida

        self.proc = subprocess.Popen(
            [str(self.driver)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1,
        )
        self.lines: queue.Queue[str] = queue.Queue()
        threading.Thread(target=self._pump, daemon=True).start()
        self.expect("STARTED")

        self.events: queue.Queue = queue.Queue()
        self.payloads = []
        self.logs = []
        self.connected = threading.Event()
        self.filters = FilterManager()
        self.session = FridaSession(
            SessionConfig(attach_pid=self.proc.pid),
            self.filters,
            log_cb=self.logs.append,
            intercept_cb=lambda _state: None,
            get_stack=lambda: (False, 0),
            history_cb=self._history,
            outcome_cb=lambda _db_id, _outcome: None,
            intercept_log_cb=lambda _text, db_id, decision_id: self.events.put((self.payloads[db_id - 1], decision_id)),
        )
        self.session.connected_cb = self.connected.set
        self.session.connect(frida.get_local_device().id)
        self.assertTrue(self.connected.wait(timeout=20), "\n".join(self.logs))
        self.command("setup")
        self.expect("DONE setup")

    def tearDown(self):
        self.session.cleanup()
        self.proc.kill()
        self.proc.wait(timeout=5)

    def _history(self, payload, counter):
        self.payloads.append(payload)
        return counter

    def _pump(self):
        for line in self.proc.stdout:
            self.lines.put(line.rstrip("\n"))

    def command(self, text):
        self.proc.stdin.write(text + "\n")
        self.proc.stdin.flush()

    def expect(self, prefix, timeout=10.0) -> str:
        deadline = time.monotonic() + timeout
        seen = []
        while time.monotonic() < deadline:
            try:
                line = self.lines.get(timeout=max(0.05, deadline - time.monotonic()))
            except queue.Empty:
                break
            if line.startswith(prefix):
                return line
            seen.append(line)
        self.fail(f"expected {prefix!r}; saw {seen}; logs: {self.logs[-10:]}")

    def held(self):
        payload, decision_id = self.events.get(timeout=10)
        self.assertTrue(payload["decision"]["required"])
        return payload, decision_id

    def assert_nothing(self, prefix, wait=0.5):
        time.sleep(wait)
        while not self.lines.empty():
            line = self.lines.get_nowait()
            self.assertFalse(line.startswith(prefix), line)

    # --- tests -------------------------------------------------------------

    def test_agent_reports_hooks(self):
        joined = "\n".join(self.logs)
        self.assertIn("Hooked xpc:xpc_connection_send_message", joined)
        self.assertIn("Hooked xpc:xpc_connection_set_event_handler", joined)
        self.assertIn("Objective-C runtime not available", joined)

    def test_outgoing_message_is_decoded_and_held(self):
        self.command("send")
        payload, decision_id = self.held()
        self.assert_nothing("SENT", wait=0.3)

        info = payload["infoIntent"]
        ipc = payload["ipc"]
        self.assertEqual(payload["methodName"], "xpc_connection_send_message")
        self.assertEqual(payload["className"], "xpc_driver")
        self.assertEqual(info["component"], "com.example.svc")
        self.assertEqual(info["action"], "ping:")
        self.assertEqual(ipc["selectorSource"], "heuristic")
        self.assertEqual(ipc["direction"], "outgoing")
        self.assertEqual(ipc["connection"]["kind"], "mach")
        self.assertEqual(info["extras"]["op"], {"type": "string", "value": "ping"})
        self.assertEqual(info["extras"]["n"], {"type": "int64", "value": "7"})
        self.assertEqual(info["extras"]["nested/flag"], {"type": "bool", "value": "true"})
        self.assertEqual(info["extras"]["list[1]"], {"type": "uint64", "value": "2"})
        self.assertEqual(ipc["blobs"][0]["format"], "bplist16")
        self.assertIn("NSString", ipc["blobs"][0]["strings"])
        self.assertEqual(payload["decision"]["mods"], ["extra_add", "extra_rem"])

        self.assertTrue(self.session.forward(decision_id))
        sent = self.expect("SENT")
        self.assertIn("op='ping'", sent)
        self.assertIn("n=i7", sent)

    def test_modifications_rewrite_the_message(self):
        self.command("send")
        _payload, decision_id = self.held()
        for mod in (
            ("extra_add", "n", "99", "int64"),
            ("extra_rem", "op", "", ""),
            ("extra_add", "nested/name", "bob", "string"),
            ("extra_add", "nested/flag", "false", "bool"),
            ("extra_add", "blob", "00ff", "data"),
            ("extra_add", "big", "18446744073709551615", "uint64"),
            ("extra_add", "ratio", "0.5", "double"),
        ):
            self.assertTrue(self.session.stage_mod(*mod, decision_id), mod)
        self.assertFalse(self.session.stage_mod("action", "", "x", "", decision_id))
        self.assertTrue(self.session.forward(decision_id))

        sent = self.expect("SENT")
        self.assertNotIn("op=", sent)
        self.assertIn("n=i99", sent)
        self.assertIn("nested={flag=false,name='bob'}", sent)
        self.assertIn("blob=<00ff>", sent)
        self.assertIn("big=u18446744073709551615", sent)
        self.assertIn("ratio=d0.5", sent)

    def test_drop_suppresses_send(self):
        self.command("send")
        _payload, decision_id = self.held()
        self.assertTrue(self.session.drop(decision_id))
        self.expect("DONE send")
        self.assert_nothing("SENT")

    def test_async_reply_is_correlated_and_modifiable(self):
        self.command("reply")
        request, decision_id = self.held()
        self.assertTrue(request["ipc"]["expectsReply"])
        self.assertTrue(self.session.forward(decision_id))
        self.expect("SENT")

        reply, reply_decision = self.held()
        self.assertEqual(reply["methodName"], "xpc_reply_handler")
        self.assertEqual(reply["ipc"]["direction"], "reply")
        self.assertEqual(reply["ipc"]["correlation"], request["eventId"])
        self.assertEqual(reply["infoIntent"]["extras"]["echo"], {"type": "int64", "value": "7"})
        self.assertEqual(reply["className"], "xpc_driver")
        self.assertTrue(self.session.stage_mod("extra_add", "reply", "tampered", "string", reply_decision))
        self.assertTrue(self.session.forward(reply_decision))
        self.assertIn("reply='tampered'", self.expect("REPLY"))

    def test_sync_reply_drop_returns_interrupted_error(self):
        self.command("sync")
        _request, decision_id = self.held()
        self.assertTrue(self.session.forward(decision_id))
        reply, reply_decision = self.held()
        self.assertEqual(reply["methodName"], "xpc_connection_send_message_with_reply_sync (reply)")
        self.assertTrue(self.session.drop(reply_decision))
        self.assertEqual(self.expect("SYNC"), "SYNC error:Connection interrupted")

    def test_incoming_message_forward_and_drop(self):
        self.command("incoming")
        payload, decision_id = self.held()
        self.assertEqual(payload["methodName"], "xpc_event_handler")
        self.assertEqual(payload["ipc"]["direction"], "incoming")
        self.assertEqual(payload["infoIntent"]["extras"]["cmd"], {"type": "string", "value": "hello"})
        self.assertTrue(self.session.stage_mod("extra_add", "cmd", "rewritten", "string", decision_id))
        self.assertTrue(self.session.forward(decision_id))
        self.assertIn("cmd='rewritten'", self.expect("HANDLER"))

        self.command("incoming")
        _payload, decision_id = self.held()
        self.assertTrue(self.session.drop(decision_id))
        self.expect("DONE incoming")
        self.assert_nothing("HANDLER")

    def test_new_peer_on_listener_can_be_rejected(self):
        self.command("peer")
        payload, decision_id = self.held()
        self.assertEqual(payload["infoIntent"]["action"], "new peer connection")
        self.assertEqual(payload["attackSurface"]["exposure"], "listener")
        self.assertEqual(payload["ipc"]["connection"]["name"], "com.example.listener")
        self.assertTrue(payload["ipc"]["connection"]["listener"])
        self.assertEqual(payload["decision"]["mods"], [])
        self.assertTrue(self.session.drop(decision_id))
        self.expect("CANCELLED peer")
        self.assert_nothing("PEER")

    def test_agent_side_filter_lets_traffic_through_unheld(self):
        self.filters.add("ignore", ["component=com.example.*"])
        self.assertTrue(self.session.sync_filters())
        self.command("send")
        self.expect("SENT")
        time.sleep(0.2)
        self.assertTrue(self.events.empty())
        self.assertEqual(self.payloads[-1]["decision"]["reason"], "filtered")

    def test_attack_surface_rpc_degrades_gracefully_off_device(self):
        surface = self.session.get_attack_surface()
        self.assertEqual(surface["platform"], "ios")
        self.assertIsNone(surface["entitlements"])
        self.assertEqual(surface["process"]["name"], "xpc_driver")


if __name__ == "__main__":
    unittest.main()
