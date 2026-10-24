"""Bounded observer/refusal/cleanup controls; no BPF, Cargo or network execution."""
from copy import deepcopy
import io
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

import linux_cpu as cpu
import syscall_probe as probe


IDENTITY = dict(pid=101,start_ticks=100,threads=1)


def counts():
    values = [0]*probe.COUNTERS
    values[4*5] = 11
    values[4*5+2] = 10  # Unbalanced by design: one boundary-censored entry.
    return dict(event="disabled",counts=values,bins=list(probe.BINS),classes=list(probe.CLASSES),
                loader_lifetime_user_us=1000,loader_lifetime_system_us=2000,loader_lifetime_maxrss_kib=4096)


class CounterTests(unittest.TestCase):
    def test_eagain_and_unbalanced_boundaries_are_preserved(self):
        result=probe.validate_counts(counts())
        self.assertEqual(result["recvfrom"]["enter"],11)
        self.assertEqual(result["recvfrom"]["exit_eagain"],10)

    def test_shape_saturation_read_errors_and_foreign_threads_refuse(self):
        for changed in ([0]*probe.COUNTERS, [0], None):
            with self.assertRaises(ValueError):
                probe.validate_counts(dict(counts(),counts=changed))
        for index,value in ((0,-1),(0,True),(0,2**64-1),(-1,1),(-2,1)):
            record=counts()
            record["counts"][index]=value
            with self.assertRaises(ValueError):
                probe.validate_counts(record)

    def test_diagnostic_is_never_primary_acceptance(self):
        self.assertFalse(cpu.accepted(dict(passed=True,mode="clean",syscall_diagnostic=True),.01))

    def test_failed_cpu_or_latency_gate_withholds_overhead_ratio(self):
        off=dict(passed=True,syscall_trace=dict(available=True),report=dict(achieved_ops_per_second=1000,completed=2),cpu_cost=dict(server=dict(total_seconds=1)))
        on=deepcopy(off)
        with patch.object(probe,"diagnostic_gate",return_value=False),patch.object(cpu,"report_latencies",return_value=[1000,1000]):
            self.assertIsNone(probe.comparison(off,on,.01)["server_cpu_ratio"])
        with patch.object(probe,"diagnostic_gate",return_value=True), \
                patch.object(cpu,"report_latencies",side_effect=[[1000,1000],[15000,15000]]):
            result=probe.comparison(off,on,.01)
        self.assertFalse(result["eligible"])
        self.assertFalse(result["latency_delta_ns"]["passed"])
        self.assertIsNone(result["server_cpu_ratio"])

    def test_pooled_latency_failure_and_incomplete_pairs_withhold_ratio(self):
        self.assertFalse(probe.latency_guard(dict(off=[1000]*4,on=[14000]*4))["passed"])
        result=probe.pooled([],[],4)
        self.assertTrue(all(not row["eligible"] and row["server_cpu_ratio"] is None for row in result))


class LifecycleTests(unittest.TestCase):
    def capture(self, directory, arm="on"):
        owner=probe.Observer(arm,"loader","object")
        target=Mock(pid=101)
        with patch.object(probe,"target_identity",return_value=IDENTITY):
            capture=probe.Capture(owner,target,directory)
        owner.capture=capture
        return owner,capture

    def test_off_has_no_helper_or_attachment_at_all(self):
        with tempfile.TemporaryDirectory() as temporary:
            owner,capture=self.capture(Path(temporary),"off")
            with patch.object(probe,"target_identity",return_value=IDENTITY), \
                    patch.object(cpu,"spawn") as spawn, patch.object(cpu,"stop") as stop, \
                    patch.object(cpu,"scheduler_snapshot",return_value={"available":False}), \
                    patch.object(cpu,"scheduler_delta",return_value={"available":False}):
                capture.start()
                capture.enable()
                capture.finish()
                capture.close()
            spawn.assert_not_called()
            stop.assert_not_called()
            self.assertFalse(capture["attached"])
            self.assertTrue(capture["available"])

    def test_cancel_or_identity_change_refuses_before_command(self):
        with tempfile.TemporaryDirectory() as temporary:
            owner,capture=self.capture(Path(temporary))
            owner.cancel=threading.Event()
            owner.cancel.set()
            with self.assertRaises(InterruptedError):
                capture.enable()
            owner.cancel=None
            with patch.object(probe,"target_identity",return_value=dict(IDENTITY,start_ticks=101)):
                with self.assertRaisesRegex(RuntimeError,"identity changed"):
                    capture.enable()

    def test_wrong_order_and_timeout_still_settle_privileged_group(self):
        for problem in (ValueError("malformed ACK"), TimeoutError("control deadline")):
            with tempfile.TemporaryDirectory() as temporary:
                owner,capture=self.capture(Path(temporary))
                capture.helper=Mock(stdin=io.StringIO(),stdout=io.StringIO())
                capture.log=io.BytesIO()
                capture.phase=1
                with patch.object(capture,"check"),patch.object(capture,"reply",side_effect=problem), \
                        patch.object(cpu,"stop") as stop:
                    with self.assertRaises(type(problem)):
                        capture.finish()
                    capture.close()
                stop.assert_called_once_with(capture.helper,elevated=True)
                self.assertFalse(capture["available"])

    def test_real_reply_timeout_names_helper_ack_and_still_cleans_up(self):
        for cleanup_error in (None, PermissionError("cannot reap helper")):
            with self.subTest(cleanup_error=cleanup_error), tempfile.TemporaryDirectory() as temporary:
                owner,capture=self.capture(Path(temporary))
                release,finished=threading.Event(),threading.Event()

                def readline(limit):
                    try:
                        release.wait(1)  # Bounded even if cleanup regresses.
                        return ""
                    finally:
                        finished.set()

                stream=Mock(readline=readline,close=release.set)
                capture.helper=Mock(stdin=io.StringIO(),stdout=stream)
                capture.log=io.BytesIO()
                capture.deadline=.02
                try:
                    # Stable controller clock; the shared reader still waits 20ms.
                    with patch.object(capture,"check"), \
                            patch.object(probe.time,"monotonic",return_value=0), \
                            patch.object(cpu,"scheduler_snapshot",return_value={"available":False}), \
                            patch.object(cpu,"stop",side_effect=cleanup_error) as stop:
                        with self.assertRaisesRegex(TimeoutError,"syscall helper enabled ACK deadline") as raised:
                            with owner(capture.target,Path(temporary)):
                                capture.enable()
                    self.assertIsInstance(raised.exception.__cause__,TimeoutError)
                    self.assertEqual(str(raised.exception.__cause__),"native client control deadline")
                    self.assertIsNotNone(raised.exception.__cause__.__cause__)
                    self.assertIs(raised.exception.syscall_capture,capture)
                    stop.assert_called_once_with(capture.helper,elevated=True)
                    self.assertFalse(capture["available"])
                    self.assertNotIn("enable_ack_ns",capture)
                    self.assertEqual(owner.unresolved,cleanup_error is not None)
                    if cleanup_error is not None:
                        self.assertTrue(raised.exception.cleanup_unresolved)
                        with patch.object(cpu,"spawn") as spawn:
                            with self.assertRaisesRegex(RuntimeError,"previous privileged"):
                                owner.prepare_target(Mock(),Path(temporary))
                            spawn.assert_not_called()
                finally:
                    release.set()
                    self.assertTrue(finished.wait(1),"bounded control reader did not settle")

    def test_non_timeout_reply_failure_is_not_relabelled(self):
        with tempfile.TemporaryDirectory() as temporary:
            owner,capture=self.capture(Path(temporary))
            capture.helper=Mock(stdout=io.StringIO())
            original=RuntimeError("native client line exceeded bound or ended incompletely")
            with patch.object(capture,"check"), \
                    patch.object(probe.native,"control_line",side_effect=original):
                with self.assertRaises(RuntimeError) as raised:
                    capture.reply("enabled")
            self.assertIs(raised.exception,original)

    def test_cleanup_failure_is_fatal_and_prevents_next_helper(self):
        with tempfile.TemporaryDirectory() as temporary:
            owner,capture=self.capture(Path(temporary))
            capture.helper=Mock(stdin=io.StringIO(),stdout=io.StringIO())
            capture.log=io.BytesIO()
            with patch.object(cpu,"stop",side_effect=PermissionError("root group still alive")):
                with self.assertRaises(PermissionError) as raised:
                    capture.close()
            self.assertTrue(raised.exception.cleanup_unresolved)
            self.assertTrue(owner.unresolved)
            self.assertTrue(cpu.unresolved_cleanup(dict(syscall_trace=capture)))
            with patch.object(cpu,"spawn") as spawn:
                with self.assertRaisesRegex(RuntimeError,"previous privileged"):
                    owner.prepare_target(Mock(),Path(temporary))
                spawn.assert_not_called()

    def test_failed_context_keeps_primary_and_cleanup_refusal(self):
        with tempfile.TemporaryDirectory() as temporary:
            owner,capture=self.capture(Path(temporary))
            capture.helper=Mock(stdin=io.StringIO(),stdout=io.StringIO())
            capture.log=io.BytesIO()
            original=TimeoutError("native gate failed")
            with patch.object(cpu,"stop",side_effect=PermissionError("cannot reap")):
                with self.assertRaises(TimeoutError) as raised:
                    with owner(capture.target,Path(temporary)):
                        raise original
            self.assertIs(raised.exception,original)
            self.assertTrue(original.cleanup_unresolved)
            self.assertIs(original.syscall_capture,capture)

    def test_anomaly_raw_report_is_saved_before_validation_refusal(self):
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)
            owner,capture=self.capture(path)
            capture.helper=Mock(stdin=io.StringIO())
            capture.phase=1
            record=counts()
            record["counts"][-1]=1
            with patch.object(capture,"check"),patch.object(capture,"reply",return_value=record):
                with self.assertRaises(ValueError):
                    capture.finish()
            self.assertEqual(json.loads((path/"syscall-counts.json").read_text()),record)

    def test_unsupported_fixture_refuses_before_any_spawn(self):
        with patch.object(cpu,"spawn") as spawn:
            with self.assertRaisesRegex(ValueError,"ordinary Mio"):
                cpu.window(None,None,("oscore",32,1000,"coaptic-mio-direct"),2,Path("unused"),
                           syscall_observer=probe.Observer("on","loader","object"))
            spawn.assert_not_called()


if __name__=="__main__":
    unittest.main()
