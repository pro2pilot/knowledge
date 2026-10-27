"""Adversarial replay of the actual post-exit checker, without privileged work."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import acceptance as a
import controller as c


class Acceptance(unittest.TestCase):
    def evidence(self, mode):
        blob, fixture = c.make_blob()
        tap = ("TAP version 13\n# Subtest: " + c.EXPECTED_TEST_NAME + "\nok 1 - " + c.EXPECTED_TEST_NAME +
               "\n  ---\n  duration_ms: 1\n  type: 'test'\n  ...\n1..1\n# tests 1\n# suites 0\n# pass 1\n# fail 0\n# cancelled 0\n# skipped 0\n# todo 0\n# duration_ms 1\n").encode()
        output = b"" if mode == 1 else tap
        imported = ("KSM1 chroot_root_not_mountpoint EINVAL\n" +
            f"KSI1 {fixture['manifest_sha256']} {fixture['directories_sha256']} {len(fixture['files'])} " +
            f"{sum(item['bytes'] for item in fixture['files'])}\nKSD1 writable_alias_ready\n").encode()
        n = {"status": "FAIL" if mode else "WORK_CLOSED", "production_admission": False, "release_gate_qualified": False,
             "observer_ack_required": True, "component": "readonly_node_namespace", "fault_mode": mode, "fault_reached": bool(mode),
             "cleanup_confirmed": True, "cgroup_empty": True, "output_eof": True,
             "importer_namespace_drained": mode != 1, "importer_detached_writer_ready": mode != 1,
             "source_readonly": mode != 1, "authority_readback": mode != 1,
             "phase": {0: 4, 1: 2, 2: 3}[mode], "work_ms": 30001 if mode else 2000, "cleanup_ms": 2,
             "proof_emitted_ms": 30004 if mode else 2004, "stop_reason": 3 if mode else 4,
             "init_wait_status": 9 if mode else 0, "keeper_wait_status": 0, "worker_wait_status": -1 if mode == 1 else 0,
             "authority_wait_status": -1 if mode else 0, "importer_wait_status": 0,
             "input_manifest_sha256": "" if mode == 1 else fixture["manifest_sha256"],
             "directories_sha256": "" if mode == 1 else fixture["directories_sha256"],
             "importer_report_hex": "" if mode == 1 else imported.hex(), "output_bytes": len(output), "output_hex": output.hex()}
        receipt = {"status": "PREPARED_COMPONENT_QA", "run_id": "a" * 32, "architecture": "aarch64", "node_version": c.NODE_VERSION,
                   "node_sha256": "b" * 64, "native_sha256": "c" * 64, "input_sha256": c.sha256(blob), "fault_mode": mode}
        result = {"status": "CANDIDATE_FAULT_QA" if mode else "CANDIDATE_COMPONENT_QA", "run_id": receipt["run_id"],
                  "fault_mode": mode, "verification_requires": "controller_exit_zero_and_separate_acceptance_record",
                  "node_version": c.NODE_VERSION, "platform": "linux-arm64", "production_admission": False, "release_gate_qualified": False,
                  "host_cleanup_confirmed": True, "systemd_run_child_reap_confirmed": True, "reasons": [],
                  "native_return_code": 1 if mode else 0, "observer_acknowledged": not bool(mode),
                  "native_argv_sha256": "d" * 64,
                  "systemd_unit_observed_before_fault": bool(mode), "systemd_unit_observed_before_ack": not bool(mode),
                  "input_manifest_sha256": fixture["manifest_sha256"], "directories_sha256": fixture["directories_sha256"],
                  "tap_inventory": {"status": "NOT_RUN_EXPECTED_IMPORT_STALL", "tests": 0, "pass": 0} if mode == 1 else
                                   {**c.tap_inventory(output), "status": "PASS"}}
        result.update({key: receipt[key] for key in ("node_sha256", "native_sha256", "input_sha256")})
        for name, key in (("importer.js", "importer_sha256"), ("authority.js", "authority_sha256")):
            result[key] = c.sha256((HERE / name).read_bytes())
        return result, n, receipt

    def run_case(self, mode=0, mutate=None, rc=0, outcome="success", raw_change=None, omit=None):
        result, native, receipt = self.evidence(mode)
        if mutate:
            mutate(result, native, receipt)
        raw = (json.dumps(native) + "\n").encode()
        if raw_change:
            raw = raw_change(raw)
        result["native_proof_sha256"] = c.sha256(raw)
        result["native"] = {key: value for key, value in native.items() if key != "output_hex"}
        result["native"]["worker_output_sha256"] = c.sha256(bytes.fromhex(native["output_hex"]))
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as root:
            directory = Path(root)
            for name, body in (("NATIVE.json", raw), ("RESULT.json", json.dumps(result).encode()),
                               ("prepare-receipt.json", json.dumps(receipt).encode())):
                if name != omit:
                    (directory / name).write_bytes(body)
                    (directory / name).chmod(0o644)
            return a.accepted_record(directory, rc, "a" * 32, "e" * 40, "123", "1", outcome)

    def test_nominal_and_both_fixed_faults_have_distinct_acceptance(self):
        for mode in (0, 1, 2):
            got = self.run_case(mode)
            self.assertEqual(got["status"], "ACCEPTED_FAULT_QA" if mode else "ACCEPTED_COMPONENT_QA", got)
            self.assertFalse(got["production_admission"])
            self.assertFalse(got["release_gate_qualified"])

    def test_failed_cancelled_skipped_or_partial_controller_cannot_pass(self):
        for mode in (0, 1, 2):
            for rc, outcome in ((1, "success"), (0, "failure"), (0, "cancelled"), (0, "skipped")):
                self.assertEqual(self.run_case(mode, rc=rc, outcome=outcome)["status"], "REJECTED")
            self.assertEqual(self.run_case(mode, omit="NATIVE.json")["status"], "REJECTED")

    def test_fault_trigger_wrong_phase_and_late_success_are_rejected(self):
        for mode in (1, 2):
            for key, value in (("fault_reached", False), ("fault_mode", 0), ("status", "WORK_CLOSED"),
                               ("phase", 4), ("stop_reason", 4), ("work_ms", 29999), ("cleanup_ms", 10001),
                               ("proof_emitted_ms", 30000), ("init_wait_status", 0), ("keeper_wait_status", 9)):
                with self.subTest(mode=mode, key=key):
                    got = self.run_case(mode, mutate=lambda r,n,p:n.update({key:value}))
                    self.assertEqual(got["status"], "REJECTED", got)

    def test_missing_cleanup_reap_and_forbidden_observer_success_are_rejected(self):
        for mode in (0, 1, 2):
            for key in ("host_cleanup_confirmed", "systemd_run_child_reap_confirmed"):
                self.assertEqual(self.run_case(mode, mutate=lambda r,n,p:r.update({key:False}))["status"], "REJECTED")
            for key in ("cleanup_confirmed", "cgroup_empty", "output_eof"):
                self.assertEqual(self.run_case(mode, mutate=lambda r,n,p:n.update({key:False}))["status"], "REJECTED")
        for mode in (1, 2):
            self.assertEqual(self.run_case(mode, mutate=lambda r,n,p:r.update(observer_acknowledged=True))["status"], "REJECTED")

    def test_duplicate_native_json_and_nonfinite_values_are_rejected(self):
        self.assertEqual(self.run_case(raw_change=lambda raw: raw.replace(b'{', b'{"status":"FAIL",', 1))["status"], "REJECTED")
        for text in ('{"value":NaN}', '{"nested":{"x":1,"x":2}}'):
            with self.assertRaises(ValueError): c.strict_json(text)

    def test_nominal_deadline_and_truthy_ack_cannot_be_promoted(self):
        for key, value in (("work_ms", 30000), ("work_ms", True), ("cleanup_ms", 10001), ("proof_emitted_ms", 1), ("proof_emitted_ms", 42001)):
            self.assertEqual(self.run_case(mutate=lambda r,n,p:n.update({key:value}))["status"], "REJECTED")
        self.assertEqual(self.run_case(mutate=lambda r,n,p:r.update(observer_acknowledged="true"))["status"], "REJECTED")


if __name__ == "__main__": unittest.main()
