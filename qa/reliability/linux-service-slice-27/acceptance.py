#!/usr/bin/env python3
"""Post-exit acceptance for exact readonly-component or fixed pipe-stall QA.

Never promotes a native FAIL to successful work. ACCEPTED_FAULT_QA means only
the specified failed experiment and its cleanup were independently checked.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re

import controller as c


def accepted_record(directory: Path, controller_exit: int, run_id: str, revision: str,
                    action_run: str, attempt: str, outcome: str = "success") -> dict:
    record = {"schema_version": "knowledge-linux-service-slice-acceptance.v2", "status": "REJECTED",
              "decision_scope": "fixed component QA only; not production, KVE, release, or public RPC qualification",
              "source_revision": revision, "workflow_run_id": action_run, "workflow_run_attempt": attempt,
              "run_id": run_id, "controller_exit": controller_exit, "controller_step_outcome": outcome,
              "reason": "candidate_evidence_contract_failed", "production_admission": False,
              "release_gate_qualified": False, "fault_mode": None, "source_pins": None}
    try:
        c.require(re.fullmatch(r"[a-f0-9]{32}", run_id) is not None and
                  re.fullmatch(r"[a-f0-9]{40}", revision) is not None and
                  re.fullmatch(r"[1-9][0-9]*", action_run) is not None and
                  re.fullmatch(r"[1-9][0-9]*", attempt) is not None,
                  "acceptance_identity", "Invalid run/workflow/source identity")
        raws, values = {}, {}
        for name, limit in (("RESULT.json", 64 * 1024), ("NATIVE.json", c.MAX_NATIVE_JSON), ("prepare-receipt.json", 64 * 1024)):
            st, raw = c.physical_read(directory / name, limit, os.getuid())
            c.require(st.st_mode & 0o7777 == 0o644, "acceptance_file_mode", "Evidence permissions differ")
            raws[name], values[name] = raw, c.strict_json(raw)
        result, native, receipt = (values[name] for name in ("RESULT.json", "NATIVE.json", "prepare-receipt.json"))
        c.require(all(isinstance(value, dict) for value in (result, native, receipt)), "acceptance_shape", "Evidence is not an object")
        for name, key in (("RESULT.json", "result_sha256"), ("NATIVE.json", "native_sha256"), ("prepare-receipt.json", "prepare_receipt_sha256")):
            record[key] = c.sha256(raws[name])
        mode = receipt.get("fault_mode")
        c.require(type(mode) is int and mode in {0, 1, 2} and type(result.get("fault_mode")) is int and result["fault_mode"] == mode,
                  "acceptance_fault_profile", "Evidence has the wrong fixed fault profile")
        record["fault_mode"] = mode
        c.require(set(receipt) == {"status", "run_id", "architecture", "node_version", "node_sha256", "native_sha256", "input_sha256", "fault_mode"} and
                  receipt["status"] == "PREPARED_COMPONENT_QA" and receipt["run_id"] == run_id and
                  receipt["architecture"] in {"aarch64", "x86_64"} and receipt["node_version"] == c.NODE_VERSION,
                  "acceptance_prepare", "Prepare receipt does not match its fixed schema")
        pins = {key: receipt.get(key) for key in ("node_sha256", "native_sha256", "input_sha256")}
        c.require(all(isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value) for value in pins.values()) and
                  all(result.get(key) == value for key, value in pins.items()), "acceptance_pins", "Prepared and result pins differ")
        for name, field in (("importer.js", "importer_sha256"), ("authority.js", "authority_sha256")):
            expected = hashlib.sha256((Path(__file__).parent / name).read_bytes()).hexdigest()
            c.require(result.get(field) == expected, "acceptance_source_pin", "Installed role source differs from current source")
            pins[field] = expected
        c.require(isinstance(result.get("native_argv_sha256"), str) and re.fullmatch(r"[a-f0-9]{64}", result["native_argv_sha256"]),
                  "acceptance_argv_pin", "Native launch profile pin is missing")
        pins["native_argv_sha256"] = result["native_argv_sha256"]
        record["source_pins"] = pins
        blob, fixture = c.make_blob()
        c.require(c.sha256(blob) == receipt["input_sha256"] and
                  result.get("input_manifest_sha256") == fixture["manifest_sha256"] and
                  result.get("directories_sha256") == fixture["directories_sha256"],
                  "acceptance_fixture_pin", "Tested fixture does not bind current generated source")
        c.require(result.get("run_id") == run_id and result.get("node_version") == c.NODE_VERSION and
                  result.get("platform") == ("linux-arm64" if receipt["architecture"] == "aarch64" else "linux-x64") and
                  result.get("production_admission") is False and result.get("release_gate_qualified") is False and
                  result.get("verification_requires") == "controller_exit_zero_and_separate_acceptance_record" and
                  result.get("native_proof_sha256") == record["native_sha256"] and
                  result.get("host_cleanup_confirmed") is True and result.get("reasons") == [] and
                  result.get("systemd_run_child_reap_confirmed") is True,
                  "acceptance_result", "Controller result is incomplete or contradictory")
        c.require(set(native) == {"status", "production_admission", "release_gate_qualified", "observer_ack_required", "component",
                  "cleanup_confirmed", "fault_mode", "fault_reached", "importer_namespace_drained", "importer_detached_writer_ready",
                  "source_readonly", "authority_readback", "phase", "work_ms", "cleanup_ms", "proof_emitted_ms", "stop_reason",
                  "init_wait_status", "keeper_wait_status", "worker_wait_status", "authority_wait_status", "importer_wait_status",
                  "importer_report_hex", "cgroup_empty", "output_eof", "output_bytes", "input_manifest_sha256", "directories_sha256", "output_hex"} and
                  native.get("production_admission") is False and native.get("release_gate_qualified") is False and
                  native.get("component") == "readonly_node_namespace", "acceptance_native_schema", "Native schema is not exact")
        c.require(type(native.get("output_bytes")) is int and 0 <= native["output_bytes"] <= c.MAX_WORKER_OUTPUT and
                  isinstance(native.get("output_hex"), str) and re.fullmatch(r"(?:[0-9a-f]{2})*", native["output_hex"]) is not None and
                  len(native["output_hex"]) == native["output_bytes"] * 2, "acceptance_output", "Worker output is not bounded exact bytes")
        c.require(isinstance(native.get("importer_report_hex"), str) and
                  re.fullmatch(r"(?:[0-9a-f]{2}){0,257}", native["importer_report_hex"]) is not None,
                  "acceptance_importer_report", "Importer diagnostic is not bounded exact bytes")
        output = bytes.fromhex(native["output_hex"])
        expected_summary = {key: value for key, value in native.items() if key != "output_hex"}
        expected_summary["worker_output_sha256"] = c.sha256(output)
        c.require(json.dumps(result.get("native"), sort_keys=True, separators=(",", ":")) ==
                  json.dumps(expected_summary, sort_keys=True, separators=(",", ":")),
                  "acceptance_native_summary", "Controller summary differs from raw native proof")
        tap = c.tap_inventory(output)
        if mode != 1:
            c.require(native["input_manifest_sha256"] == fixture["manifest_sha256"] and
                      native["directories_sha256"] == fixture["directories_sha256"], "acceptance_native_input", "Native input differs")
            expected_import = ("KSM1 chroot_root_not_mountpoint EINVAL\n" +
                f"KSI1 {fixture['manifest_sha256']} {fixture['directories_sha256']} {len(fixture['files'])} " +
                f"{sum(item['bytes'] for item in fixture['files'])}\nKSD1 writable_alias_ready\n").encode("ascii")
            c.require(native["importer_report_hex"] == expected_import.hex() and tap is not None and
                      result.get("tap_inventory") == {**tap, "status": "PASS"}, "acceptance_worker_inventory", "Importer or actual TAP inventory differs")
        else:
            c.require(result.get("tap_inventory") == {"status": "NOT_RUN_EXPECTED_IMPORT_STALL", "tests": 0, "pass": 0},
                      "acceptance_unexpected_worker", "Import-stall experiment claimed a worker run")
        if mode:
            accepted = (result.get("status") == "CANDIDATE_FAULT_QA" and
                result.get("systemd_unit_observed_before_fault") is True and
                c.fault_acceptance(result.get("native_return_code"), native, mode,
                                   result.get("observer_acknowledged"), True, tap))
        else:
            accepted = (result.get("status") == "CANDIDATE_COMPONENT_QA" and
                result.get("systemd_unit_observed_before_ack") is True and
                c.component_acceptance(result.get("native_return_code"), native,
                                       result.get("observer_acknowledged"), True, tap))
        c.require(accepted, "acceptance_native_contract", "Native lifecycle/timing or fixed fault contract failed")
        c.require(type(controller_exit) is int and controller_exit == 0 and outcome == "success",
                  "controller_step_not_successful", "Controller did not finish successfully")
        record["status"] = "ACCEPTED_FAULT_QA" if mode else "ACCEPTED_COMPONENT_QA"
        record["reason"] = None
    except (OSError, ValueError, TypeError, KeyError, c.SliceFailure) as exc:
        record["reason"] = exc.code if isinstance(exc, c.SliceFailure) else "evidence_read_or_parse_failed"
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--public-dir", type=Path, required=True)
    parser.add_argument("--controller-exit", type=int, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--workflow-run-id", required=True)
    parser.add_argument("--workflow-run-attempt", required=True)
    parser.add_argument("--controller-step-outcome", default="success", choices=("success", "failure", "cancelled", "skipped"))
    args = parser.parse_args()
    record = accepted_record(args.public_dir, args.controller_exit, args.run_id, args.source_revision,
                             args.workflow_run_id, args.workflow_run_attempt, args.controller_step_outcome)
    body = (json.dumps(record, sort_keys=True, indent=2) + "\n").encode()
    # An exclusive new acceptance file preserves any earlier terminal decision.
    c.write_new_file(args.public_dir / "ACCEPTANCE.json", body, 0o644)
    print(json.dumps({"status": record["status"], "reason": record["reason"], "fault_mode": record["fault_mode"]}))
    return 0 if record["status"] in {"ACCEPTED_COMPONENT_QA", "ACCEPTED_FAULT_QA"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
