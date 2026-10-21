#!/usr/bin/env python3
"""Addressed active-state unlink regression for an owned Darwin broker fixture.

The synthetic Node worker emits one marker and remains alive for 60 seconds.
After the marker this controller unlinks one exact owned state file, waits for
the ordinary authority child to exit without making an RPC, then reads the
bounded native status/probe oracle. This is diagnostic evidence only.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import time


MAX_FILE = 4 * 1024 * 1024
MAX_REPLY = 65536
READY_MARKER = b"DARWIN_ACTIVE_STATE_FAULT_WORKER_READY\n"
EXPECTED_PROOF_FIELDS = {
    "schema": "knowledge-darwin-private-ruid-proof.v1",
    "phase": "terminal",
    "terminal_cleanup": True,
    "state": "cleanup_unconfirmed",
    "native_cleanup_facts_confirmed": False,
    "cleanup_confirmed": False,
    "capability_qualified": False,
    "uid_history_tuple_verified": False,
    "admission_closed": True,
}
PROOF_ALLOWLIST = (
    "schema", "phase", "terminal_cleanup", "state", "native_cleanup_facts_confirmed",
    "cleanup_confirmed", "capability_qualified", "uid_history_tuple_verified",
    "attempt_id", "descriptor_sha256", "source_sha256", "host_id", "boot_id", "task_ruid",
    "installation_id", "allocation_seq", "allocation_sha256", "account_policy_id",
    "account_policy_sha256", "admission_closed",
    "spawn_exclusion_acquired", "spawn_intents_resolved", "kernel_membership_method",
    "kernel_membership_zero", "registered_authority_exited", "authority_identity",
    "controller_identity", "controller_excluded_from_boundary", "persistent_broker_excluded_from_boundary",
    "receipt_kind",
    "command_drain_sha256", "cleanup_started_monotonic_ms", "cleanup_deadline_monotonic_ms",
    "cleanup_budget_exceeded", "observed_monotonic_ms",
)
DESCRIPTOR_ALLOWLIST = (
    "attempt_id", "backend", "source_sha256", "broker_binary_sha256", "stub_source_sha256",
    "stub_binary_sha256", "stub_wire_version", "host_id", "boot_id", "task_ruid", "task_gid",
    "installation_id", "allocation_seq", "allocation_sha256", "account_policy_id",
    "account_policy_sha256", "uid_history_header_sha256", "uid_history_source_sha256",
    "profile_sha256", "work_budget_ms", "cleanup_budget_ms",
)
BINDING_FIELDS = (
    "attempt_id", "descriptor_sha256", "source_sha256", "host_id", "boot_id", "task_ruid",
    "installation_id", "allocation_seq", "allocation_sha256", "account_policy_id",
    "account_policy_sha256",
)


def load_module(name, path):
    source = Path(path)
    if source.is_symlink() or not source.is_file():
        raise RuntimeError("required helper is missing or unsafe")
    spec = importlib.util.spec_from_file_location(name, source)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load pure helper module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def load_helpers():
    here = Path(__file__).resolve().parent
    m2 = load_module("knowledge_active_fault_m2", here / "daemon-harness-m2.py")
    uid = load_module("knowledge_active_fault_uid", here / "uid-registry-fault-harness.py")
    return m2, uid


def rpc_observe(helper, binary, sock, request, timeout=3):
    completed = subprocess.run([binary, "--request", "--socket=" + sock],
        input=helper.canonical(request), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=timeout, check=False)
    if not completed.stdout or len(completed.stdout) > MAX_REPLY:
        return {"transport_ok": False, "transport_exit": completed.returncode}
    try:
        reply = json.loads(completed.stdout)
    except (ValueError, TypeError):
        return {"transport_ok": False, "transport_exit": completed.returncode,
                "invalid_json": True}
    return {"transport_ok": True, "transport_exit": completed.returncode, "reply": reply}


def public_rpc(helper, binary, sock, request, timeout=3):
    observed = rpc_observe(helper, binary, sock, request, timeout)
    if not observed.get("transport_ok"):
        return {key: value for key, value in observed.items() if key != "reply"}
    reply = observed["reply"]
    fields = ("ok", "error", "schema", "attempt_id", "descriptor_sha256", "descriptor",
              "source_sha256", "state", "admission_closed", "proof", "registry_healthy",
              "entry_store_loaded", "uid_history", "account_policy", "capability_qualified",
              "qualification_mode", "cleanup_started_monotonic_ms", "cleanup_deadline_monotonic_ms")
    return {"transport_ok": True, "transport_exit": observed["transport_exit"],
            **{key: reply[key] for key in fields if key in reply}}


def select_fields(value, names):
    if not isinstance(value, dict):
        return {}
    return {name: value[name] for name in names if name in value}


def root_command(argv, timeout=5, max_output=MAX_FILE):
    completed = subprocess.run(["/usr/bin/sudo", "-n", *argv], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
    if len(completed.stdout) > max_output or len(completed.stderr) > 8192:
        raise RuntimeError("fixed root helper output exceeded its bound")
    return completed


def read_owned_target(target):
    st = root_command(["/usr/bin/stat", "-f", "%u %g %Lp %l %HT", str(target)], max_output=4096)
    if st.returncode:
        raise RuntimeError("owned state target metadata could not be read")
    try:
        fields = st.stdout.decode("ascii").strip().split()
        uid, gid, mode, links = (int(fields[i], 8 if i == 2 else 10) for i in range(4))
    except (ValueError, IndexError, UnicodeError):
        raise RuntimeError("owned state target metadata response was malformed")
    if (uid != 0 or gid != 0 or mode != 0o600 or links != 1 or
            fields[4:] != ["Regular", "File"]):
        raise RuntimeError("owned state target is not root-owned 0600 single-link regular data")
    content = root_command(["/bin/cat", str(target)])
    if content.returncode or not content.stdout or len(content.stdout) > MAX_FILE:
        raise RuntimeError("owned state bytes could not be captured within the bound")
    return content.stdout


def fixture_target(uid_helpers, sock, fault):
    fixture, registry = uid_helpers.fixture_registry_path(sock)
    target = fixture / "anchors" / "account-policy.json" if fault == "policy-unlink" else registry
    expected_parent = fixture / "anchors" if fault == "policy-unlink" else fixture / "registry"
    if (target.parent != expected_parent or target.is_symlink() or
            target.resolve(strict=True) != target or not target.is_file()):
        raise RuntimeError("fault target is not the exact nonsymlink file in this fixture")
    directory_stat = target.parent.lstat()
    if (target.parent.is_symlink() or not stat.S_ISDIR(directory_stat.st_mode) or
            directory_stat.st_uid != 0 or
            stat.S_IMODE(directory_stat.st_mode) != (0o755 if fault == "policy-unlink" else 0o700)):
        raise RuntimeError("fault target parent failed the literal owned-fixture checks")
    return fixture, target


def validate_target_bytes(fault, raw, binding, descriptor):
    try:
        value = json.loads(raw)
    except (ValueError, TypeError, UnicodeError):
        raise RuntimeError("owned state file is not valid JSON")
    if not isinstance(value, dict):
        raise RuntimeError("owned state file root is not an object")
    if fault == "policy-unlink":
        expected = (value.get("schema") == "knowledge-darwin-account-policy.v1" and
                    value.get("id") == binding["account_policy_id"] and
                    value.get("installation_id") == binding["installation_id"] and
                    hashlib.sha256(raw).hexdigest() == binding["account_policy_sha256"])
        if not expected:
            raise RuntimeError("account-policy file did not match the reservation binding")
    else:
        attempts = value.get("attempts")
        entry = attempts.get(binding["attempt_id"]) if isinstance(attempts, dict) else None
        entry_descriptor = entry.get("descriptor") if isinstance(entry, dict) else None
        if (not isinstance(entry_descriptor, dict) or
                entry.get("descriptor_sha256") != binding["descriptor_sha256"] or
                entry_descriptor.get("source_sha256") != binding["source_sha256"] or
                entry_descriptor.get("task_ruid") != binding["task_ruid"] or
                entry_descriptor.get("allocation_seq") != binding["allocation_seq"] or
                entry_descriptor.get("allocation_sha256") != binding["allocation_sha256"] or
                entry_descriptor.get("account_policy_sha256") != binding["account_policy_sha256"]):
            raise RuntimeError("registry bytes did not contain the exact own reservation binding")


def prepare_authority(helper, uid_helpers, args, probe, prepared, binding):
    binary, sock, node = str(Path(args.binary)), str(Path(args.socket)), str(Path(args.node))
    credentials = {"attempt_id": binding["attempt_id"], "token": prepared["token"]}
    directories = ["fixtures"]
    for directory in directories:
        helper.rpc(binary, sock, {"op": "mkdir", **credentials, "path": directory})
    worker = ("'use strict';\n" +
        "if(process.getuid()!==" + str(binding["task_ruid"]) +
        "||process.geteuid()!==" + str(binding["task_ruid"]) +
        "||process.getgid()!==" + str(binding["task_ruid"]) +
        "||process.getgroups().some(g=>g!==" + str(binding["task_ruid"]) + ")) throw Error('creds');\n" +
        "process.stdout.write('" + READY_MARKER.decode("ascii").strip() + "\\n');\n" +
        "setTimeout(()=>{},60000);\n").encode("utf-8")
    files = [helper.transfer(binary, sock, credentials, "fixtures/main.js", worker)]
    files.sort(key=lambda item: item["path"].encode())
    directories.sort(key=lambda item: item.encode())
    helper.rpc(binary, sock, {"op": "seal", **credentials,
        "manifest_sha256": helper.digest(helper.canonical(files)),
        "directories_sha256": helper.digest(helper.canonical(directories))})
    status = helper.rpc(binary, sock, {"op": "status", "attempt_id": binding["attempt_id"],
        "descriptor_sha256": binding["descriptor_sha256"]})
    if helper.digest(status["sandbox_profile"].encode()) != prepared["descriptor"].get("profile_sha256"):
        raise RuntimeError("sandbox profile digest did not match the descriptor")
    if args.profile_output:
        uid_helpers.save_profile(args.profile_output, status, prepared["descriptor"])
    helper.rpc(binary, sock, {"op": "expect_authority", **credentials})
    raw_outputs = helper.create_raw_outputs(args.evidence_dir)
    config = {"binary": binary, "socket": sock, "node": node, "credentials": credentials,
              "raw_outputs": raw_outputs, "timeout_ms": 60000}
    child = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "--authority-child"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    child.stdin.write(helper.canonical(config) + b"\n")
    child.stdin.flush()
    ready = json.loads(helper.read_line_bounded(child.stdout.fileno(), 60))
    if ready.get("registered") is not True or not helper.valid_identity(ready.get("authority_identity")):
        raise RuntimeError("native authority registration lacked its exact birth identity")
    helper.rpc(binary, sock, {"op": "permit", **credentials})
    child.stdin.write(b"G")
    child.stdin.flush()
    return child, raw_outputs, ready


def authority_child():
    helper, _ = load_helpers()
    config = json.loads(sys.stdin.buffer.readline(MAX_REPLY))
    credentials = config["credentials"]
    registration = helper.rpc(config["binary"], config["socket"],
        {"op": "register_authority", **credentials})
    print(json.dumps({"registered": True, "authority_identity": registration.get("authority")},
                     sort_keys=True), flush=True)
    if sys.stdin.buffer.read(1) != b"G":
        return 2
    result = helper.run_client(config["binary"], config["socket"], {
        "op": "run", **credentials, "argv": [config["node"], "fixtures/main.js"],
        "cwd": ".", "env": {}, "timeout_ms": config["timeout_ms"],
    }, config["raw_outputs"])
    print(json.dumps({"native_run_exit_code": result["native"].get("exit_code"),
                      "native_run_signal": result["native"].get("signal")}, sort_keys=True), flush=True)
    return 0


def collect_marker(m2, child, raw_outputs, timeout=40):
    path = Path(raw_outputs["stdout"])
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if child.poll() is not None:
            raise RuntimeError("authority exited before the worker-ready marker")
        try:
            data = m2.read_bounded(path)
        except (OSError, RuntimeError):
            data = b""
        count = data.count(READY_MARKER)
        if count:
            if count != 1:
                raise RuntimeError("worker-ready marker was not emitted exactly once")
            return data
        time.sleep(0.025)
    raise RuntimeError("private-UID worker-ready marker was not observed within the bound")


def controller(args, helper, uid_helpers):
    if sys.platform != "darwin" or os.getuid() == 0:
        raise RuntimeError("run this controller as an ordinary user on real macOS")
    binary, sock = str(Path(args.binary)), str(Path(args.socket))
    fixture, target = fixture_target(uid_helpers, sock, args.fault)
    probe = helper.rpc(binary, sock, {"op": "probe"})
    if (probe.get("qualification_mode") is not True or probe.get("capability_qualified") is not False or
            probe.get("source_sha256") is None or
            not uid_helpers.validate_probe(probe, helper)):
        raise RuntimeError("initial diagnostic probe did not match the bounded UID/policy contract")
    node_path = Path(args.node).resolve(strict=True)
    if probe.get("allowed_runtimes", {}).get(str(node_path)) != helper.digest(node_path.read_bytes()):
        raise RuntimeError("protected Node runtime pin mismatch")
    started_ns = time.monotonic_ns()
    prepared = helper.rpc(binary, sock, {"op": "prepare", "mode": "isolated_copy",
        "attempt_nonce": secrets.token_hex(32), "work_budget_ms": 120000,
        "cleanup_budget_ms": 10000}, timeout=125)
    try:
        binding = uid_helpers.validate_binding(prepared, probe, helper)
    except Exception:
        try:
            uid_helpers.public_rpc(helper, binary, sock, {"op": "close",
                "attempt_id": prepared.get("attempt_id"),
                "descriptor_sha256": prepared.get("descriptor_sha256"), "cleanup_budget_ms": 10000})
        except Exception:
            pass
        raise
    descriptor = prepared["descriptor"]
    raw_target = read_owned_target(target)
    validate_target_bytes(args.fault, raw_target, binding, descriptor)
    result = {
        "schema": "knowledge-darwin-active-state-fault-smoke.v1",
        "scenario": args.fault,
        "source_sha256": binding["source_sha256"],
        "descriptor_sha256": binding["descriptor_sha256"],
        "descriptor": select_fields(descriptor, DESCRIPTOR_ALLOWLIST),
        "binding": binding,
        "capability_qualified": False,
        "qualification_mode": True,
        "diagnostic_certified": False,
        "full_certified": False,
        "backend_certified": False,
        "product_certified": False,
        "physical_smoke_passed": False,
        "whole_cleanup_claimed": False,
        "uid_wide_signal_claimed": False,
        "target_before_fault": {"bytes": len(raw_target), "sha256": hashlib.sha256(raw_target).hexdigest(),
                                "root_owned_0600_single_link": True},
        "worker_marker": {"value": READY_MARKER.decode("ascii").strip(), "observed": False,
                          "count": 0},
        "times_monotonic_ns": {"controller_started": started_ns},
        "native_helper_pid": None,
        "native_helper_pid_status": "unknown_not_exposed_by_public_status",
    }
    child = None
    raw_outputs = None
    primary = {"passed": False, "reason": "not_started"}
    attempt_ref = {"attempt_id": binding["attempt_id"],
                   "descriptor_sha256": binding["descriptor_sha256"]}
    try:
        child, raw_outputs, ready = prepare_authority(helper, uid_helpers, args, probe, prepared, binding)
        result["times_monotonic_ns"]["authority_registered"] = time.monotonic_ns()
        result["authority_direct_child_pid"] = child.pid
        result["authority_identity"] = ready["authority_identity"]
        result["native_run_client_pid"] = None
        result["native_run_client_pid_status"] = "unknown_parent_pid_not_returned_by_authority_protocol"
        result["worker_stdout_path"] = raw_outputs["stdout"]
        marker_bytes = collect_marker(helper, child, raw_outputs)
        result["worker_marker"] = {"value": READY_MARKER.decode("ascii").strip(),
            "observed": True, "count": marker_bytes.count(READY_MARKER),
            "stdout_bytes_at_observation": len(marker_bytes),
            "stdout_sha256_at_observation": hashlib.sha256(marker_bytes).hexdigest()}
        result["times_monotonic_ns"]["worker_marker_observed"] = time.monotonic_ns()

        # The target was root-verified and bound before worker start. From this
        # marker onward the sole privileged operation before the wait is rm.
        result["times_monotonic_ns"]["fault_command_start"] = time.monotonic_ns()
        mutation = root_command(["/bin/rm", "--", str(target)], timeout=5, max_output=4096)
        result["fault_command_exit"] = mutation.returncode
        result["times_monotonic_ns"]["fault_command_end"] = time.monotonic_ns()
        if mutation.returncode != 0:
            raise RuntimeError("fixed unlink of the verified own target failed")
        result["fault_target"] = str(target)
        result["times_monotonic_ns"]["authority_wait_start"] = time.monotonic_ns()
        try:
            child.wait(timeout=15)
            authority_waited = True
        except subprocess.TimeoutExpired:
            authority_waited = False
        result["times_monotonic_ns"]["authority_wait_end"] = time.monotonic_ns()
        result["authority_wait"] = {"actual_wait_completed": authority_waited,
            "exit_code": child.returncode, "timed_out_after_seconds": None if authority_waited else 15,
            "direct_child_reaped_by_controller": authority_waited}
        if not authority_waited:
            raise RuntimeError("authority child did not exit within the fixed 15-second post-fault wait")

        # No RPC occurs from fault completion through the bounded authority wait above.
        result["times_monotonic_ns"]["post_wait_status_start"] = time.monotonic_ns()
        status_observed = public_rpc(helper, binary, sock, {"op": "status", **attempt_ref}, timeout=5)
        result["times_monotonic_ns"]["post_wait_status_end"] = time.monotonic_ns()
        result["times_monotonic_ns"]["post_wait_probe_start"] = time.monotonic_ns()
        probe_observed = public_rpc(helper, binary, sock, {"op": "probe"}, timeout=5)
        result["times_monotonic_ns"]["post_wait_probe_end"] = time.monotonic_ns()
        status_descriptor = status_observed.get("descriptor")
        proof = status_observed.get("proof")
        expected_descriptor = select_fields(descriptor, DESCRIPTOR_ALLOWLIST)
        descriptor_binding_ok = (isinstance(status_descriptor, dict) and
            all(status_descriptor.get(key) == descriptor.get(key) for key in BINDING_FIELDS if key in descriptor))
        proof_binding_ok = (isinstance(proof, dict) and
            all(type(proof.get(key)) is type(binding[key]) and proof.get(key) == binding[key]
                for key in BINDING_FIELDS))
        flags_ok = (status_observed.get("capability_qualified") is False and
            probe_observed.get("capability_qualified") is False and
            probe_observed.get("qualification_mode") is True and
            all(result.get(key) is False for key in
                ("diagnostic_certified", "full_certified", "backend_certified", "product_certified")))
        oracle_ok = (status_observed.get("transport_ok") is True and status_observed.get("transport_exit") == 0 and
            status_observed.get("ok") is True and status_observed.get("state") == "cleanup_unconfirmed" and
            status_observed.get("admission_closed") is True and helper.exact_fields(proof, EXPECTED_PROOF_FIELDS) and
            proof_binding_ok and descriptor_binding_ok and flags_ok and
            status_observed.get("attempt_id") == binding["attempt_id"] and
            status_observed.get("descriptor_sha256") == binding["descriptor_sha256"] and
            probe_observed.get("transport_ok") is True and probe_observed.get("transport_exit") == 0 and
            probe_observed.get("source_sha256") == binding["source_sha256"])
        if isinstance(proof, dict) and any("ack" in key.lower() for key in proof):
            oracle_ok = False
        if isinstance(proof, dict) and uid_helpers.contains_private_key_name(proof):
            oracle_ok = False
        result["post_wait_status"] = {key: status_observed.get(key) for key in
            ("transport_ok", "transport_exit", "ok", "attempt_id", "descriptor_sha256", "state",
             "admission_closed", "capability_qualified", "cleanup_started_monotonic_ms",
             "cleanup_deadline_monotonic_ms") if key in status_observed}
        result["post_wait_probe"] = {key: probe_observed.get(key) for key in
            ("transport_ok", "transport_exit", "ok", "source_sha256", "capability_qualified",
             "qualification_mode", "registry_healthy", "entry_store_loaded") if key in probe_observed}
        result["native_proof"] = select_fields(proof, PROOF_ALLOWLIST)
        result["descriptor_binding_exact"] = descriptor_binding_ok
        result["proof_binding_exact"] = proof_binding_ok
        result["all_diagnostic_and_certification_flags_false"] = flags_ok
        result["immutable_primary_observation"] = {"oracle_passed": oracle_ok,
            "authority_wait_completed": authority_waited,
            "authority_exit_code": child.returncode,
            "post_wait_state": status_observed.get("state"),
            "admission_closed": status_observed.get("admission_closed"),
            "proof_state": proof.get("state") if isinstance(proof, dict) else None,
            "cleanup_confirmed": proof.get("cleanup_confirmed") if isinstance(proof, dict) else None}
        primary = {"passed": oracle_ok, "reason": None if oracle_ok else "active-state oracle mismatch"}
        if oracle_ok:
            result["physical_smoke_passed"] = True
        else:
            raise RuntimeError("post-wait native state did not match the exact unconfirmed-fault oracle")
    except Exception as error:
        result["error_reason"] = str(error)[:512] if isinstance(error, RuntimeError) else type(error).__name__
        primary = {"passed": False, "reason": result["error_reason"]}
    finally:
        if child is not None and child.poll() is None:
            result.setdefault("authority_wait", {"actual_wait_completed": False,
                "exit_code": None, "direct_child_reaped_by_controller": False})
        # Best-effort exact owned close is explicitly after the immutable primary measurement.
        if child is not None and child.poll() is None:
            result["times_monotonic_ns"]["best_effort_close_start"] = time.monotonic_ns()
            close_result = public_rpc(helper, binary, sock, {"op": "close", **attempt_ref,
                "cleanup_budget_ms": 10000}, timeout=5)
            result["times_monotonic_ns"]["best_effort_close_end"] = time.monotonic_ns()
            result["post_measurement_cleanup"] = {"attempted": True,
                "state": close_result.get("state"), "error": close_result.get("error"),
                "transport_ok": close_result.get("transport_ok")}
            try:
                child.wait(timeout=5)
                result["post_measurement_cleanup"]["authority_exit_code"] = child.returncode
                result["post_measurement_cleanup"]["authority_exit_reaped_by_controller"] = True
            except subprocess.TimeoutExpired:
                result["post_measurement_cleanup"]["authority_exit_reaped_by_controller"] = False
        if child is not None and child.poll() is not None and child.stdout is not None:
            try:
                stdout, stderr = child.communicate(timeout=2)
                result["authority_stdout_sha256"] = hashlib.sha256(stdout).hexdigest()
                result["authority_stderr_sha256"] = hashlib.sha256(stderr).hexdigest()
            except Exception:
                pass
        result["immutable_primary_observation"] = result.get("immutable_primary_observation",
            {"oracle_passed": False, "authority_wait_completed": False,
             "post_wait_state": None, "admission_closed": None, "proof_state": None,
             "cleanup_confirmed": None})
        result["physical_smoke_passed"] = primary["passed"]
        result["diagnostic_certified"] = False
        result["full_certified"] = False
        result["backend_certified"] = False
        result["product_certified"] = False
        if raw_outputs:
            result["worker_output_summary"] = helper.raw_evidence_summary(raw_outputs)
    return result


def main():
    if len(sys.argv) == 2 and sys.argv[1] == "--authority-child":
        return authority_child()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--socket", required=True)
    parser.add_argument("--node", required=True)
    parser.add_argument("--profile-output")
    parser.add_argument("--evidence-dir", required=True)
    parser.add_argument("--fault", choices=("policy-unlink", "registry-unlink"), required=True)
    args = parser.parse_args()
    try:
        helper, uid_helpers = load_helpers()
        result = controller(args, helper, uid_helpers)
        print(json.dumps(result, sort_keys=True, indent=2))
        return 0 if result.get("physical_smoke_passed") is True else 1
    except Exception as error:
        result = {"schema": "knowledge-darwin-active-state-fault-smoke.v1",
            "scenario": args.fault, "physical_smoke_passed": False,
            "capability_qualified": False, "qualification_mode": True,
            "diagnostic_certified": False, "full_certified": False,
            "backend_certified": False, "product_certified": False,
            "whole_cleanup_claimed": False, "uid_wide_signal_claimed": False,
            "error_reason": str(error)[:512] if isinstance(error, RuntimeError) else type(error).__name__}
        print(json.dumps(result, sort_keys=True, indent=2))
        return 1


if __name__ == "__main__":
    sys.exit(main())
