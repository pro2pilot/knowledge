#!/usr/bin/env python3
"""Ordinary-user physical smoke for the exact installed native broker.

No root Python/JavaScript, implicit installation, original-project access or
certification. An administrator starts the protected native daemon separately.
An explicitly supplied protected native admission probe uses sudo only for
its fixed read-only flock diagnostic in the owned disposable fixture.
The private workload is a fixed synthetic Node script copied through native RPC.
"""
import argparse
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import select
import stat
import subprocess
import sys
import tempfile
import time


MAX_REPLY = 65536
MAX_RUN_FILE = 65536


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def digest(value):
    return hashlib.sha256(value).hexdigest()


def read_bounded(path):
    fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_uid != os.getuid():
            raise RuntimeError("native run evidence changed type or ownership")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(MAX_RUN_FILE + 1)
    finally:
        os.close(fd)
    if len(data) > MAX_RUN_FILE:
        raise RuntimeError("native run evidence exceeded bound; raw file retained")
    return data


def create_raw_outputs(evidence_dir):
    if evidence_dir is None:
        root = Path(tempfile.mkdtemp(prefix="knowledge-darwin-run-evidence."))
    else:
        supplied = Path(evidence_dir)
        if supplied.is_symlink() or not supplied.is_dir():
            raise RuntimeError("evidence directory must already exist and must not be a symlink")
        root = supplied.resolve(strict=True)
    tag = secrets.token_hex(8)
    paths = {key: root / ("native-run-" + tag + "." + suffix + ".raw")
             for key, suffix in (("stdout", "stdout"), ("stderr", "stderr"), ("fd3", "fd3"))}
    for path in paths.values():
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(str(path), flags, 0o600)
        try:
            st = os.fstat(fd)
            if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_uid != os.getuid() or
                    stat.S_IMODE(st.st_mode) & 0o077):
                raise RuntimeError("new native evidence file failed ownership/type checks")
        finally:
            os.close(fd)
    return {key: str(path) for key, path in paths.items()}


def open_precreated_output(path):
    flags = os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_uid != os.getuid() or
                st.st_size != 0 or stat.S_IMODE(st.st_mode) & 0o077):
            raise RuntimeError("precreated native evidence file changed before authority use")
        high = fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 10)
    finally:
        os.close(fd)
    return os.fdopen(high, "wb", closefd=True)


def rpc(binary, sock, request, timeout=75):
    result = subprocess.run([binary, "--request", "--socket=" + sock],
                            input=canonical(request), capture_output=True,
                            timeout=timeout, check=False)
    if len(result.stdout) > MAX_REPLY:
        raise RuntimeError("native response exceeds bound")
    if not result.stdout:
        raise RuntimeError("native transport failed with exit " + str(result.returncode))
    reply = json.loads(result.stdout)
    if result.returncode != 0 or not reply.get("ok"):
        # Deliberately never print request JSON: it may contain the owner token.
        raise RuntimeError("native RPC rejected: " + str(reply.get("error", "unknown")))
    return reply


def rpc_observe(binary, sock, request):
    """Bounded RPC capture for negative schema probes; never returns secrets in output."""
    result = subprocess.run([binary, "--request", "--socket=" + sock],
                            input=canonical(request), capture_output=True,
                            timeout=75, check=False)
    if len(result.stdout) > MAX_REPLY or not result.stdout:
        return {"transport_exit": result.returncode, "transport_ok": False}
    try:
        reply = json.loads(result.stdout)
    except (ValueError, TypeError):
        return {"transport_exit": result.returncode, "transport_ok": False,
                "invalid_json": True}
    # Deliberately whitelist response fields: never serialize a token.
    observed = {"transport_exit": result.returncode, "transport_ok": True,
                "ok": reply.get("ok"), "error": reply.get("error"),
                "schema": reply.get("schema")}
    for name in ("descriptor", "descriptor_sha256", "attempt_id", "state", "proof"):
        if name in reply:
            observed[name] = reply[name]
    return observed


def read_line_bounded(fd, timeout, *, select_fn=None, read_fn=None, clock_fn=None):
    select_fn = select.select if select_fn is None else select_fn
    read_fn = os.read if read_fn is None else read_fn
    clock_fn = time.monotonic if clock_fn is None else clock_fn
    deadline = clock_fn() + timeout
    data = bytearray()
    while True:
        remaining = deadline - clock_fn()
        if remaining <= 0:
            raise RuntimeError("authority response exceeded its bounded wait")
        ready, _, _ = select_fn([fd], [], [], remaining)
        if not ready:
            raise RuntimeError("authority response exceeded its bounded wait")
        chunk = read_fn(fd, min(4096, MAX_REPLY - len(data)))
        if not chunk:
            raise RuntimeError("authority response ended before its newline")
        newline = chunk.find(b"\n")
        if newline >= 0:
            if newline != len(chunk) - 1 or len(data) + len(chunk) >= MAX_REPLY:
                raise RuntimeError("authority response contained trailing data or exceeded its bound")
            data.extend(chunk)
            return bytes(data)
        data.extend(chunk)
        if len(data) >= MAX_REPLY:
            raise RuntimeError("authority response exceeded its bound")


def exact_fields(actual, expected):
    return isinstance(actual, dict) and all(
        type(actual.get(key)) is type(value) and actual.get(key) == value
        for key, value in expected.items())

def valid_identity(identity):
    numeric = ("pid", "start_sec", "start_usec", "ruid", "pidversion")
    strings = ("unique_id", "parent_unique_id")
    return (isinstance(identity, dict) and set(identity) == set(numeric + strings) and
            all(type(identity.get(key)) is int and identity[key] >= 0 for key in numeric) and
            identity["pid"] > 1 and identity["pidversion"] > 0 and
            all(isinstance(identity.get(key), str) and
                re.fullmatch(r"[0-9]+", identity[key]) is not None for key in strings) and
            int(identity["unique_id"]) > 0)


def same_identity(actual, expected):
    return (valid_identity(actual) and valid_identity(expected) and
            exact_fields(actual, expected) and set(actual) == set(expected))


def valid_cleanup_epoch(start, deadline):
    return (type(start) is int and type(deadline) is int and start >= 0 and
            deadline > start and deadline - start <= 10000)


def admission_path_parts(path_value):
    prefix = "/private/tmp/"
    if not isinstance(path_value, str) or not path_value.startswith(prefix):
        raise RuntimeError("admission path is outside the fixed private tmp root")
    parts = path_value[len(prefix):].split("/")
    if (len(parts) != 3 or
            re.fullmatch(r"knowledge-launchd-smoke\.[A-Za-z0-9_-]+", parts[0]) is None or
            parts[1] != "registry" or
            re.fullmatch(r"[a-f0-9]{64}\.admission", parts[2]) is None):
        raise RuntimeError("admission path does not have the exact fixture/registry/file shape")
    return parts[0], parts[2]


def admission_target(socket_value, helper_value, descriptor_id):
    if not isinstance(descriptor_id, str) or not re.fullmatch(r"[a-f0-9]{64}", descriptor_id):
        raise RuntimeError("prepared attempt did not provide a valid admission identifier")
    socket_path = Path(socket_value)
    if not socket_path.is_absolute() or socket_path.is_symlink():
        raise RuntimeError("broker socket path must be absolute and must not be a symlink")
    resolved_socket = socket_path.resolve(strict=True)
    fixture_root = resolved_socket.parent.parent.resolve(strict=True)
    if (resolved_socket.parent.name != "control" or
            fixture_root.parent != Path("/private/tmp") or
            not re.fullmatch(r"knowledge-launchd-smoke\.[A-Za-z0-9_-]+", fixture_root.name)):
        raise RuntimeError("broker socket is outside the expected owned CI fixture")
    admission_path = fixture_root / "registry" / (descriptor_id + ".admission")
    fixture_name, admission_name = admission_path_parts(str(admission_path))
    if fixture_name != fixture_root.name or admission_name != descriptor_id + ".admission":
        raise RuntimeError("admission path decomposition changed its fixture binding")
    helper = Path(helper_value)
    if not helper.is_absolute() or helper.is_symlink():
        raise RuntimeError("admission probe path must be absolute and must not be a symlink")
    helper_stat = helper.stat()
    if (not stat.S_ISREG(helper_stat.st_mode) or helper_stat.st_uid != 0 or
            helper_stat.st_nlink != 1 or helper_stat.st_mode & 0o022 or
            helper_stat.st_mode & 0o111 == 0):
        raise RuntimeError("admission probe is not a protected root-owned executable")
    return helper, fixture_root / "registry" / (descriptor_id + ".admission")


def self_check_admission_path():
    fixture = "knowledge-launchd-smoke.fixture_12-test"
    leaf = "a" * 64 + ".admission"
    path = "/private/tmp/" + fixture + "/registry/" + leaf
    if admission_path_parts(path) != (fixture, leaf):
        raise RuntimeError("valid admission path did not preserve the complete fixture basename")
    for invalid in ("/tmp/" + fixture + "/registry/" + leaf,
                    "/private/tmp/knowledge-launchd-smoke.x/../registry/" + leaf,
                    "/private/tmp/knowledge-launchd-smoke.x/registry/../" + leaf,
                    "/private/tmp/knowledge-launchd-smoke.x/registry/" + "A" * 64 + ".admission"):
        try:
            admission_path_parts(invalid)
        except RuntimeError:
            continue
        raise RuntimeError("unsafe admission path decomposition was accepted")
    return {"passed": True, "fixture_basename": fixture, "leaf_shape_validated": True}


def run_admission_check(helper, admission_path):
    completed = subprocess.run(
        ["/usr/bin/sudo", "-n", str(helper), "--check", str(admission_path)],
        stdin=subprocess.DEVNULL, capture_output=True, timeout=5, check=False)
    if len(completed.stdout) > 4096 or len(completed.stderr) > 4096:
        raise RuntimeError("admission check output exceeded its bound")
    try:
        reply = json.loads(completed.stdout)
    except (ValueError, TypeError):
        raise RuntimeError("admission check returned invalid JSON")
    if (completed.returncode != 0 or not isinstance(reply, dict) or set(reply) != {"ok", "result"} or
            not exact_fields(reply, {"ok": True, "result": "already_held"})):
        raise RuntimeError("admission check did not confirm the existing OFD lock")
    return {"exit_code": completed.returncode, "result": reply["result"],
            "stdout_sha256": digest(completed.stdout), "stderr_sha256": digest(completed.stderr)}


def close_observed_attempt(binary, sock, reply):
    """Close any unexpectedly accepted probe promptly, retaining only public proof."""
    if not reply.get("attempt_id") or not reply.get("descriptor_sha256"):
        return {"closed": False, "reason": "no-bindable-attempt"}
    closed = rpc_observe(binary, sock, {
        "op": "close", "attempt_id": reply["attempt_id"],
        "descriptor_sha256": reply["descriptor_sha256"], "cleanup_budget_ms": 10000})
    proof = closed.get("proof") if isinstance(closed.get("proof"), dict) else {}
    return {"closed": closed.get("ok") is True, "state": closed.get("state"),
            "cleanup_confirmed": proof.get("cleanup_confirmed"),
            "native_cleanup_facts_confirmed": proof.get("native_cleanup_facts_confirmed")}


def timing_contract_probe(binary, sock):
    """Exercise exact timing validation before the ordinary smoke reservation."""
    cases = [
        ("zero_work_budget", {"work_budget_ms": 0, "cleanup_budget_ms": 10000}),
        ("missing_work_budget", {"cleanup_budget_ms": 10000}),
        ("work_budget_max_plus_one", {"work_budget_ms": 60000000001,
                                       "cleanup_budget_ms": 10000}),
        ("cleanup_budget_max_plus_one", {"work_budget_ms": 120000,
                                         "cleanup_budget_ms": 3600001}),
        ("boolean_work_budget", {"work_budget_ms": True,
                                  "cleanup_budget_ms": 10000}),
    ]
    result = {"expected_contract": "exact timing bounds and strict numeric schema",
              "cases": [], "diagnostic_exact_budget": {"supported": False},
              "backend_certified": False, "capability_qualified": False,
              "unsafe_to_continue": False}
    for name, fields in cases:
        nonce = secrets.token_hex(32)
        request = {"op": "prepare", "mode": "isolated_copy", "attempt_nonce": nonce,
                   **fields}
        observed = rpc_observe(binary, sock, request)
        item = {"name": name, "rejected": observed.get("ok") is False,
                "error": observed.get("error"), "transport_ok": observed.get("transport_ok")}
        if observed.get("ok") is True:
            item["unexpected_acceptance"] = True
            item["cleanup"] = close_observed_attempt(binary, sock, observed)
            if item["cleanup"].get("closed") is not True or item["cleanup"].get("state") != "closed":
                result["unsafe_to_continue"] = True
        else:
            lookup = rpc_observe(binary, sock, {"op": "lookup", "attempt_nonce": nonce})
            item["reservation_absent"] = lookup.get("ok") is False and lookup.get("error") == "RESERVATION_UNKNOWN"
            item["lookup_error"] = lookup.get("error")
        item["passed"] = item.get("rejected") is True and item.get("reservation_absent") is True
        result["cases"].append(item)

    nonce = secrets.token_hex(32)
    prepared = rpc_observe(binary, sock, {"op": "prepare", "mode": "isolated_copy",
        "attempt_nonce": nonce, "work_budget_ms": 60000000000,
        "cleanup_budget_ms": 3600000})
    diagnostic = {"accepted": prepared.get("ok") is True,
                  "error": prepared.get("error")}
    descriptor = prepared.get("descriptor") if isinstance(prepared.get("descriptor"), dict) else {}
    budget = descriptor.get("work_budget_ms")
    start = descriptor.get("work_started_monotonic_ms")
    deadline = descriptor.get("work_deadline_ms")
    cleanup_budget = descriptor.get("cleanup_budget_ms")
    status = None
    if prepared.get("ok") is True:
        binding = {"attempt_id": prepared.get("attempt_id"),
                   "descriptor_sha256": prepared.get("descriptor_sha256")}
        status = rpc_observe(binary, sock, {"op": "status", **binding})
        status_descriptor = status.get("descriptor") if isinstance(status.get("descriptor"), dict) else {}
        status_start = status_descriptor.get("work_started_monotonic_ms")
        status_deadline = status_descriptor.get("work_deadline_ms")
        status_delta = (status_deadline - status_start
                        if type(status_start) is int and type(status_deadline) is int else None)
        exact = (budget == 60000000000 and cleanup_budget == 3600000 and
                 type(start) is int and type(deadline) is int and
                 deadline - start == 60000000000 and
                 status.get("ok") is True and
                 status_descriptor.get("work_budget_ms") == 60000000000 and
                 status_descriptor.get("cleanup_budget_ms") == 3600000 and
                 status_delta == 60000000000)
        diagnostic.update({"supported": exact,
                           "descriptor_work_budget_ms": budget,
                           "descriptor_cleanup_budget_ms": cleanup_budget,
                           "deadline_minus_start_ms": deadline - start if type(start) is int and type(deadline) is int else None,
                           "status_matches": status.get("ok") is True and status_descriptor == descriptor})
        diagnostic["cleanup"] = close_observed_attempt(binary, sock, prepared)
        if diagnostic["cleanup"].get("closed") is not True or diagnostic["cleanup"].get("state") != "closed":
            result["unsafe_to_continue"] = True
    result["diagnostic_exact_budget"] = diagnostic
    result["status"] = ("PASS" if all(case["passed"] for case in result["cases"]) and diagnostic.get("supported")
                        else "UNSUPPORTED_OR_REJECTED" if not diagnostic.get("supported")
                        else "TIMING_NEGATIVE_CASE_FAILED")
    return result


def run_client(binary, sock, request, raw_outputs):
    # The controller owns these exclusive files so output survives an authority
    # exit before it can serialize its JSON result back to the controller.
    stdout_file = open_precreated_output(raw_outputs["stdout"])
    stderr_file = open_precreated_output(raw_outputs["stderr"])
    metadata_file = open_precreated_output(raw_outputs["fd3"])
    saved_fd3 = None
    process = None
    timed_out = False
    try:
        try:
            saved_fd3 = os.dup(3)
        except OSError:
            pass
        os.dup2(metadata_file.fileno(), 3, inheritable=True)
        try:
            process = subprocess.Popen([binary, "--run", "--socket=" + sock],
                                       stdin=subprocess.PIPE, stdout=stdout_file,
                                       stderr=stderr_file, pass_fds=(3,))
        finally:
            os.close(3)
            if saved_fd3 is not None:
                os.dup2(saved_fd3, 3, inheritable=True)
                os.close(saved_fd3)
                saved_fd3 = None
        try:
            process.communicate(canonical(request), timeout=40)
        except subprocess.TimeoutExpired:
            timed_out = True
            process.kill()
            process.wait(timeout=5)
    finally:
        for handle in (stdout_file, stderr_file, metadata_file):
            handle.close()
        if saved_fd3 is not None:
            os.close(saved_fd3)
    raw = {key: read_bounded(path) for key, path in raw_outputs.items()}
    if timed_out:
        raise RuntimeError("native run exceeded its bounded wait; raw files retained")
    if process.returncode != 0 or not raw["fd3"]:
        raise RuntimeError("native run transport failed: " + str(process.returncode))
    return {"native": json.loads(raw["fd3"]),
            "stdout": raw["stdout"].decode("utf-8", errors="replace"),
            "stderr": raw["stderr"].decode("utf-8", errors="replace"),
            "native_exit_code": process.returncode,
            "raw_evidence_paths": raw_outputs}


def authority():
    config = json.loads(sys.stdin.buffer.readline(MAX_REPLY))
    binary, sock = config["binary"], config["socket"]
    credentials = {"attempt_id": config["attempt_id"], "token": config["token"]}
    registration = rpc(binary, sock, {"op": "register_authority", **credentials})
    print(json.dumps({"registered": True,
                      "authority_identity": registration.get("authority")}, sort_keys=True), flush=True)
    if sys.stdin.buffer.read(1) != b"G":
        return 2
    result = run_client(binary, sock, {
        "op": "run", **credentials, "argv": [config["node"], "fixtures/main.js"],
        "cwd": ".", "env": {}, "timeout_ms": 20000,
    }, config["raw_outputs"])
    success = result["native"].get("ok") and result["native"].get("exit_code") == 0
    success = success and "DARWIN_NATIVE_PRIVATE_NODE_OK" in result["stdout"]
    if (not success or type(result["native"].get("exit_code")) is not int or
            result["native"].get("exit_code") != 0 or result["native"].get("signal") is not None):
        print(json.dumps({"drainready": False, "node_exit_code": result["native"].get("exit_code")}), flush=True)
        return 3
    if config.get("scenario", "normal") == "interrupt_drain":
        print(json.dumps({"node_completed": True, "node_exit_code": result["native"]["exit_code"],
                          "node_stdout_sha256": digest(result["stdout"].encode()),
                          "node_stderr_sha256": digest(result["stderr"].encode())}, sort_keys=True), flush=True)
        if sys.stdin.buffer.read(1) != b"D":
            return 6
        try:
            drained = rpc(binary, sock, {"op": "drain_commands", **credentials,
                                         "cleanup_budget_ms": 10000})
        except RuntimeError as error:
            detail = str(error)
            code = detail.rsplit(":", 1)[-1].strip() if detail.startswith("native RPC rejected:") else "TRANSPORT_OR_PROTOCOL_FAILURE"
            print(json.dumps({"drain_rejected": True, "error": code}), flush=True)
        else:
            # A completed drain is evidence that cancellation lost the race.
            proof = drained.get("command_drain_proof", {})
            print(json.dumps({"drainready": True, "drain_state": drained.get("state"),
                              "drain_proof": proof}, sort_keys=True), flush=True)
        if sys.stdin.buffer.read(1) != b"C":
            return 7
        return 0
    drained = rpc(binary, sock, {"op": "drain_commands", **credentials,
                                 "cleanup_budget_ms": 10000})
    proof = drained.get("command_drain_proof", {})
    expected = {
        "schema": "knowledge-darwin-command-drain-proof.v1",
        "phase": "commands_drained",
        "terminal_cleanup": False,
        "native_command_drain_facts_confirmed": True,
        "command_drain_confirmed": False,
        "registered_authority_alive": True,
        "kernel_membership_zero": True,
    }
    if drained.get("state") != "commands_drained" or not exact_fields(proof, expected):
        print(json.dumps({"drainready": False, "drain_state": drained.get("state"),
                          "drain_proof": proof}), flush=True)
        return 4
    print(json.dumps({"drainready": True, "node_exit_code": result["native"].get("exit_code"),
                      "node_stdout_sha256": digest(result["stdout"].encode()),
                      "node_stderr_sha256": digest(result["stderr"].encode()),
                      "drain_state": drained["state"], "drain_proof": proof}, sort_keys=True), flush=True)
    # The controller keeps this ordinary authority alive until it sends the
    # terminal close RPC. The broker must then terminate this exact process.
    if sys.stdin.buffer.read(1) != b"C":
        return 5
    return 0


def raw_evidence_summary(paths):
    summary = {}
    for key, name in paths.items():
        path = Path(name)
        try:
            size = path.stat().st_size
            if size > MAX_RUN_FILE:
                summary[key] = {"path": str(path), "bytes": size, "bounded_read": False}
                continue
            data = read_bounded(path)
            item = {"path": str(path), "bytes": len(data), "sha256": digest(data),
                    "bounded_read": True}
            if key in ("stdout", "stderr"):
                item["text"] = data.decode("utf-8", errors="replace")
            summary[key] = item
        except OSError as error:
            summary[key] = {"path": str(path), "read_error": type(error).__name__}
        except RuntimeError:
            summary[key] = {"path": str(path), "bounded_read": False,
                            "read_error": "output changed or exceeded bound while collecting"}
    return summary


def transfer(binary, sock, credentials, path, content, mode=420):
    metadata = {"bytes": len(content), "mode": mode,
                "path": path, "sha256": digest(content)}
    rpc(binary, sock, {"op": "put_begin", **credentials, **metadata})
    for offset in range(0, len(content), 65536):
        rpc(binary, sock, {"op": "put_chunk", **credentials,
                          "path": path, "offset": offset,
                          "data": base64.b64encode(content[offset:offset + 65536]).decode("ascii")})
    rpc(binary, sock, {"op": "put_commit", **credentials,
                      "path": path, "sha256": metadata["sha256"]})
    return metadata


def controller(args):
    if sys.platform != "darwin" or os.getuid() == 0:
        raise RuntimeError("run this harness as an ordinary owner on real macOS")
    binary, sock, node = str(Path(args.binary)), str(Path(args.socket)), str(Path(args.node))
    installed_node_digest = digest(Path(node).read_bytes())
    probe = rpc(binary, sock, {"op": "probe"})
    if not probe.get("qualification_mode") or probe.get("capability_qualified") is not False:
        raise RuntimeError("expected explicit diagnostic daemon with capability_qualified=false")
    if probe.get("allowed_runtimes", {}).get(node) != installed_node_digest:
        raise RuntimeError("protected Node runtime pin mismatch")
    timing_contract = timing_contract_probe(binary, sock)
    if timing_contract.get("unsafe_to_continue"):
        raise RuntimeError("timing-probe attempt could not be closed; regular Node smoke not started")
    timing_cases = timing_contract.get("cases")
    timing_max = timing_contract.get("diagnostic_exact_budget")
    if (timing_contract.get("status") != "PASS" or not isinstance(timing_cases, list) or
            len(timing_cases) != 5 or any(case.get("passed") is not True for case in timing_cases) or
            not isinstance(timing_max, dict) or timing_max.get("supported") is not True or
            timing_max.get("status_matches") is not True or
            not isinstance(timing_max.get("cleanup"), dict) or
            timing_max["cleanup"].get("closed") is not True or
            timing_max["cleanup"].get("state") != "closed"):
        raise RuntimeError("timing contract probes did not all pass; regular Node smoke not started")
    prepared = rpc(binary, sock, {"op": "prepare", "mode": "isolated_copy",
                                 "attempt_nonce": secrets.token_hex(32),
                                 "work_budget_ms": 120000, "cleanup_budget_ms": 10000})
    credentials = {"attempt_id": prepared["attempt_id"], "token": prepared["token"]}
    binding = {"attempt_id": prepared["attempt_id"],
               "descriptor_sha256": prepared["descriptor_sha256"]}
    child = None
    admission_holder = None
    terminal_reply = None
    pending_epoch = None
    pending_observed = False
    interrupt_ready = False
    raw_outputs = None
    result = {"schema": "knowledge-darwin-native-physical-smoke.v1",
              "scenario": args.scenario,
              "source_sha256": probe["source_sha256"],
              "descriptor_sha256": prepared["descriptor_sha256"],
              "descriptor": prepared["descriptor"],
              "capability_qualified": False, "product_certified": False,
              "timing_contract_probe": timing_contract}
    outcome = 1
    primary_pass = False
    drain_proof = None
    cleanup_epoch = None
    proof_binding = None
    registered_authority_identity = None
    try:
        raw_outputs = create_raw_outputs(args.evidence_dir)
        result["native_run_evidence_files"] = raw_outputs
        descriptor = prepared.get("descriptor", {})
        proof_binding = {
            "attempt_id": descriptor.get("attempt_id"),
            "descriptor_sha256": prepared.get("descriptor_sha256"),
            "source_sha256": probe.get("source_sha256"),
            "host_id": descriptor.get("host_id"),
            "boot_id": descriptor.get("boot_id"),
            "task_ruid": descriptor.get("task_ruid"),
        }
        if (not all(type(proof_binding.get(key)) is str for key in
                    ("attempt_id", "descriptor_sha256", "source_sha256", "host_id", "boot_id")) or
                type(proof_binding.get("task_ruid")) is not int or
                proof_binding["attempt_id"] != prepared.get("attempt_id") or
                proof_binding["source_sha256"] != descriptor.get("source_sha256") or
                proof_binding["host_id"] != probe.get("host_id") or
                proof_binding["boot_id"] != probe.get("boot_id")):
            raise RuntimeError("prepared descriptor and broker probe identity pins disagree")
        expected_uid = prepared["descriptor"]["task_ruid"]
        code = ("'use strict'; const fs=require('fs');"
                "if(process.getuid()!==" + str(expected_uid) +
                "||process.geteuid()!==" + str(expected_uid) +
                "||process.getgid()!==" + str(expected_uid) +
                "||process.getgroups().some(g=>g!==" + str(expected_uid) + "))throw Error('creds');"
                "if(fs.readFileSync('payload.bin').length!==70001)throw Error('chunk');"
                "if(fs.readFileSync('empty.txt').length!==0)throw Error('empty');"
                "if(!fs.statSync('empty-dir').isDirectory())throw Error('dir');"
                "fs.writeFileSync('private-output.txt','PRIVATE_UID_WRITE_OK\\n');"
                "process.stdout.write('DARWIN_NATIVE_PRIVATE_NODE_OK\\n');\n").encode()
        directories = sorted(["fixtures", "empty-dir"], key=lambda x: x.encode())
        for directory in directories:
            rpc(binary, sock, {"op": "mkdir", **credentials, "path": directory})
        files = [transfer(binary, sock, credentials, "fixtures/main.js", code),
                 transfer(binary, sock, credentials, "payload.bin", b"x" * 70001),
                 transfer(binary, sock, credentials, "empty.txt", b"")]
        files.sort(key=lambda item: item["path"].encode())
        rpc(binary, sock, {"op": "seal", **credentials,
                          "manifest_sha256": digest(canonical(files)),
                          "directories_sha256": digest(canonical(directories))})
        exact_profile = rpc(binary, sock, {"op": "status", **binding})["sandbox_profile"]
        if digest(exact_profile.encode()) != prepared["descriptor"]["profile_sha256"]:
            raise RuntimeError("actual profile digest mismatch")
        result["profile_sha256"] = digest(exact_profile.encode())
        if args.profile_output:
            Path(args.profile_output).write_bytes(exact_profile.encode())
        rpc(binary, sock, {"op": "expect_authority", **credentials})
        child = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "--authoritychildmode"],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
        config = {"binary": binary, "socket": sock, "node": node,
                  "raw_outputs": raw_outputs, "scenario": args.scenario, **credentials}
        child.stdin.write(canonical(config) + b"\n")
        child.stdin.flush()
        ready = json.loads(read_line_bounded(child.stdout.fileno(), 60))
        if ready.get("registered") is not True:
            raise RuntimeError("authority did not register")
        registered_authority_identity = ready.get("authority_identity")
        if not valid_identity(registered_authority_identity):
            raise RuntimeError("authority registration did not return an exact process birth identity")
        result["registered_authority_identity"] = registered_authority_identity
        rpc(binary, sock, {"op": "permit", **credentials})
        child.stdin.write(b"G")
        child.stdin.flush()
        line = read_line_bounded(child.stdout.fileno(), 60)
        authority_result = json.loads(line)
        if args.scenario == "interrupt_drain":
            if (authority_result.get("node_completed") is not True or
                    type(authority_result.get("node_exit_code")) is not int or
                    authority_result.get("node_exit_code") != 0):
                raise RuntimeError("private Node workload did not complete before drain cancellation")
            if not args.admission_probe:
                raise RuntimeError("interrupt_drain requires the installed root admission probe")
            helper, admission_path = admission_target(
                sock, args.admission_probe, prepared["descriptor"].get("boundary_id"))
            admission_holder = subprocess.Popen(
                ["/usr/bin/sudo", "-n", str(helper), "--hold=1500", str(admission_path)],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            hold_started = json.loads(read_line_bounded(admission_holder.stdout.fileno(), 5))
            if (hold_started.get("ok") is not True or hold_started.get("result") != "hold_started" or
                    type(hold_started.get("pid")) is not int or admission_holder.poll() is not None):
                raise RuntimeError("root admission helper did not confirm a live lock holder")
            result["admission_lock_holder_started"] = {
                "pid": hold_started["pid"],
                "device": hold_started.get("device"),
                "inode": hold_started.get("inode"),
            }
            child.stdin.write(b"D")
            child.stdin.flush()
            status_deadline = time.monotonic() + 5
            observed_status = None
            last_status_error = None
            while time.monotonic() < status_deadline:
                try:
                    remaining = status_deadline - time.monotonic()
                    observed_status = rpc(binary, sock, {"op": "status", **binding},
                                          timeout=max(0.01, min(2.0, remaining)))
                    last_status_error = None
                except (RuntimeError, subprocess.TimeoutExpired) as error:
                    last_status_error = type(error).__name__
                if observed_status and observed_status.get("state") in ("draining_commands", "commands_drained"):
                    break
                time.sleep(0.05)
            if observed_status and observed_status.get("state") == "draining_commands":
                pending_epoch = (observed_status.get("cleanup_started_monotonic_ms"),
                                 observed_status.get("cleanup_deadline_monotonic_ms"))
                pending_observed = (valid_cleanup_epoch(*pending_epoch) and
                                    admission_holder.poll() is None)
            result["pending_drain_observation"] = {
                "state": observed_status.get("state") if observed_status else None,
                "observed": pending_observed,
                "cleanup_epoch": list(pending_epoch) if pending_epoch else None,
                "holder_alive_at_observation": admission_holder.poll() is None,
                "last_status_error": last_status_error,
            }
            if not pending_observed:
                result["scenario_status"] = "NOTPROVEN"
                result["scenario_reason"] = "pending drain was not observed while admission holder remained alive"
            else:
                holder_alive_at_close = admission_holder.poll() is None
                result["pending_drain_observation"]["holder_alive_at_close"] = holder_alive_at_close
                if not holder_alive_at_close:
                    pending_observed = False
                    result["pending_drain_observation"]["observed"] = False
                    result["scenario_status"] = "NOTPROVEN"
                    result["scenario_reason"] = "admission holder exited before terminal cancellation began"
                else:
                    terminal_reply = rpc(binary, sock, {"op": "close", **binding,
                                                        "cleanup_budget_ms": 10000})
                    interrupt_ready = True
            primary_pass = pending_observed
        else:
            if authority_result.get("drainready") is not True:
                raise RuntimeError("authority workload or command drain failed")
        if args.scenario == "interrupt_drain":
            if interrupt_ready:
                result["scenario_status"] = "PENDING_DRAIN_INTERRUPTED"
                result["authority_drain_response"] = "optional; authority may be killed before emitting it"
            result["positive_node_workload"] = True
        else:
            if authority_result.get("drainready") is not True:
                raise RuntimeError("authority workload or command drain failed")
        if args.scenario == "normal":
            drain_proof = authority_result.get("drain_proof", {})
            result["authority_drain_ready"] = {
                "node_exit_code": authority_result.get("node_exit_code"),
                "node_stdout_sha256": authority_result.get("node_stdout_sha256"),
                "node_stderr_sha256": authority_result.get("node_stderr_sha256"),
                "drain_state": authority_result.get("drain_state"),
                "drain_proof": drain_proof,
            }
            cleanup_epoch = (drain_proof.get("cleanup_started_monotonic_ms"),
                             drain_proof.get("cleanup_deadline_monotonic_ms"))
            if child.poll() is not None:
                raise RuntimeError("authority exited before terminal close")
            required_drain = {
                **proof_binding,
                "schema": "knowledge-darwin-command-drain-proof.v1",
                "phase": "commands_drained", "terminal_cleanup": False,
                "native_command_drain_facts_confirmed": True,
                "command_drain_confirmed": False,
                "capability_qualified": False, "admission_closed": True,
                "spawn_exclusion_acquired": True, "spawn_exclusion_held_until_terminal": True,
                "spawn_intents_resolved": True,
                "registered_authority_alive": True, "kernel_membership_zero": True,
            }
            if (authority_result.get("drain_state") != "commands_drained" or
                    not exact_fields(drain_proof, required_drain) or
                    not same_identity(drain_proof.get("authority_identity"),
                                      registered_authority_identity) or
                    not valid_cleanup_epoch(*cleanup_epoch)):
                raise RuntimeError("command-drain proof did not match the diagnostic contract")
            if any("ack" in key.lower() for key in drain_proof):
                raise RuntimeError("command-drain proof unexpectedly contains acknowledgement data")
            status = rpc(binary, sock, {"op": "status", **binding})
            if (status.get("state") != "commands_drained" or status.get("attempt_id") != binding["attempt_id"] or
                    status.get("command_drain_proof") != drain_proof):
                raise RuntimeError("persisted status did not retain the command-drain proof")
            status_epoch = (status.get("cleanup_started_monotonic_ms"),
                            status.get("cleanup_deadline_monotonic_ms"))
            if not all(type(value) is int for value in status_epoch) or status_epoch != cleanup_epoch:
                raise RuntimeError("cleanup epoch changed during command drain")
            contender = rpc_observe(binary, sock, {"op": "prepare", "mode": "isolated_copy",
                                                   "attempt_nonce": secrets.token_hex(32),
                                                   "work_budget_ms": 120000, "cleanup_budget_ms": 10000})
            if contender.get("error") != "ATTEMPT_ACTIVE":
                raise RuntimeError("new prepare was not blocked by the active drained attempt")
            after_permit = rpc_observe(binary, sock, {"op": "permit", **credentials})
            after_mkdir = rpc_observe(binary, sock, {"op": "mkdir", **credentials, "path": "after-drain"})
            if after_permit.get("error") != "ADMISSION_CLOSED" or after_mkdir.get("error") != "ADMISSION_CLOSED":
                raise RuntimeError("post-drain permit or mkdir did not return ADMISSION_CLOSED")
            result["drain_admission_checks"] = {
                "new_prepare_error": contender.get("error"),
                "permit_error": after_permit.get("error"),
                "mkdir_error": after_mkdir.get("error"),
                "cleanup_epoch_unchanged": True,
            }
            if args.admission_probe:
                helper, admission_path = admission_target(
                    sock, args.admission_probe, prepared["descriptor"].get("boundary_id"))
                result["admission_lock_check"] = run_admission_check(helper, admission_path)
            result["positive_node_workload"] = True
            result["acknowledgement_emitted"] = False
            primary_pass = True
    except Exception as error:
        result["error"] = str(error)
    finally:
        try:
            final = terminal_reply or rpc(binary, sock, {"op": "close", **binding, "cleanup_budget_ms": 10000})
            proof = final.get("proof", {})
            result["native_proof"] = proof
            result["close_state"] = final.get("state")
            result["native_cleanup_facts_confirmed"] = proof.get("native_cleanup_facts_confirmed")
            result["kernel_membership_zero"] = proof.get("kernel_membership_zero")
            result["registered_authority_exited"] = proof.get("registered_authority_exited")
            result["production_cleanup_confirmed"] = proof.get("cleanup_confirmed")
            result["terminal_command_drain_sha256"] = proof.get("command_drain_sha256")
            terminal_epoch = (proof.get("cleanup_started_monotonic_ms"),
                              proof.get("cleanup_deadline_monotonic_ms"))
            epoch_valid = all(type(value) is int for value in terminal_epoch)
            result["cleanup_epoch_unchanged_through_terminal"] = (
                cleanup_epoch is not None and epoch_valid and terminal_epoch == cleanup_epoch)
            if proof.get("cleanup_confirmed") is not False:
                raise RuntimeError("unqualified smoke must never report production cleanup confirmation")
            if (not proof_binding or not valid_identity(registered_authority_identity) or
                    not exact_fields(proof, {
                    **proof_binding,
                    "native_cleanup_facts_confirmed": True,
                    "registered_authority_exited": True,
                    "terminal_cleanup": True,
                    "phase": "terminal",
                    "cleanup_confirmed": False,
                    "capability_qualified": False,
                    "kernel_membership_zero": True,
                    "cleanup_budget_exceeded": False,
                    "state": "closed",
                }) or not same_identity(proof.get("authority_identity"),
                                        registered_authority_identity)):
                raise RuntimeError("terminal cleanup proof did not match native diagnostic facts")
            if args.scenario == "normal":
                if (proof.get("command_drain_sha256") != digest(canonical(drain_proof)) or
                        not result["cleanup_epoch_unchanged_through_terminal"]):
                    raise RuntimeError("terminal cleanup proof failed exact drain linkage or native facts")
            else:
                terminal_started, terminal_deadline = terminal_epoch
                pending_started, pending_deadline = pending_epoch or (None, None)
                if (not pending_observed or not epoch_valid or
                        type(pending_started) is not int or type(pending_deadline) is not int or
                        terminal_started != pending_started or terminal_deadline > pending_deadline or
                        terminal_deadline <= terminal_started or terminal_deadline - terminal_started > 10000 or
                        proof.get("command_drain_sha256") is not None or
                        "command_drain_proof" in final):
                    result["scenario_status"] = "NOTPROVEN"
                    raise RuntimeError("pending drain was not interrupted without extending its cleanup epoch")
                result["cleanup_epoch_unchanged_through_terminal"] = terminal_deadline == pending_deadline
                result["terminal_cleanup_deadline_shortened"] = terminal_deadline < pending_deadline
                result["scenario_status"] = "PENDING_DRAIN_INTERRUPTED"
            if child is None:
                raise RuntimeError("authority child was not started")
            if args.scenario == "normal" and child.stdin is not None:
                child.stdin.close()
                child.stdin = None
            elif child.stdin is not None:
                child.stdin.close()
                child.stdin = None
            stdout, stderr = child.communicate(timeout=15)
            result["authority_exit_code"] = child.returncode
            result["authority_stdout_sha256"] = digest(stdout)
            result["authority_stderr_sha256"] = digest(stderr)
            result["authority_stderr"] = stderr[:8192].decode("utf-8", errors="replace")
            result["authority_killed_by_broker"] = child.returncode == -9
            if args.scenario == "interrupt_drain":
                result["drain_interruption_error_observed"] = b"COMMAND_DRAIN_INTERRUPTED_BY_TERMINAL_STOP" in stdout
                result["cleanup_busy_observed"] = b"CLEANUP_BUSY" in stdout or b"CLEANUP_BUSY" in stderr
                reported_drain_errors = []
                for output_line in stdout.splitlines():
                    try:
                        output_record = json.loads(output_line)
                    except (ValueError, TypeError):
                        continue
                    if output_record.get("drain_rejected") is True:
                        reported_drain_errors.append(output_record.get("error"))
                result["authority_drain_error_codes"] = reported_drain_errors
                if any(code != "COMMAND_DRAIN_INTERRUPTED_BY_TERMINAL_STOP"
                       for code in reported_drain_errors):
                    raise RuntimeError("authority observed an unexpected drain interruption error")
                rejected_prefix = b"native RPC rejected:"
                if rejected_prefix in stdout and b"COMMAND_DRAIN_INTERRUPTED_BY_TERMINAL_STOP" not in stdout:
                    raise RuntimeError("authority reported a drain RPC error other than terminal interruption")
            if child.returncode != -9:
                raise RuntimeError("registered authority did not exit from broker SIGKILL")
            if admission_holder is not None:
                holder_stdout, holder_stderr = admission_holder.communicate(timeout=5)
                helper_lines = holder_stdout.splitlines()
                completion = json.loads(helper_lines[-1]) if helper_lines else {}
                helper_ok = (admission_holder.returncode == 0 and
                             completion.get("ok") is True and completion.get("result") == "hold_complete")
                result["admission_lock_holder_lifecycle"] = {
                    "pid": result.get("admission_lock_holder_started", {}).get("pid"),
                    "exit_code": admission_holder.returncode,
                    "reaped": admission_holder.returncode is not None,
                    "hold_complete_observed": helper_ok,
                    "stdout_sha256": digest(holder_stdout),
                    "stderr_sha256": digest(holder_stderr),
                    "stderr": holder_stderr[:8192].decode("utf-8", errors="replace"),
                }
                if not helper_ok:
                    raise RuntimeError("root admission lock holder did not complete and reap successfully")
            if args.scenario == "interrupt_drain":
                if result.get("cleanup_busy_observed"):
                    raise RuntimeError("terminal cleanup was rejected as CLEANUP_BUSY")
                if not interrupt_ready:
                    result["scenario_status"] = "NOTPROVEN"
                    outcome = 1
                else:
                    outcome = 0
            else:
                outcome = 0 if primary_pass else 1
        except Exception as error:
            result["close_error"] = str(error)
            if args.scenario == "interrupt_drain":
                result["scenario_status"] = "NOTPROVEN"
                result["scenario_reason"] = str(error)
                result["cleanup_busy_observed"] = "CLEANUP_BUSY" in str(error)
            outcome = 1
            if child is not None and child.poll() is None:
                # A cleanup retry remains bound to this one attempt.
                try:
                    rpc(binary, sock, {"op": "close", **binding, "cleanup_budget_ms": 10000})
                except Exception as retry_error:
                    result["close_retry_error"] = str(retry_error)
                if child.stdin is not None:
                    child.stdin.close()
                    child.stdin = None
                try:
                    child.wait(timeout=15)
                    result["authority_exit_code_after_retry"] = child.returncode
                except subprocess.TimeoutExpired:
                    result["authority_exit_unconfirmed"] = True
            if child is not None and child.poll() is not None and child.stdout is not None:
                try:
                    stdout, stderr = child.communicate(timeout=5)
                    result.setdefault("authority_stdout_sha256", digest(stdout))
                    result.setdefault("authority_stderr_sha256", digest(stderr))
                    result.setdefault("authority_stderr", stderr[:8192].decode("utf-8", errors="replace"))
                except Exception as collection_error:
                    result["authority_collection_error"] = str(collection_error)
        if admission_holder is not None and admission_holder.poll() is None:
            try:
                holder_stdout, holder_stderr = admission_holder.communicate(timeout=5)
                result["admission_lock_holder_lifecycle"] = {
                    "pid": result.get("admission_lock_holder_started", {}).get("pid"),
                    "exit_code": admission_holder.returncode,
                    "reaped": admission_holder.returncode is not None,
                    "stdout_sha256": digest(holder_stdout),
                    "stderr_sha256": digest(holder_stderr),
                    "stderr": holder_stderr[:8192].decode("utf-8", errors="replace"),
                }
            except subprocess.TimeoutExpired:
                result["admission_lock_holder_lifecycle"] = {
                    "pid": result.get("admission_lock_holder_started", {}).get("pid"),
                    "reaped": False, "exit_unconfirmed": True,
                }
                outcome = 1
        if raw_outputs is not None:
            result["native_run_raw_output_summary"] = raw_evidence_summary(raw_outputs)
    result["physical_smoke_passed"] = outcome == 0
    print(json.dumps(result, sort_keys=True, indent=2))
    return outcome


def main():
    if len(sys.argv) == 2 and sys.argv[1] in ("--authority", "--authoritychildmode"):
        return authority()
    if len(sys.argv) == 2 and sys.argv[1] == "--self-check-admission-path":
        print(json.dumps(self_check_admission_path(), sort_keys=True))
        return 0
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--socket", required=True)
    parser.add_argument("--node", required=True)
    parser.add_argument("--profile-output")
    parser.add_argument("--evidence-dir")
    parser.add_argument("--scenario", choices=("normal", "interrupt_drain"), default="normal")
    parser.add_argument("--admission-probe")
    args = parser.parse_args()
    if args.scenario == "interrupt_drain" and not args.admission_probe:
        parser.error("--admission-probe is required for interrupt_drain")
    return controller(args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print(json.dumps({"physical_smoke_passed": False, "product_certified": False,
                          "setup_error": str(error)}), flush=True)
        sys.exit(1)
