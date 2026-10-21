#!/usr/bin/env python3
"""Ordinary-user physical smoke for the exact installed native broker.

No root Python/JavaScript, implicit installation, sudo, original-project access,
or certification. An administrator starts the protected native daemon separately.
The private workload is a fixed synthetic Node script copied through native RPC.
"""
import argparse
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import subprocess
import sys
import tempfile


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


def rpc(binary, sock, request):
    result = subprocess.run([binary, "--request", "--socket=" + sock],
                            input=canonical(request), capture_output=True,
                            timeout=75, check=False)
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
    rpc(binary, sock, {"op": "register_authority", **credentials})
    print(json.dumps({"registered": True}), flush=True)
    if sys.stdin.buffer.read(1) != b"G":
        return 2
    result = run_client(binary, sock, {
        "op": "run", **credentials, "argv": [config["node"], "fixtures/main.js"],
        "cwd": ".", "env": {}, "timeout_ms": 20000,
    }, config["raw_outputs"])
    print(json.dumps(result, sort_keys=True), flush=True)
    success = result["native"].get("ok") and result["native"].get("exit_code") == 0
    success = success and "DARWIN_NATIVE_PRIVATE_NODE_OK" in result["stdout"]
    return 0 if success else 3


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
    prepared = rpc(binary, sock, {"op": "prepare", "mode": "isolated_copy",
                                 "attempt_nonce": secrets.token_hex(32),
                                 "work_budget_ms": 120000, "cleanup_budget_ms": 10000})
    credentials = {"attempt_id": prepared["attempt_id"], "token": prepared["token"]}
    binding = {"attempt_id": prepared["attempt_id"],
               "descriptor_sha256": prepared["descriptor_sha256"]}
    child = None
    raw_outputs = None
    result = {"schema": "knowledge-darwin-native-physical-smoke.v1",
              "source_sha256": probe["source_sha256"],
              "descriptor_sha256": prepared["descriptor_sha256"],
              "descriptor": prepared["descriptor"],
              "capability_qualified": False, "product_certified": False,
              "timing_contract_probe": timing_contract}
    outcome = 1
    try:
        raw_outputs = create_raw_outputs(args.evidence_dir)
        result["native_run_evidence_files"] = raw_outputs
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
        child = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "--authority"],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
        config = {"binary": binary, "socket": sock, "node": node,
                  "raw_outputs": raw_outputs, **credentials}
        child.stdin.write(canonical(config) + b"\n")
        child.stdin.flush()
        ready = json.loads(child.stdout.readline(MAX_REPLY))
        if ready.get("registered") is not True:
            raise RuntimeError("authority did not register")
        rpc(binary, sock, {"op": "permit", **credentials})
        child.stdin.write(b"G")
        child.stdin.close()
        child.stdin = None
        stdout, stderr = child.communicate(timeout=45)
        result["authority_exit_code"] = child.returncode
        result["authority_stderr"] = stderr[:8192].decode("utf-8", errors="replace")
        result["authority_stderr_sha256"] = digest(stderr)
        result["authority_stdout_sha256"] = digest(stdout)
        result["authority_result"] = json.loads(stdout[:MAX_REPLY])
        if child.returncode:
            raise RuntimeError("positive private Node workload failed")
        result["positive_node_workload"] = True
        outcome = 0
    except Exception as error:
        result["error"] = str(error)
    finally:
        if child is not None and child.poll() is None:
            child.terminate()  # only this harness's exact Popen direct child
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)
        if child is not None and "authority_stderr" not in result:
            try:
                abandoned_stdout, abandoned_stderr = child.communicate(timeout=5)
                result["authority_exit_code"] = child.returncode
                result["authority_abandoned_stdout"] = abandoned_stdout[:8192].decode("utf-8", errors="replace")
                result["authority_stderr"] = abandoned_stderr[:8192].decode("utf-8", errors="replace")
                result["authority_stderr_sha256"] = digest(abandoned_stderr)
            except Exception as error:
                result["authority_collection_error"] = str(error)
        try:
            final = rpc(binary, sock, {"op": "close", **binding, "cleanup_budget_ms": 10000})
            proof = final.get("proof", {})
            result["native_proof"] = proof
            result["close_state"] = final.get("state")
            result["native_cleanup_facts_confirmed"] = proof.get("native_cleanup_facts_confirmed")
            result["kernel_membership_zero"] = proof.get("kernel_membership_zero")
            result["registered_authority_exited"] = proof.get("registered_authority_exited")
            result["production_cleanup_confirmed"] = proof.get("cleanup_confirmed")
            if proof.get("cleanup_confirmed") is not False:
                raise RuntimeError("unqualified smoke must never report production cleanup confirmation")
            if not proof.get("native_cleanup_facts_confirmed"):
                outcome = 1
        except Exception as error:
            result["close_error"] = str(error)
            outcome = 1
        if raw_outputs is not None:
            result["native_run_raw_output_summary"] = raw_evidence_summary(raw_outputs)
    result["physical_smoke_passed"] = outcome == 0
    print(json.dumps(result, sort_keys=True, indent=2))
    return outcome


def main():
    if len(sys.argv) == 2 and sys.argv[1] == "--authority":
        return authority()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--socket", required=True)
    parser.add_argument("--node", required=True)
    parser.add_argument("--profile-output")
    parser.add_argument("--evidence-dir")
    return controller(parser.parse_args())


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print(json.dumps({"physical_smoke_passed": False, "product_certified": False,
                          "setup_error": str(error)}), flush=True)
        sys.exit(1)
