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
import subprocess
import sys


MAX_REPLY = 65536


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def digest(value):
    return hashlib.sha256(value).hexdigest()


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


def run_client(binary, sock, request):
    # fd3 is deliberately separate from workload stdout/stderr. This is an
    # ordinary, single-threaded harness process, never a privileged preexec hook.
    read_fd, write_fd = os.pipe()
    metadata_fd = fcntl.fcntl(read_fd, fcntl.F_DUPFD_CLOEXEC, 20)
    os.close(read_fd)
    os.dup2(write_fd, 3, inheritable=True)
    if write_fd != 3:
        os.close(write_fd)
    process = subprocess.Popen([binary, "--run", "--socket=" + sock],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, pass_fds=(3,))
    os.close(3)
    try:
        stdout, stderr = process.communicate(canonical(request), timeout=40)
        metadata = bytearray()
        while True:
            chunk = os.read(metadata_fd, 4096)
            if not chunk:
                break
            metadata.extend(chunk)
            if len(metadata) > MAX_REPLY:
                raise RuntimeError("native run metadata exceeds bound")
    finally:
        os.close(metadata_fd)
    if process.returncode != 0 or not metadata:
        raise RuntimeError("native run transport failed: " + str(process.returncode))
    return {"native": json.loads(metadata),
            "stdout": stdout[:8192].decode("utf-8", errors="replace"),
            "stderr": stderr[:8192].decode("utf-8", errors="replace")}


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
    })
    print(json.dumps(result, sort_keys=True), flush=True)
    success = result["native"].get("ok") and result["native"].get("exit_code") == 0
    success = success and "DARWIN_NATIVE_PRIVATE_NODE_OK" in result["stdout"]
    return 0 if success else 3


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
    prepared = rpc(binary, sock, {"op": "prepare", "mode": "isolated_copy",
                                 "attempt_nonce": secrets.token_hex(32),
                                 "work_budget_ms": 120000, "cleanup_budget_ms": 10000})
    credentials = {"attempt_id": prepared["attempt_id"], "token": prepared["token"]}
    binding = {"attempt_id": prepared["attempt_id"],
               "descriptor_sha256": prepared["descriptor_sha256"]}
    child = None
    result = {"schema": "knowledge-darwin-native-physical-smoke.v1",
              "source_sha256": probe["source_sha256"],
              "descriptor_sha256": prepared["descriptor_sha256"],
              "descriptor": prepared["descriptor"],
              "capability_qualified": False, "product_certified": False}
    outcome = 1
    try:
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
        config = {"binary": binary, "socket": sock, "node": node, **credentials}
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
        result["authority_result"] = json.loads(stdout[:MAX_REPLY])
        result["authority_stderr"] = stderr[:8192].decode("utf-8", errors="replace")
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
    return controller(parser.parse_args())


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print(json.dumps({"physical_smoke_passed": False, "product_certified": False,
                          "setup_error": str(error)}), flush=True)
        sys.exit(1)
