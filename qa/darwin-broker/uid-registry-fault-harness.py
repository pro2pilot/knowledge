#!/usr/bin/env python3
"""Narrow physical persistence-fault probe for the owned Darwin fixture.

This controller prepares one isolated-copy reservation, corrupts or removes
only its own root-protected registry.json, and verifies that the broker leaves
the recorded reservation unconfirmed. Native prepare creates the workspace;
this controller never registers an authority, transfers project data or launches Node.
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


MAX_REPLY = 65536
MAX_REGISTRY = 4 * 1024 * 1024
CORRUPT_SENTINEL = b"KNOWLEDGE_OWNED_CORRUPT_REGISTRY_FIXTURE\n"
EXPECTED_SOURCE_FIELDS = ("attempt_id", "descriptor_sha256", "source_sha256",
                          "host_id", "boot_id", "task_ruid", "installation_id",
                          "allocation_seq", "allocation_sha256")
EXPECTED_STRING_FIELDS = ("attempt_id", "descriptor_sha256", "source_sha256", "host_id",
                          "boot_id", "installation_id", "allocation_seq", "allocation_sha256")


def load_harness_helpers():
    source = Path(__file__).with_name("daemon-harness-m2.py")
    if source.is_symlink() or not source.is_file():
        raise RuntimeError("M2 helper module is missing or unsafe")
    spec = importlib.util.spec_from_file_location("knowledge_daemon_harness_m2", source)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load M2 helper module")
    module = importlib.util.module_from_spec(spec)
    # Registering before exec_module is the normal importlib protocol and keeps
    # the helper's __main__ guard inactive.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    for name in ("canonical", "digest", "exact_fields"):
        if not callable(getattr(module, name, None)):
            raise RuntimeError("M2 helper API is incomplete")
    return module


def rpc_observe_bounded(helper, binary, sock, request, timeout=3):
    """Bound each RPC and retain only protocol fields needed by this probe."""
    completed = subprocess.run(
        [binary, "--request", "--socket=" + sock],
        input=helper.canonical(request), stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=timeout, check=False)
    if len(completed.stdout) > MAX_REPLY or not completed.stdout:
        return {"transport_ok": False, "transport_exit": completed.returncode}
    try:
        reply = json.loads(completed.stdout)
    except (ValueError, TypeError):
        return {"transport_ok": False, "transport_exit": completed.returncode,
                "invalid_json": True}
    if not isinstance(reply, dict):
        return {"transport_ok": False, "transport_exit": completed.returncode,
                "invalid_json": True}
    # Keep the full parsed value private to the caller; any emitted record is
    # built from an explicit public-field allowlist below.
    return {"transport_ok": True, "transport_exit": completed.returncode,
            "reply": reply}


def public_rpc(helper, binary, sock, request, timeout=3):
    result = rpc_observe_bounded(helper, binary, sock, request, timeout)
    if not result.get("transport_ok"):
        return {key: value for key, value in result.items() if key != "reply"}
    reply = result["reply"]
    safe = {"transport_ok": True, "transport_exit": result["transport_exit"]}
    for key in ("ok", "error", "schema", "attempt_id", "descriptor_sha256",
                "descriptor", "source_sha256", "state", "proof", "registry_healthy",
                "entry_store_loaded", "uid_history", "capability_qualified",
                "qualification_mode"):
        if key in reply:
            safe[key] = reply[key]
    return safe


def exact_bool(value, expected):
    return type(value) is bool and value is expected


def contains_private_key_name(value):
    if isinstance(value, dict):
        return any(any(part in str(key).lower().replace("_", "").replace("-", "") for part in
                       ("token", "secret", "password", "credential", "privatekey", "apikey")) or
                   contains_private_key_name(item)
                   for key, item in value.items())
    if isinstance(value, list):
        return any(contains_private_key_name(item) for item in value)
    return False


def fixture_registry_path(socket_value):
    if not isinstance(socket_value, str) or not socket_value.startswith("/private/tmp/"):
        raise RuntimeError("socket is outside the required private tmp root")
    if "\x00" in socket_value or "\\" in socket_value:
        raise RuntimeError("socket path contains an invalid character")
    raw = Path(socket_value)
    if not raw.is_absolute() or ".." in raw.parts or raw.name != "broker.sock" or raw.parent.name != "control":
        raise RuntimeError("socket path has an invalid fixture shape")
    fixture = raw.parent.parent
    if re.fullmatch(r"knowledge-launchd-smoke\.[A-Za-z0-9_-]+", fixture.name) is None:
        raise RuntimeError("socket path is not bound to one owned smoke fixture")
    if fixture.parent != Path("/private/tmp"):
        raise RuntimeError("socket path is not an immediate child of the private tmp root")
    try:
        if raw.resolve(strict=True) != raw or fixture.resolve(strict=True) != fixture:
            raise RuntimeError("socket fixture path resolves through an alias")
    except OSError:
        raise RuntimeError("socket fixture path does not exist")
    if raw.is_symlink() or not stat.S_ISSOCK(raw.lstat().st_mode):
        raise RuntimeError("broker socket is not a real nonsymlink socket")

    # /private/tmp is the sole sticky-world-writable ancestor allowed here.
    tmp = Path("/private/tmp")
    tmp_st = tmp.lstat()
    if (tmp.is_symlink() or tmp_st.st_uid != 0 or
            stat.S_IMODE(tmp_st.st_mode) != 0o1777 or not tmp_st.st_mode & stat.S_ISVTX):
        raise RuntimeError("private tmp root failed the literal sticky-root check")
    for directory, expected_mode in ((fixture, 0o711),
                                     (fixture / "control", 0o711),
                                     (fixture / "registry", 0o700)):
        st = directory.lstat()
        if (directory.is_symlink() or not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or
                stat.S_IMODE(st.st_mode) != expected_mode):
            raise RuntimeError("owned fixture directory failed type or protection checks")
    target = fixture / "registry" / "registry.json"
    if target.is_symlink():
        raise RuntimeError("registry target is a symlink")
    return fixture, target


def root_command(argv, *, timeout=5, max_output=MAX_REGISTRY):
    completed = subprocess.run(["/usr/bin/sudo", "-n", *argv],
                               stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, timeout=timeout, check=False)
    if len(completed.stdout) > max_output or len(completed.stderr) > 8192:
        raise RuntimeError("fixed root helper output exceeded its bound")
    return completed


def read_registry_root(target):
    st = root_command(["/usr/bin/stat", "-f", "%u %g %Lp %l %HT", str(target)],
                      max_output=4096)
    if st.returncode != 0:
        raise RuntimeError("registry metadata could not be read")
    try:
        fields = st.stdout.decode("ascii").strip().split()
        uid, gid, mode, links = (int(fields[index], 8 if index == 2 else 10)
                                 for index in range(4))
    except (ValueError, IndexError, UnicodeError):
        raise RuntimeError("registry metadata response was malformed")
    if (uid != 0 or gid != 0 or mode & 0o7777 != 0o600 or mode & 0o7000 or
            links != 1 or fields[4:] != ["Regular", "File"]):
        raise RuntimeError("registry target is not a root-owned 0600 single-link regular file")
    content = root_command(["/bin/cat", str(target)])
    if content.returncode != 0 or not content.stdout or len(content.stdout) > MAX_REGISTRY:
        raise RuntimeError("registry bytes could not be captured within the bound")
    return content.stdout


def write_corrupt_staging(evidence_dir):
    root = Path(evidence_dir)
    if root.is_symlink() or not root.is_dir():
        raise RuntimeError("evidence directory must already exist and be nonsymlink")
    rst = root.stat()
    if rst.st_uid != os.getuid() or stat.S_IMODE(rst.st_mode) & 0o077:
        raise RuntimeError("evidence directory is not private and user-owned")
    path = root / "KNOWLEDGE_OWNED_CORRUPT_REGISTRY_FIXTURE"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(path), flags, 0o600)
    try:
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_nlink != 1 or
                stat.S_IMODE(st.st_mode) != 0o600):
            raise RuntimeError("corrupt-registry staging file failed ownership checks")
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(CORRUPT_SENTINEL)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(fd)
    return path


def save_profile(path_value, status, descriptor):
    profile = status.get("sandbox_profile")
    if not isinstance(profile, str) or "\x00" in profile:
        raise RuntimeError("status did not return a valid exact sandbox profile")
    raw = profile.encode("utf-8")
    if hashlib.sha256(raw).hexdigest() != descriptor.get("profile_sha256"):
        raise RuntimeError("sandbox profile digest did not match the descriptor")
    path = Path(path_value)
    if not path.is_absolute() or path.exists() or path.is_symlink():
        raise RuntimeError("profile output must be a new absolute path")
    parent = path.parent
    if parent.is_symlink() or not parent.is_dir() or parent.stat().st_uid != os.getuid():
        raise RuntimeError("profile output parent is not a user-owned directory")
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        offset = 0
        while offset < len(raw):
            count = os.write(fd, raw[offset:])
            if count <= 0:
                raise RuntimeError('profile evidence write made no progress')
            offset += count
        os.fsync(fd)
    finally:
        os.close(fd)
    actual = path.read_bytes()
    if actual != raw:
        raise RuntimeError('profile evidence did not survive exact readback')
    return hashlib.sha256(actual).hexdigest()


def validate_probe(probe):
    uid_history = probe.get("uid_history")
    return (
        exact_bool(probe.get("ok"), True) and
        exact_bool(probe.get("qualification_mode"), True) and
        exact_bool(probe.get("capability_qualified"), False) and
        exact_bool(probe.get("registry_healthy"), True) and
        exact_bool(probe.get("entry_store_loaded"), True) and
        isinstance(uid_history, dict) and
        exact_bool(uid_history.get("healthy_cached"), True) and
        uid_history.get("health_source") == "disk_refresh_attempt" and
        isinstance(uid_history.get("header_sha256"), str) and
        re.fullmatch(r"[0-9a-f]{64}", uid_history["header_sha256"]) is not None and
        isinstance(uid_history.get("source_sha256"), str) and
        re.fullmatch(r"[0-9a-f]{64}", uid_history["source_sha256"]) is not None and
        isinstance(probe.get("source_sha256"), str) and
        re.fullmatch(r"[0-9a-f]{64}", probe["source_sha256"]) is not None and
        isinstance(probe.get("host_id"), str) and isinstance(probe.get("boot_id"), str))


def validate_binding(prepared, probe):
    descriptor = prepared.get("descriptor")
    if not isinstance(descriptor, dict):
        raise RuntimeError("prepare did not return a public descriptor")
    binding = {
        "attempt_id": prepared.get("attempt_id"),
        "descriptor_sha256": prepared.get("descriptor_sha256"),
        "source_sha256": probe.get("source_sha256"),
        "host_id": descriptor.get("host_id"),
        "boot_id": descriptor.get("boot_id"),
        "task_ruid": descriptor.get("task_ruid"),
        "installation_id": descriptor.get("installation_id"),
        "allocation_seq": descriptor.get("allocation_seq"),
        "allocation_sha256": descriptor.get("allocation_sha256"),
    }
    uid_history = probe.get("uid_history") if isinstance(probe.get("uid_history"), dict) else {}
    if (not all(type(binding[k]) is str for k in EXPECTED_STRING_FIELDS) or
            type(binding["task_ruid"]) is not int or
            re.fullmatch(r"[0-9a-f]{64}", binding["attempt_id"]) is None or
            re.fullmatch(r"[0-9a-f]{64}", binding["descriptor_sha256"]) is None or
            re.fullmatch(r"[0-9a-f]{64}", binding["source_sha256"]) is None or
            re.fullmatch(r"[0-9a-f]{64}", binding["installation_id"]) is None or
            re.fullmatch(r"[1-9][0-9]{0,19}", binding["allocation_seq"]) is None or
            re.fullmatch(r"[0-9a-f]{64}", binding["allocation_sha256"]) is None or
            not (1000000000 <= binding["task_ruid"] < 1900000000) or
            binding["attempt_id"] != descriptor.get("attempt_id") or
            binding["source_sha256"] != descriptor.get("source_sha256") or
            binding["host_id"] != probe.get("host_id") or
            binding["boot_id"] != probe.get("boot_id") or
            descriptor.get("uid_history_header_sha256") != uid_history.get("header_sha256") or
            descriptor.get("uid_history_source_sha256") != uid_history.get("source_sha256") or
            contains_private_key_name(descriptor)):
        raise RuntimeError("prepared descriptor did not match the public probe binding")
    return binding


def binding_matches(proof, binding):
    if not isinstance(proof, dict):
        return False
    return all(type(proof.get(k)) is type(binding[k]) and proof.get(k) == binding[k]
               for k in EXPECTED_SOURCE_FIELDS)


def unconfirmed_proof_binding_matches(proof, binding):
    return (binding_matches(proof, binding) and
            type(proof.get("uid_history_tuple_verified")) is bool and
            proof.get("uid_history_tuple_verified") is False)


def make_staging_cleanup(path):
    if path is None:
        return
    try:
        st = path.lstat()
        if stat.S_ISREG(st.st_mode) and st.st_uid == os.getuid() and st.st_nlink == 1:
            path.unlink()
    except OSError:
        pass


def controller(args, helper):
    if sys.platform != "darwin" or os.getuid() == 0:
        raise RuntimeError("run this controller as an ordinary user on real macOS")
    binary, sock = str(Path(args.binary)), str(Path(args.socket))
    fixture, target = fixture_registry_path(sock)
    probe_reply = helper.rpc(binary, sock, {"op": "probe"}, timeout=3)
    if not validate_probe(probe_reply):
        raise RuntimeError("daemon probe is not healthy in explicit diagnostic mode")
    prepared = helper.rpc(binary, sock, {"op": "prepare", "mode": "isolated_copy",
        "attempt_nonce": secrets.token_hex(32), "work_budget_ms": 120000,
        "cleanup_budget_ms": 10000}, timeout=75)
    attempt_ref = {"attempt_id": prepared["attempt_id"],
                   "descriptor_sha256": prepared["descriptor_sha256"]}
    try:
        binding = validate_binding(prepared, probe_reply)
    except Exception:
        try:
            public_rpc(helper, binary, sock,
                       {"op": "close", **attempt_ref, "cleanup_budget_ms": 10000})
        except Exception:
            pass
        raise
    descriptor = prepared["descriptor"]
    output = {
        "schema": "knowledge-darwin-uid-registry-fault-smoke.v1",
        "scenario": "registry_fault_" + args.fault,
        "source_sha256": binding["source_sha256"],
        "descriptor_sha256": binding["descriptor_sha256"],
        "descriptor": descriptor,
        "capability_qualified": False,
        "node_launched": False,
        "authority_registered": False,
        "workspace_creation": "performed_by_native_prepare",
        "project_data_transferred": False,
        "physical_smoke_passed": False,
        "whole_cleanup_claimed": False,
        "uid_wide_signal_claimed": False,
        "proof_current_persistence_confirmed": False,
    }
    stage = None
    try:
        status = helper.rpc(binary, sock, {"op": "status", **attempt_ref}, timeout=3)
        if (status.get("attempt_id") != binding["attempt_id"] or
                status.get("descriptor_sha256") != binding["descriptor_sha256"] or
                status.get("state") not in ("copying", "reserved")):
            raise RuntimeError("prepared reservation did not appear in its bound status")
        if args.profile_output:
            output["sandbox_profile_sha256"] = save_profile(args.profile_output, status, descriptor)
        original = read_registry_root(target)
        output["registry_before_fault"] = {"bytes": len(original),
                                            "sha256": hashlib.sha256(original).hexdigest(),
                                            "root_owned_0600_single_link": True}
        if args.fault == "unlink":
            mutation = root_command(["/bin/rm", str(target)], max_output=4096)
        else:
            stage = write_corrupt_staging(args.evidence_dir)
            mutation = root_command(["/usr/bin/install", "-o", "0", "-g", "0", "-m", "0600",
                                     str(stage), str(target)], max_output=4096)
        if mutation.returncode != 0:
            raise RuntimeError("fixed registry fault mutation failed")
        if args.fault == "unlink":
            listing = root_command(["/bin/ls", "-A", str(target.parent)], max_output=4096)
            if listing.returncode != 0:
                raise RuntimeError("registry directory could not be checked after unlink")
            remaining_names = listing.stdout.decode("utf-8", errors="strict").splitlines()
            if "registry.json" in remaining_names:
                raise RuntimeError("registry.json reappeared after unlink")
            output["registry_after_fault"] = {"exists": False, "unhealed": True}
        else:
            changed = read_registry_root(target)
            if changed != CORRUPT_SENTINEL:
                raise RuntimeError("registry bytes were not the exact synthetic corruption fixture")
            output["registry_after_fault"] = {"exists": True, "exact_synthetic_corruption": True,
                                              "bytes": len(changed),
                                              "sha256": hashlib.sha256(changed).hexdigest(),
                                              "unhealed": True}

        before_close = public_rpc(helper, binary, sock, {"op": "status", **attempt_ref})
        output["post_fault_status_error"] = before_close.get("error")
        if before_close.get("state") == "cleanup_unconfirmed":
            pass
        # Closing after the durable-write fault may reject immediately. That is
        # expected input to the bounded status observation, not a close success.
        close_observation = public_rpc(helper, binary, sock,
                                       {"op": "close", **attempt_ref,
                                        "cleanup_budget_ms": 10000})
        allowed_close_errors = {"ADMISSION_CLOSE_DURABILITY_FAILED",
                                "CLEANUP_RECEIPT_DURABILITY_UNCONFIRMED",
                                "REGISTRY_DURABILITY_UNCONFIRMED"}
        if (close_observation.get("error") not in allowed_close_errors and
                close_observation.get("state") != "cleanup_unconfirmed" and
                close_observation.get("transport_ok") is not False):
            raise RuntimeError("close observation did not report the expected durability failure")
        output["close_observation"] = {
            "transport_ok": close_observation.get("transport_ok"),
            "ok": close_observation.get("ok"),
            "error": close_observation.get("error"),
            "state": close_observation.get("state"),
        }
        deadline = time.monotonic() + 25
        final_status = None
        while time.monotonic() < deadline:
            observed = rpc_observe_bounded(helper, binary, sock,
                                           {"op": "status", **attempt_ref}, timeout=3)
            if observed.get("transport_ok"):
                candidate = observed["reply"]
                if (observed.get("transport_exit") == 0 and
                        exact_bool(candidate.get("ok"), True) and
                        candidate.get("attempt_id") == binding["attempt_id"] and
                        candidate.get("state") == "cleanup_unconfirmed" and
                        isinstance(candidate.get("proof"), dict)):
                    final_status = candidate
                    break
            time.sleep(0.1)
        if final_status is None:
            raise RuntimeError("bounded status polling did not observe cleanup_unconfirmed")
        proof = final_status["proof"]
        expected = {"schema": "knowledge-darwin-private-ruid-proof.v1",
                    "phase": "terminal", "terminal_cleanup": True,
                    "state": "cleanup_unconfirmed", "native_cleanup_facts_confirmed": False,
                    "cleanup_confirmed": False, "capability_qualified": False,
                    "uid_history_tuple_verified": False}
        if (not unconfirmed_proof_binding_matches(proof, binding) or
                not helper.exact_fields(proof, expected) or
                final_status.get("attempt_id") != binding["attempt_id"] or
                final_status.get("descriptor_sha256") != binding["descriptor_sha256"]):
            raise RuntimeError("unconfirmed proof/status did not retain the exact public reservation binding")
        cleanup_started = proof.get("cleanup_started_monotonic_ms")
        cleanup_deadline = proof.get("cleanup_deadline_monotonic_ms")
        status_started = final_status.get("cleanup_started_monotonic_ms")
        status_deadline = final_status.get("cleanup_deadline_monotonic_ms")
        cleanup_exceeded = proof.get("cleanup_budget_exceeded")
        if (type(cleanup_started) is not int or type(cleanup_deadline) is not int or
                cleanup_started < 0 or cleanup_deadline <= cleanup_started or
                cleanup_deadline - cleanup_started > 10000 or
                type(status_started) is not int or type(status_deadline) is not int or
                (status_started, status_deadline) != (cleanup_started, cleanup_deadline) or
                type(cleanup_exceeded) is not bool):
            raise RuntimeError("unconfirmed proof cleanup epoch did not match successful status")
        if any("ack" in key.lower() for key in proof):
            raise RuntimeError("unconfirmed proof unexpectedly contains acknowledgement data")
        if contains_private_key_name(proof):
            raise RuntimeError("unconfirmed proof contains a private credential field")
        output["native_proof"] = proof
        output["recorded_attempt_remains_observable"] = True
        output["cleanup_unconfirmed_observed"] = True

        contender = public_rpc(helper, binary, sock, {"op": "prepare", "mode": "isolated_copy",
            "attempt_nonce": secrets.token_hex(32), "work_budget_ms": 120000,
            "cleanup_budget_ms": 10000})
        if (contender.get("ok") is not False or contender.get("attempt_id") is not None or
                not isinstance(contender.get("error"), str) or not contender["error"]):
            raise RuntimeError("new reservation was not rejected after registry fault")
        output["observed_resource_reuse_rejected_after_fault"] = True
        output["new_prepare_error"] = contender["error"]

        # The second read proves that no status/close/retry path healed the
        # target. Capture no raw registry bytes in output.
        if args.fault == "unlink":
            listing = root_command(["/bin/ls", "-A", str(target.parent)], max_output=4096)
            if listing.returncode != 0 or "registry.json" in listing.stdout.decode("utf-8", errors="strict").splitlines():
                raise RuntimeError("unlink fault was healed during observation")
            output["registry_still_unhealed_after_observation"] = True
        else:
            final_bytes = read_registry_root(target)
            if final_bytes != CORRUPT_SENTINEL:
                raise RuntimeError("corrupt registry bytes changed during observation")
            output["registry_still_unhealed_after_observation"] = True
        output["physical_smoke_passed"] = True
        return 0, output
    finally:
        make_staging_cleanup(stage)
        if output.get("physical_smoke_passed") is not True:
            # Keep the owned reservation from being stranded on setup errors.
            # The wrapper later verifies fixture teardown independently.
            try:
                public_rpc(helper, binary, sock,
                           {"op": "close", **attempt_ref, "cleanup_budget_ms": 10000})
            except Exception:
                pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--socket", required=True)
    parser.add_argument("--node", required=True)  # Retained for wrapper CLI compatibility; never launched.
    parser.add_argument("--profile-output")
    parser.add_argument("--evidence-dir", required=True)
    parser.add_argument("--fault", choices=("unlink", "corrupt"), required=True)
    args = parser.parse_args()
    try:
        helper = load_harness_helpers()
        code, output = controller(args, helper)
    except Exception as error:
        code = 1
        output = {"schema": "knowledge-darwin-uid-registry-fault-smoke.v1",
                  "scenario": "registry_fault_" + args.fault,
                  "physical_smoke_passed": False,
                  "whole_cleanup_claimed": False,
                  "uid_wide_signal_claimed": False,
                  "proof_current_persistence_confirmed": False,
                  "setup_error": type(error).__name__,
                  "error_reason": str(error)[:512] if isinstance(error, RuntimeError) else type(error).__name__}
    print(json.dumps(output, sort_keys=True, indent=2))
    return code


if __name__ == "__main__":
    sys.exit(main())
