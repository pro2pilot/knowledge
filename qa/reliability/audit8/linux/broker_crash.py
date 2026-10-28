#!/usr/bin/env python3
"""Disposable last-only broker SIGKILL and durable restart-fence qualification.

Only the fixed systemd unit is signalled/restarted. All Python and project Node
execution use ordinary/private UIDs. Lost broker custody never becomes a forged
terminal receipt: exact retained process exits are independent diagnostics.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import select
import signal
import struct
import subprocess
import sys
import time

from physical_native import Bridge, source_for, wire

UNIT = "knowledge-linux-native-v1.service"


def identity(pid):
    text = Path(f"/proc/{pid}/stat").read_text()
    fields = text[text.rfind(")") + 2:].split()
    uid_line = next(row for row in Path(f"/proc/{pid}/status").read_text().splitlines() if row.startswith("Uid:"))
    uids = [int(value) for value in uid_line.split()[1:]]
    assert len(uids) == 4 and len(set(uids)) == 1
    return {"pid": pid, "state": fields[0], "parent_pid": int(fields[1]), "birth_ticks": fields[19], "uid": uids[0]}


def dead(descriptor):
    poller = select.poll();poller.register(descriptor, select.POLLIN)
    return bool(poller.poll(0))


class Admin:
    def __init__(self, report, deadline):
        self.commands = report["admin_commands"] = []
        self.deadline = deadline

    def run(self, argv, timeout=5):
        if argv[0] == "/usr/bin/systemctl":
            assert argv in [
                ["/usr/bin/systemctl", "kill", "--kill-whom=main", "--signal=SIGKILL", UNIT],
                ["/usr/bin/systemctl", "start", UNIT],
            ]
        else:
            assert argv[0] == "/usr/bin/cat" and len(argv) == 2
            assert re.fullmatch(r"/sys/fs/cgroup/[A-Za-z0-9_.:/-]+/writer-[a-f0-9]{64}-0/cgroup.procs", argv[1])
            assert "/../" not in argv[1] and "/./" not in argv[1]
        remaining = min(timeout, self.deadline - time.monotonic())
        assert remaining > 0
        command = ["/usr/bin/sudo", "-n", "/usr/bin/timeout", "--signal=KILL", str(max(1, int(remaining))), *argv]
        started = time.monotonic()
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=remaining + 1,
                                env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"})
        assert len(result.stdout) + len(result.stderr) <= 65536
        self.commands.append({"argv": command, "exit_code": result.returncode,
                              "elapsed_ms": round((time.monotonic() - started) * 1000, 3),
                              "stdout": result.stdout.decode(errors="replace"), "stderr": result.stderr.decode(errors="replace")})
        assert result.returncode == 0, self.commands[-1]
        return result.stdout


def service_main():
    result = subprocess.run(["/usr/bin/systemctl", "show", "--property=MainPID", "--value", UNIT],
                            check=True, timeout=3, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    pid = int(result.stdout)
    assert pid > 1
    return pid


def envelope(bridge):
    source = source_for("cancel")
    request = {"repoRoot": "/source", "stateRoot": "/state", "taskId": "AUDIT8-BROKER-CRASH", "sessionId": "AUDIT8-LINUX",
               "tests": [{"argv": ["node", "native-fixture.js"], "cwd": ".", "timeout_ms": 10000}],
               "sourceFiles": ["native-fixture.js"], "checkedBy": "audit8-broker-crash"}
    authority = {"batch_id": "KVB-" + secrets.token_hex(16), "deadline_ns": str(bridge.deadline), "nonce": bridge.nonce.hex(),
                 "public_key": "302a300506032b6570032100" + secrets.token_hex(32), "request": request,
                 "request_sha256": hashlib.sha256(wire(request)).hexdigest()}
    return wire({"source": source, "authority": authority})


def children(pid):
    body = Path(f"/proc/{pid}/task/{pid}/children").read_text()
    assert len(body) < 4096
    return [int(value) for value in body.split()]


def run(config, report, deadline):
    admin = Admin(report, deadline)
    bridge = Bridge(config, "positive")
    bridge.deadline = time.monotonic_ns() + 30_000_000_000
    bridge.cleanup_ms = 10000
    storage = subprocess.Popen([sys.executable, "-c", "import sys;sys.stdin.readline();sys.stdin.readline()"],
                               stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    held = {}
    identities = report["retained_identities"] = {}
    observer = None

    def retain(name, pid, expected_uid=None, expected_parent=None):
        descriptor = os.pidfd_open(pid)
        observed = identity(pid)
        assert not dead(descriptor)
        if expected_uid is not None:
            original_birth = observed["birth_ticks"]
            role_end = min(time.monotonic() + 2, deadline)
            # authority_bound is deliberately published while the fixed child
            # is still natively gated; observe its actual privilege drop too.
            while observed["uid"] != expected_uid and time.monotonic() < role_end:
                assert not dead(descriptor)
                time.sleep(0.005);observed = identity(pid)
                assert observed["birth_ticks"] == original_birth
            assert observed["uid"] == expected_uid
        if expected_parent is not None:
            assert observed["parent_pid"] == expected_parent
        held[name] = descriptor;identities[name] = observed

    try:
        retain("controller", os.getpid(), os.getuid())
        retain("broker", service_main(), 0, 1)
        retain("client", bridge.child.pid, os.getuid(), os.getpid())
        retain("storage", storage.pid, os.getuid(), os.getpid())
        bridge.send(1);capability, _ = bridge.until("capability")
        assert capability["status"] == "ready" and capability["busy"] is False
        assert capability["broker_binary_sha256"] == config["broker_binary_sha256"]
        bridge.send(2, storage.pid);registered, _ = bridge.until("writer_registered")
        assert registered["birth_ticks"] == identities["storage"]["birth_ticks"]
        group_row = Path(f"/proc/{storage.pid}/cgroup").read_text().strip()
        assert group_row.startswith("0::/") and "\n" not in group_row
        group = "/sys/fs/cgroup" + group_row[3:]
        assert group.endswith("/writer-" + bridge.nonce.hex() + "-0")
        members = [int(value) for value in admin.run(["/usr/bin/cat", group + "/cgroup.procs"]).split()]
        assert len(members) == 2 and storage.pid in members
        guardian = next(pid for pid in members if pid != storage.pid)
        retain("storage_guardian", guardian, 0, identities["broker"]["pid"])
        storage.stdin.write(b"permit\n");storage.stdin.flush()
        os.kill(storage.pid, signal.SIGSTOP)
        stop_end = time.monotonic() + 1
        while identity(storage.pid)["state"] not in {"T", "t"} and time.monotonic() < stop_end:
            time.sleep(0.005)
        assert identity(storage.pid)["state"] in {"T", "t"}
        bridge.send(3, body=envelope(bridge));opened, _ = bridge.until("opened")
        retain("keeper", opened["keeper_pid"], 0, identities["broker"]["pid"])
        retain("init", opened["init_pid"], 0, opened["keeper_pid"])
        bridge.send(6);authority, _ = bridge.until("authority_bound")
        retain("authority", authority["authority_pid"], opened["authority_uid"], opened["init_pid"])
        assert identities["authority"]["birth_ticks"] == authority["authority_birth_ticks"]
        worker_end = min(time.monotonic() + 3, deadline)
        while time.monotonic() < worker_end:
            candidates = [pid for pid in children(opened["init_pid"]) if pid != authority["authority_pid"]]
            if len(candidates) == 1:
                worker_init = candidates[0]
                workers = children(worker_init)
                if len(workers) == 1 and identity(workers[0])["uid"] == opened["worker_uid"]:
                    retain("worker_init", worker_init, 0, opened["init_pid"])
                    retain("worker", workers[0], opened["worker_uid"], worker_init)
                    break
            time.sleep(0.01)
        assert "worker" in held, "actual_worker_not_observed_before_crash"
        report["admission"] = {"capability": capability, "writer": registered, "opened": opened, "authority": authority}
        report["original_deadlines"] = {"work_deadline_ns": str(bridge.deadline), "cleanup_budget_ms": bridge.cleanup_ms,
                                         "original_maximum_ns": str(bridge.deadline + bridge.cleanup_ms * 1_000_000)}
        crash_ns = time.monotonic_ns()
        admin.run(["/usr/bin/systemctl", "kill", "--kill-whom=main", "--signal=SIGKILL", UNIT])
        report["broker_sigkill_sent_ns"] = str(crash_ns)
        drain_end = min(crash_ns + bridge.cleanup_ms * 1_000_000,
                        bridge.deadline + bridge.cleanup_ms * 1_000_000)
        exits = report["pidfd_exit_observations"] = {}
        actors = [name for name in held if name != "controller"]
        while time.monotonic_ns() < drain_end and time.monotonic() < deadline:
            for name in actors:
                if name not in exits and dead(held[name]):
                    exits[name] = str(time.monotonic_ns())
            if len(exits) == len(actors):
                break
            time.sleep(0.005)
        assert len(exits) == len(actors), {"missing_exact_exits": [name for name in actors if name not in exits]}
        assert not dead(held["controller"])
        storage.wait(timeout=2);bridge.child.wait(timeout=2)
        assert storage.returncode in {-signal.SIGKILL, -signal.SIGTERM}
        # Production systemd may send SIGCONT with SIGTERM to a stopped actor.
        # This proves prompt exact production cleanup, not a particular killer.
        assert int(exits["storage"]) - crash_ns < 2_000_000_000
        remaining = bytearray();eof = False
        while time.monotonic_ns() < drain_end and time.monotonic() < deadline:
            readable, _, _ = select.select([bridge.child.stdout], [], [], 0.01)
            if not readable:
                continue
            block = os.read(bridge.child.stdout.fileno(), 65536)
            if not block:
                eof = True;break
            remaining.extend(block)
            assert len(remaining) <= 65536
        assert eof, "client_output_eof_unconfirmed_under_original_cleanup_bound"
        raw = bytes(bridge.pending) + bytes(remaining)
        extra = []
        while raw:
            assert len(raw) >= 16
            magic, version, kind, size = struct.unpack_from("<IIII", raw)
            assert (magic, version) == (0x4B4C4F31, 1) and kind in {1, 2} and size <= 8192 and len(raw) >= 16 + size
            body = raw[16:16 + size];raw = raw[16 + size:]
            if body:
                extra.append(json.loads(body))
        report["events_before_broker_death"] = bridge.events
        report["events_after_broker_death"] = extra
        assert not any(event.get("event") == "terminal" for event in bridge.events + extra)
        report["creator_reaps"] = {"storage_exit_code": storage.returncode, "client_exit_code": bridge.child.returncode,
                                    "client_output_eof": eof,
                                    "acceptance_released": False, "fabricated_native_closure": False}
        admin.run(["/usr/bin/systemctl", "start", UNIT], timeout=25)
        restarted = identity(service_main())
        assert restarted["uid"] == 0 and (restarted["pid"], restarted["birth_ticks"]) != (identities["broker"]["pid"], identities["broker"]["birth_ticks"])
        observer = Bridge(config, "positive");observer.send(1)
        after, _ = observer.until("capability")
        assert after["status"] == "quarantined" and after["busy"] is False
        for key in ("installation_id", "host_id", "boot_id", "native_source_sha256", "broker_binary_sha256", "trusted_runtime_manifest_sha256"):
            assert after[key] == capability[key]
        assert after["daemon_epoch"] != capability["daemon_epoch"]
        observer.send(3, body=envelope(observer))
        kind, denied, raw_denial = observer.next()
        assert kind == 1 and denied == {"schema_version": "knowledge-linux-native-service.v1", "event": "denied", "status": "rejected", "reason": "native_quarantined"}
        assert not any(event.get("event") in {"opened", "authority_bound", "permitted", "terminal"} for event in observer.events)
        report["restart"] = {"broker": restarted, "capability": after, "same_boot": True,
                             "unresolved_history_fence_retained": True, "open_denial": denied,
                             "denial_raw_sha256": hashlib.sha256(raw_denial).hexdigest()}
        report["status"] = "PASS_BROKER_CRASH_EXACT_DRAIN_RESTART_FENCED"
    finally:
        if observer is not None and observer.child.poll() is None:
            observer.child.kill();observer.child.wait(timeout=3)
        if storage.poll() is None:
            storage.kill();storage.wait(timeout=3)
        if bridge.child.poll() is None:
            bridge.child.kill();bridge.child.wait(timeout=3)
        for descriptor in held.values():
            os.close(descriptor)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=Path("/var/lib/knowledge-linux-native-v1/installation.json"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    assert os.getuid() != 0 and os.geteuid() != 0
    assert os.environ.get("GITHUB_ACTIONS") == "true", "dedicated_disposable_CI_only"
    started = time.monotonic()
    report = {"schema_version": "knowledge-linux-broker-crash-qa.v1", "status": "FAIL", "cohort_seconds": 60,
              "scope": "Exact live native actors and storage custody across broker SIGKILL; same-boot restart refusal. No public ACK claimed.",
              "closure_owner_scope": "native custody plus production systemd control-group cleanup; attribution not isolated",
              "caller_uid": os.getuid()}
    try:
        config = json.loads(args.config.read_bytes())
        assert config["caller_uid"] == os.getuid() and config["broker"] == "/var/lib/knowledge-linux-native-v1/broker"
        run(config, report, started + 60)
        assert time.monotonic() - started < 60, "broker_crash_cohort_deadline"
    except BaseException as error:
        report["status"] = "FAIL";report["error"] = {"type": type(error).__name__, "message": str(error)}
        raise
    finally:
        report["elapsed_seconds"] = round(time.monotonic() - started, 3)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"status": report["status"], "output": str(args.output)}))


if __name__ == "__main__":
    main()
