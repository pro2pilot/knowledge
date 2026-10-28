#!/usr/bin/env python3
"""Ordinary-UID physical native service checks through the installed bridge.

This exercises production transport, source import, fresh A, typed nested W,
storage enrollment, cancellation and deadlines. It does not claim the public
KVE final-CAS path; that is qualified by the public integration separately.
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import select
import signal
import struct
import subprocess
import sys
import time

MODES = ["positive", "cancel", "timeout", "cancel_before_permit", "broker_paused_cancel"]


def sha(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def wire(value) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()


def identity(pid):
    body = Path(f"/proc/{pid}/stat").read_text()
    fields = body[body.rfind(")") + 2:].split()
    return {"pid": pid, "state": fields[0], "birth_ticks": fields[19]}


def dead(descriptor):
    poller = select.poll();poller.register(descriptor, select.POLLIN)
    return bool(poller.poll(0))


def systemctl_signal(signame):
    assert signame in {"SIGSTOP", "SIGCONT"}
    subprocess.run(["/usr/bin/sudo", "-n", "/usr/bin/systemctl", "kill", "--kill-whom=main",
                    "--signal=" + signame, "knowledge-linux-native-v1.service"], check=True, timeout=5,
                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={"PATH": "/usr/bin:/bin", "LANG": "C"})


def cancel_with_paused_broker(bridge, opened, storage):
    """Suspend only the fixed native main process, keeping its custody intact."""
    main = subprocess.run(["/usr/bin/systemctl", "show", "--property=MainPID", "--value", "knowledge-linux-native-v1.service"],
                          check=True, timeout=3, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    broker_pid = int(main.stdout)
    assert broker_pid > 1
    before = identity(broker_pid)
    held = {name: os.pidfd_open(pid) for name, pid in {
        "broker": broker_pid, "keeper": opened["keeper_pid"], "init": opened["init_pid"], "storage": storage.pid}.items()}
    paused = False
    try:
        systemctl_signal("SIGSTOP");paused = True
        observed = identity(broker_pid)
        assert observed["birth_ticks"] == before["birth_ticks"] and observed["state"] in {"T", "t"}
        started = time.monotonic_ns()
        bridge.send(4)
        limit = time.monotonic() + 3
        while time.monotonic() < limit and not all(dead(held[name]) for name in ("keeper", "init", "storage")):
            time.sleep(0.01)
        assert all(dead(held[name]) for name in ("keeper", "init", "storage")), "independent native cancellation did not drain while broker stopped"
        during = identity(broker_pid)
        assert during["birth_ticks"] == before["birth_ticks"] and during["state"] in {"T", "t"} and not dead(held["broker"])
        return {"broker": before, "broker_stopped_during_exact_pidfd_exits": True,
                "keeper_pidfd_exit": True, "init_pidfd_exit": True, "storage_pidfd_exit": True,
                "elapsed_ms": round((time.monotonic_ns() - started) / 1_000_000, 3)}
    finally:
        if paused:
            systemctl_signal("SIGCONT")
        for descriptor in held.values():
            os.close(descriptor)


class Bridge:
    def __init__(self, config, mode):
        self.nonce = secrets.token_bytes(32)
        self.deadline = time.monotonic_ns() + (1_500_000_000 if mode == "timeout" else 20_000_000_000)
        self.cleanup_ms = 10000
        self.ordinal = 0
        self.child = subprocess.Popen([config["broker"], "--client"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE, env={"PATH": "/usr/bin:/bin", "LANG": "C"})
        self.pending = bytearray()
        self.events = []
        self.results = []

    def send(self, op, pid=0, body=b""):
        self.ordinal += 1
        header = struct.pack("<IIIIIIQQ32sQ", 0x4B4C5331, 1, op, self.ordinal, len(body), pid,
                             self.deadline, self.cleanup_ms, self.nonce, 0)
        self.child.stdin.write(header + body)
        self.child.stdin.flush()

    def next(self, seconds=15):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            if len(self.pending) >= 16:
                magic, version, kind, size = struct.unpack_from("<IIII", self.pending)
                assert (magic, version) == (0x4B4C4F31, 1) and kind in {1, 2} and size <= 32 * 1024 * 1024
                if len(self.pending) >= 16 + size:
                    body = bytes(self.pending[16:16 + size]);del self.pending[:16 + size]
                    value = json.loads(body) if body else None
                    if kind == 1:
                        self.events.append(value)
                    else:
                        self.results.append(value)
                    return kind, value, body
            readable, _, _ = select.select([self.child.stdout], [], [], min(0.05, max(0, end - time.monotonic())))
            if readable:
                chunk = os.read(self.child.stdout.fileno(), 65536)
                if not chunk:
                    raise AssertionError(f"native bridge EOF: code={self.child.poll()}, stderr={self.child.stderr.read(4096)!r}, events={self.events}")
                self.pending.extend(chunk)
        raise AssertionError(f"native event timeout; events={self.events}")

    def until(self, event):
        for _ in range(64):
            kind, value, body = self.next()
            if kind == 1 and value.get("event") == "denied":
                raise AssertionError(f"native denial: {value}")
            if kind == 1 and value.get("event") == event:
                return value, body
        raise AssertionError("native event count")


def source_for(mode):
    script = """'use strict';
const fs=require('node:fs'),assert=require('node:assert/strict'),cp=require('node:child_process');
assert.ok(process.getuid()>0);assert.equal(process.getuid(),process.geteuid());
assert.throws(()=>fs.writeFileSync('/source/unexpected','x'),e=>['EACCES','EROFS'].includes(e.code));
assert.throws(()=>fs.readdirSync('/state'),e=>e.code==='EACCES');
for(const name of Object.keys(process.env))assert.ok(!name.startsWith('KNOWLEDGE_')&&!name.startsWith('NODE_'));
for(const fd of fs.readdirSync('/proc/self/fd')){try{const link=fs.readlinkSync('/proc/self/fd/'+fd);assert.ok(!link.includes('knowledge-native-source')&&!link.includes('/var/lib/knowledge-linux-native'));}catch(e){if(e.code!=='ENOENT')throw e;}}
"""
    if mode == "positive":
        script += "const p=cp.spawn(process.execPath,['-e',\"setInterval(()=>{},1000)\"],{detached:true,stdio:['ignore','inherit','inherit']});p.unref();console.log(JSON.stringify({native_worker:true,uid:process.getuid(),descendant:p.pid}));\n"
    else:
        script += "console.log('native-work-started');setInterval(()=>{},1000);\n"
    body = script.encode()
    files = [{"path": "native-fixture.js", "bytes": len(body), "mode": 0o644, "sha256": sha(body), "data_base64": base64.b64encode(body).decode()}]
    # Same explicit importer digest grammar; data_base64 is excluded.
    manifest_rows = [{key: row[key] for key in ("bytes", "mode", "path", "sha256")} for row in files]
    manifest = sha(wire(manifest_rows))
    return {"schema_version": "knowledge-linux-service-copy-input.v1", "directories": [], "files": files,
            "manifest_sha256": manifest, "directories_sha256": sha(wire([]))}


def run_mode(config, mode, evidence=None):
    bridge = Bridge(config, mode)
    storage = subprocess.Popen([sys.executable, "-c", "import sys,time;sys.stdin.readline();sys.stdin.readline()"],
                               stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    started = time.monotonic()
    observations = {}
    try:
        bridge.send(1)
        capability, _ = bridge.until("capability")
        assert capability["status"] == "ready" and capability["busy"] is False
        for key in ("installation_id", "host_id", "source_sha256", "runtime_sha256", "node_sha256", "broker_binary_sha256", "trusted_source_manifest_sha256"):
            assert capability[key] == config[key], key
        bridge.send(2, storage.pid)
        registered, _ = bridge.until("writer_registered")
        assert registered["pid"] == storage.pid and registered["registered_before_storage_permit"] is True
        storage.stdin.write(b"permit\n");storage.stdin.flush()
        if mode != "positive":
            os.kill(storage.pid, signal.SIGSTOP)
        source = source_for(mode)
        request = {"repoRoot": "/source", "stateRoot": "/state", "taskId": "AUDIT8-NATIVE", "sessionId": "AUDIT8-LINUX",
                   "tests": [{"argv": ["node", "native-fixture.js"], "cwd": ".", "timeout_ms": 10000}],
                   "sourceFiles": ["native-fixture.js"], "checkedBy": "audit8-native"}
        authority = {"batch_id": "KVB-" + secrets.token_hex(16), "deadline_ns": str(bridge.deadline), "nonce": bridge.nonce.hex(),
                     "public_key": "302a300506032b6570032100" + secrets.token_hex(32), "request": request, "request_sha256": sha(wire(request))}
        bridge.send(3, body=wire({"source": source, "authority": authority}))
        opened, _ = bridge.until("opened")
        assert opened["authority_uid"] != opened["worker_uid"] and opened["work_deadline_ns"] == str(bridge.deadline)
        if mode == "cancel_before_permit":
            bridge.send(4)
        else:
            bridge.send(6)
        if mode in {"cancel", "broker_paused_cancel"}:
            bridge.until("authority_bound")
            time.sleep(0.2)
            if mode == "broker_paused_cancel":
                observations["broker_pause"] = cancel_with_paused_broker(bridge, opened, storage)
            else:
                bridge.send(4)
        terminal, raw = bridge.until("terminal")
        expected = "completed" if mode == "positive" else "timed_out" if mode == "timeout" else "cancelled"
        assert terminal["status"] == expected, terminal
        for key in ("cleanup_confirmed", "init_exit_observed", "init_reaped", "keeper_exited", "output_eof", "cgroup_empty", "journal_closed"):
            assert terminal[key] is True, (key, terminal)
        assert terminal["nonce"] == bridge.nonce.hex()
        assert int(terminal["observed_ns"]) < int(terminal["cleanup_deadline_ns"]) <= bridge.deadline + bridge.cleanup_ms * 1_000_000
        base = dict(terminal);proof = base.pop("proof_sha256")
        assert sha(wire(base)) == proof
        if mode == "cancel_before_permit":
            assert terminal["commands"] == terminal["commands_drained"] == terminal["authority_pid"] == 0
            assert terminal["importer_drained"] is False and terminal["authority_readback"] is False
            assert not any(event["event"] in {"authority_bound", "permitted"} for event in bridge.events)
        if mode == "positive":
            assert terminal["authority_pid"] > 1 and terminal["authority_pidfd_exit_observed"] is True
            assert terminal["commands"] == terminal["commands_drained"] == 1 and terminal["authority_status"] == 0
            kind, result, body = bridge.next()
            assert kind == 2 and result["nonce"] == bridge.nonce.hex() and sha(body) == terminal["result_sha256"]
            record = result["result"][0]["record"]
            assert record["status"] == "pass" and record["exit_code"] == 0
            assert record["runtime_sha256"] == config["node_sha256"] and record["source_snapshot"] == [{"path": "native-fixture.js", "sha256": source["files"][0]["sha256"]}]
            storage.stdin.write(b"finish\n");storage.stdin.flush()
        closed, _ = bridge.until("writer_closed")
        assert closed["pid"] == storage.pid and closed["birth_ticks"] == registered["birth_ticks"] and closed["registration_ordinal"] == registered["ordinal"]
        assert closed["writer_cgroup_empty"] is True and closed["closed_in_budget"] is True
        assert int(closed["observed_ns"]) < int(closed["deadline_ns"]) <= int(terminal["cleanup_deadline_ns"])
        if mode == "timeout":
            # Regression: timeout previously killed stopped S only at cleanup
            # END, so no exact closure could be recorded within that budget.
            assert int(closed["observed_ns"]) - int(terminal["cleanup_started_ns"]) < 5_000_000_000
            observations["timeout_starts_storage_drain"] = True
        storage.wait(timeout=5)
        bridge.child.stdin.close()
        assert bridge.child.wait(timeout=5) == 0
        return {"scenario": mode, "status": "PASS", "elapsed_seconds": round(time.monotonic() - started, 3), "events": bridge.events,
                "result": bridge.results, "storage_exit_code": storage.returncode, "observations": observations}
    except BaseException as error:
        if evidence is not None:
            evidence.append({"scenario": mode, "status": "FAIL", "elapsed_seconds": round(time.monotonic() - started, 3),
                             "events": bridge.events, "result": bridge.results, "observations": observations,
                             "error": {"type": type(error).__name__, "message": str(error)}})
        raise
    finally:
        if storage.poll() is None:
            storage.kill();storage.wait(timeout=5)
        if bridge.child.poll() is None:
            bridge.child.kill();bridge.child.wait(timeout=5)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=Path("/var/lib/knowledge-linux-native-v1/installation.json"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--mode", choices=MODES + ["all"], default="all")
    args = parser.parse_args()
    assert os.getuid() != 0 and os.geteuid() != 0
    config = json.loads(args.config.read_bytes())
    assert config["caller_uid"] == os.getuid()
    results = []
    try:
        for mode in (MODES if args.mode == "all" else [args.mode]):
            results.append(run_mode(config, mode, results))
            time.sleep(0.1)
    finally:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps({"schema_version": "knowledge-linux-native-physical-qa.v1", "status": "PASS" if len(results) == (len(MODES) if args.mode == "all" else 1) and all(item["status"] == "PASS" for item in results) else "FAIL",
                                          "configuration": config, "scenarios": results}, indent=2) + "\n")
    print(json.dumps({"status": "PASS", "scenarios": len(results), "output": str(args.output)}))


if __name__ == "__main__":
    main()
