"""Client for the compile-time-only pipeline4 physical QA persistence gate.

This is an orchestration helper, not a native qualification tool. It speaks to
one launchd-activated socket connection per isolated fixture and never prints
or persists protocol payloads.
"""
import json
import argparse
import re
import socket
import struct
import sys

SCHEMA = "knowledge-darwin-qa-persistence-gate.v1"
POINTS = {"history_journal_read", "registry_file_fsync", "registry_fullfsync"}
MAX_FRAME = 512


def _read_exact(stream, count):
    chunks = []
    remaining = count
    while remaining:
        chunk = stream.recv(remaining)
        if not chunk:
            raise RuntimeError("QA gate peer closed before a complete frame")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _send(stream, value):
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if not 0 < len(payload) <= MAX_FRAME:
        raise RuntimeError("QA gate frame outside its fixed bound")
    stream.sendall(struct.pack("!I", len(payload)) + payload)


def _receive(stream):
    (size,) = struct.unpack("!I", _read_exact(stream, 4))
    if not 0 < size <= MAX_FRAME:
        raise RuntimeError("QA gate peer sent an invalid frame length")
    value = json.loads(_read_exact(stream, size).decode("utf-8"))
    if not isinstance(value, dict) or value.get("schema") != SCHEMA:
        raise RuntimeError("QA gate peer sent an unexpected typed message")
    return value


def persistence_gate(socket_path, run_id, point, expected_qa_build_id,
                     observe_while_pending):
    """Arm one point, observe exact scenario state while pending, then release.

    `observe_while_pending` runs only after the native ENTERED event and before
    RELEASE. Its own failure is re-raised after releasing the gate so the
    fixture can complete the actual persistence call and be shut down safely.
    """
    if (point not in POINTS or not isinstance(run_id, str) or
            not re.fullmatch(r"[a-f0-9]{64}", run_id) or
            not isinstance(expected_qa_build_id, str) or
            not re.fullmatch(r"[a-f0-9]{64}", expected_qa_build_id)):
        raise ValueError("invalid pinned QA gate point or run id")
    arm = {"schema": SCHEMA, "op": "arm", "run_id": run_id,
           "point": point, "occurrence": 1}
    release = {"schema": SCHEMA, "op": "release", "run_id": run_id,
               "point": point, "ordinal": 1}
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        # External watchdog; the native QA hold intentionally has no timeout.
        # Closing on watchdog expiry is a stop-latching failure, never a PASS.
        stream.settimeout(60)
        stream.connect(socket_path)
        _send(stream, arm)
        entered = _receive(stream)
        if (set(entered) != {"schema", "op", "run_id", "point", "ordinal",
                             "broker_pid", "qa_build_id", "persistence_gate"} or
                entered.get("op") != "entered" or entered.get("run_id") != run_id or
                entered.get("point") != point or entered.get("ordinal") != 1 or
                type(entered.get("broker_pid")) is not int or entered["broker_pid"] <= 0 or
                entered.get("qa_build_id") != expected_qa_build_id or
                entered.get("persistence_gate") is not True):
            raise RuntimeError("native QA gate ENTERED observation did not match its contract")
        callback_error = None
        try:
            observe_while_pending(entered)
        except BaseException as error:
            callback_error = error
        _send(stream, release)
        completed = _receive(stream)
        if (set(completed) != {"schema", "op", "run_id", "point", "ordinal",
                               "result_ok", "errno"} or
                completed.get("op") != "completed" or completed.get("run_id") != run_id or
                completed.get("point") != point or completed.get("ordinal") != 1 or
                type(completed.get("result_ok")) is not bool or
                type(completed.get("errno")) is not int):
            raise RuntimeError("native QA gate COMPLETED observation did not match its contract")
        if callback_error is not None:
            raise callback_error
        return {"entered": True, "completed": True,
                "persistence_result_ok": completed["result_ok"],
                "persistence_errno": completed["errno"],
                "gate_kind": "compile-time QA boundary hold; real persistence call follows release"}


def _root_gate_client(socket_path, run_id, point, build_id):
    """Root-only socket peer; the parent keeps policy observations unprivileged."""
    arm = {"schema": SCHEMA, "op": "arm", "run_id": run_id,
           "point": point, "occurrence": 1}
    release = {"schema": SCHEMA, "op": "release", "run_id": run_id,
               "point": point, "ordinal": 1}
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.settimeout(90)
        stream.connect(socket_path)
        _send(stream, arm)
        entered = _receive(stream)
        if (set(entered) != {"schema", "op", "run_id", "point", "ordinal",
                             "broker_pid", "qa_build_id", "persistence_gate"} or
                entered.get("op") != "entered" or entered.get("run_id") != run_id or
                entered.get("point") != point or entered.get("ordinal") != 1 or
                type(entered.get("broker_pid")) is not int or entered["broker_pid"] <= 0 or
                entered.get("qa_build_id") != build_id or entered.get("persistence_gate") is not True):
            raise RuntimeError("native QA gate ENTERED observation did not match its contract")
        sys.stdout.write(json.dumps({"op": "entered", "broker_pid": entered["broker_pid"]},
                                    separators=(",", ":")) + "\n")
        sys.stdout.flush()
        control = sys.stdin.readline(128)
        if control != '{"op":"release"}\n':
            raise RuntimeError("QA gate controller did not authorize release")
        _send(stream, release)
        completed = _receive(stream)
        if (set(completed) != {"schema", "op", "run_id", "point", "ordinal",
                               "result_ok", "errno"} or
                completed.get("op") != "completed" or completed.get("run_id") != run_id or
                completed.get("point") != point or completed.get("ordinal") != 1 or
                type(completed.get("result_ok")) is not bool or
                type(completed.get("errno")) is not int):
            raise RuntimeError("native QA gate COMPLETED observation did not match its contract")
        sys.stdout.write(json.dumps({"op": "completed", "result_ok": completed["result_ok"],
                                     "errno": completed["errno"]}, separators=(",", ":")) + "\n")
        sys.stdout.flush()


def persistence_gate_as_root(socket_path, run_id, point, expected_qa_build_id,
                             observe_while_pending, helper_path):
    """Run the socket peer as root while keeping all role observations as caller."""
    import subprocess

    if (point not in POINTS or not re.fullmatch(r"[a-f0-9]{64}", run_id) or
            not re.fullmatch(r"[a-f0-9]{64}", expected_qa_build_id)):
        raise ValueError("invalid pinned QA gate point or run id")
    proc = subprocess.Popen(["/usr/bin/sudo", "-n", sys.executable, helper_path,
        "--root-gate-client", socket_path, run_id, point, expected_qa_build_id],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, encoding="utf-8", shell=False, bufsize=1)
    try:
        line = proc.stdout.readline()
        entered = json.loads(line)
        if set(entered) != {"op", "broker_pid"} or entered.get("op") != "entered":
            raise RuntimeError("root QA gate peer did not return ENTERED")
        observe_while_pending(entered)
        proc.stdin.write('{"op":"release"}\n')
        proc.stdin.flush()
        line = proc.stdout.readline()
        completed = json.loads(line)
        if set(completed) != {"op", "result_ok", "errno"} or completed.get("op") != "completed":
            raise RuntimeError("root QA gate peer did not return COMPLETED")
        code = proc.wait(timeout=30)
        stderr = proc.stderr.read()
        if code != 0 or stderr:
            raise RuntimeError("root QA gate peer did not exit cleanly")
        return {"entered": True, "completed": True,
                "persistence_result_ok": completed["result_ok"],
                "persistence_errno": completed["errno"],
                "gate_kind": "compile-time QA boundary hold; real persistence call follows release"}
    except BaseException:
        if proc.poll() is None:
            try:
                proc.stdin.write('{"op":"release"}\n')
                proc.stdin.flush()
            except Exception:
                pass
            try: proc.wait(timeout=30)
            except subprocess.TimeoutExpired: proc.kill(); proc.wait(timeout=5)
        raise
    finally:
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            if stream:
                stream.close()


if __name__ == "__main__" and len(sys.argv) == 6 and sys.argv[1] == "--root-gate-client":
    try:
        _root_gate_client(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
    except BaseException:
        raise SystemExit(2)
