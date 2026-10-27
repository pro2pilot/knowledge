#!/usr/bin/env python3
"""Manual, bounded QA for the fixed Linux system-service boundary.

This controller has two phases. ``prepare`` runs as the ordinary Actions
runner and compiles only the colocated service.c into runner scratch. ``run`` is
the fixed root admin/controller operation: it installs that verified static
binary at one fresh root-owned path, starts one systemd unit, exercises only
the fixed 32-byte protocol, and removes only the installation it created.
It never launches Node, a shell, a project command, or caller-selected code.
"""
from __future__ import annotations

import argparse
import array
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import select
import signal
import socket
import stat
import struct
import subprocess
import sys
import time
import uuid


HERE = Path(__file__).resolve().parent
SERVICE_SOURCE = HERE / "service.c"
HISTORY_ROOT = HERE.parents[2] / "source" / ".knowledge" / "tools" / "lib"
HISTORY_SOURCES = [HISTORY_ROOT / ("verification-linux-uid-history" + suffix) for suffix in (".h", ".c")]
RUNNER_UID = 1001
UID_FIRST = 1000010200
UID_LAST = UID_FIRST + 2 * 4 - 1
MAGIC = 0x4B425331
VERSION = 1
ORDINAL = 1
REQUEST = struct.Struct("<IIII16s")
CANARY = 0x4B4E4F574C454447
WORK_MS = 15000
CLEANUP_MS = 10000
START_TIMEOUT = 20
NORMAL_CLOSE_TIMEOUT = 30
CALLER_DEATH_TIMEOUT = 15
CRASH_CLOSE_TIMEOUT = 15
ADMIN_TIMEOUT = 20
MAX_BINARY = 16 * 1024 * 1024
MAX_RESULT = 4096
HELPER_UNCONFIRMED = False
OWNED_HELPERS: dict[int, int | None] = {}


class QAFailure(RuntimeError):
    pass


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_hash(path: Path, maximum: int = MAX_BINARY) -> tuple[str, int]:
    h = hashlib.sha256()
    size = 0
    with path.open("rb", buffering=0) as stream:
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                break
            size += len(block)
            if size > maximum:
                raise QAFailure(f"file exceeds bounded read: {path.name}")
            h.update(block)
    return h.hexdigest(), size


def json_write(path: Path, value: object, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + f".tmp-{os.getpid()}")
    body = (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), mode)
    try:
        os.write(fd, body)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.chmod(temporary, mode)
    os.replace(temporary, path)


def physical_file(path: Path, *, uid: int | None = None, maximum: int = MAX_BINARY) -> tuple[os.stat_result, bytes]:
    named = path.lstat()
    if not stat.S_ISREG(named.st_mode) or named.st_nlink != 1 or named.st_size > maximum:
        raise QAFailure(f"expected a bounded single-link regular file: {path}")
    if uid is not None and named.st_uid != uid:
        raise QAFailure(f"unexpected file owner for {path.name}")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino, opened.st_mode, opened.st_nlink, opened.st_size) != \
                (named.st_dev, named.st_ino, named.st_mode, named.st_nlink, named.st_size):
            raise QAFailure(f"file identity changed during open: {path.name}")
        chunks = bytearray()
        while len(chunks) <= maximum:
            part = os.read(fd, min(65536, maximum + 1 - len(chunks)))
            if not part:
                break
            chunks.extend(part)
        after = os.fstat(fd)
        named_after = path.lstat()
        identity = lambda row: (row.st_dev, row.st_ino, row.st_mode, row.st_nlink, row.st_size, row.st_mtime_ns)
        if len(chunks) > maximum or len(chunks) != opened.st_size or any(
                identity(row) != identity(opened) for row in (after, named_after)):
            raise QAFailure(f"file changed during bounded read: {path.name}")
        return opened, bytes(chunks)
    finally:
        os.close(fd)


def elf_static_arm64(data: bytes) -> bool:
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        return False
    e_type, machine = struct.unpack_from("<HH", data, 16)
    phoff = struct.unpack_from("<Q", data, 32)[0]
    phentsize, phnum = struct.unpack_from("<HH", data, 54)
    expected_machine = 183 if platform.machine().lower() in {"aarch64", "arm64"} else 62
    if e_type != 2 or machine != expected_machine or phentsize < 56 or phnum < 1 or phnum > 128:
        return False
    if phoff + phentsize * phnum > len(data):
        return False
    types = [struct.unpack_from("<I", data, phoff + i * phentsize)[0] for i in range(phnum)]
    return 1 in types and 2 not in types and 3 not in types  # PT_LOAD present; no PT_DYNAMIC/PT_INTERP.


def request_frame(op: int, nonce: bytes) -> bytes:
    if len(nonce) != 16:
        raise ValueError("nonce must be 16 bytes")
    return REQUEST.pack(MAGIC, VERSION, op, ORDINAL, nonce)


def bounded_command(name: str, argv: list[str], timeout: int, private: Path,
                    result: dict, *, expected: set[int] = {0}) -> subprocess.CompletedProcess:
    if not argv or argv[0] not in {"systemd-run", "systemctl"}:
        raise QAFailure("attempted non-allowlisted root admin command")
    started = time.monotonic()
    try:
        proc = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=timeout, check=False, shell=False, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"})
        out, err, code = proc.stdout, proc.stderr, proc.returncode
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout or b""
        err = exc.stderr or b""
        code = None
    folder = private / "commands"
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", name)
    out_path, err_path = folder / (safe + ".stdout"), folder / (safe + ".stderr")
    out_path.write_bytes(out); err_path.write_bytes(err)
    step = {"name": name, "exit_code": code, "expected_exit_codes": sorted(expected),
            "elapsed_seconds": round(time.monotonic() - started, 3), "timeout_seconds": timeout,
            "stdout_bytes": len(out), "stdout_sha256": sha256(out),
            "stderr_bytes": len(err), "stderr_sha256": sha256(err),
            "status": "PASS" if code in expected else "FAIL"}
    result.setdefault("admin_operations", []).append(step)
    if code not in expected:
        raise QAFailure(f"bounded admin operation failed: {name}")
    return subprocess.CompletedProcess(argv, code, out, err)


def parse_systemd_show(data: bytes) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in data.decode("utf-8", "replace").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
    return values


def read_bounded(path: Path, maximum: int, *, require_size_match: bool = True) -> bytes:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
        raise QAFailure(f"bounded regular file required: {path}")
    body = path.read_bytes()
    if (require_size_match and len(body) != info.st_size) or len(body) > maximum:
        raise QAFailure(f"file changed or exceeded bound: {path}")
    return body


def sysctl_fingerprint() -> dict:
    # Only the installation contract's relevant policy knobs. A /proc/sys
    # crawl includes write-only and dynamically changing pseudo-files.
    files = (
        "/proc/sys/kernel/apparmor_restrict_unprivileged_userns",
        "/proc/sys/kernel/apparmor_restrict_unprivileged_unconfined",
        "/proc/sys/kernel/yama/ptrace_scope",
        "/proc/sys/user/max_user_namespaces",
    )
    values = {name: read_bounded(Path(name), 4096, require_size_match=False).decode("ascii").strip()
              for name in files}
    return {"status": "captured", "scope": "explicit_policy_knobs_only", "values": values,
            "sha256": sha256(json.dumps(values,sort_keys=True,separators=(",",":")).encode())}


def apparmor_fingerprint() -> dict:
    path = Path("/sys/kernel/security/apparmor/profiles")
    try:
        body = read_bounded(path, 4 * 1024 * 1024, require_size_match=False)
    except FileNotFoundError:
        return {"status": "unavailable"}
    lines = sorted(line.strip() for line in body.splitlines() if line.strip())
    return {"status": "captured", "sha256": sha256(b"\n".join(lines) + b"\n"), "profiles": len(lines)}


def namespace_fingerprint() -> dict[str, int]:
    result = {}
    for name in ("cgroup", "ipc", "mnt", "net", "pid", "time", "user", "uts"):
        path = Path("/proc/self/ns") / name
        try:
            st = path.stat()
        except FileNotFoundError:
            continue
        result[name] = st.st_ino
    return result


def process_stat(pid: int) -> dict:
    raw = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    close = raw.rfind(")")
    if close < 0:
        raise QAFailure("malformed proc stat")
    fields = raw[close + 2:].split()
    if len(fields) < 20:
        raise QAFailure("short proc stat")
    return {"state": fields[0], "ppid": int(fields[1]), "starttime": int(fields[19])}


def cgroup_membership(pid: int) -> str:
    body = read_bounded(Path(f"/proc/{pid}/cgroup"), 65536, require_size_match=False).decode("ascii", "strict")
    rows = [line for line in body.splitlines() if line.startswith("0::")]
    if len(rows) != 1:
        raise QAFailure("process is not on one unified cgroup v2 hierarchy")
    return rows[0][3:]


def exact_pidfd(pid: int, expected_cgroup: str) -> tuple[int, dict]:
    before = process_stat(pid)
    membership = cgroup_membership(pid)
    if membership != expected_cgroup:
        raise QAFailure("refusing pidfd for a PID outside this owned QA cgroup")
    fd = os.pidfd_open(pid, 0)
    try:
        after = process_stat(pid)
        again = cgroup_membership(pid)
        info = Path(f"/proc/self/fdinfo/{fd}").read_text(encoding="ascii")
        pid_rows = [line for line in info.splitlines() if line.startswith("Pid:")]
        if (before["ppid"], before["starttime"]) != (after["ppid"], after["starttime"]) or \
                again != membership or pid_rows != [f"Pid:\t{pid}"]:
            raise QAFailure("pidfd did not retain the exact owned process identity")
        return fd, {"pid": pid, "starttime_ticks": before["starttime"], "ppid": before["ppid"],
                    "cgroup": membership}
    except Exception:
        os.close(fd)
        raise


def pidfd_ready(fd: int, timeout: float = 0.0) -> bool:
    poller = select.poll()
    poller.register(fd, select.POLLIN | select.POLLHUP | select.POLLERR)
    return bool(poller.poll(max(0, int(timeout * 1000))))


def wait_pidfd(fd: int, seconds: float) -> bool:
    return pidfd_ready(fd, seconds)


def signal_pidfd(fd: int, sig: int) -> None:
    signal.pidfd_send_signal(fd, sig, None, 0)


def fork_owned_helper() -> int:
    """Register custody before any parent-side read, parsing or allocation.

    Only this single-threaded controller reaps these direct children. Until
    waitpid confirms an exit their PID cannot refer to an unrelated process.
    """
    pid = os.fork()
    if pid > 0:
        OWNED_HELPERS[pid] = None
        OWNED_HELPERS[pid] = os.pidfd_open(pid, 0)
    return pid


def cleanup_owned_helpers() -> bool:
    global HELPER_UNCONFIRMED
    for pid, fd in list(OWNED_HELPERS.items()):
        try:
            if fd is None:
                # pidfd allocation failed before any consumer got custody.
                # Check the still-unreaped direct child before signalling.
                waited, _ = os.waitpid(pid, os.WNOHANG)
                if waited == 0:
                    os.kill(pid, signal.SIGKILL)
                    end = time.monotonic() + 2.0
                    while time.monotonic() < end:
                        waited, _ = os.waitpid(pid, os.WNOHANG)
                        if waited == pid:
                            break
                        time.sleep(0.01)
                if waited == pid:
                    OWNED_HELPERS.pop(pid, None)
            elif reap_exact_child(pid, fd, 0.25):
                os.close(fd)
        except BaseException:
            HELPER_UNCONFIRMED = True
    if OWNED_HELPERS:
        HELPER_UNCONFIRMED = True
    return not OWNED_HELPERS and not HELPER_UNCONFIRMED


def reap_exact_child(pid: int, pidfd: int, timeout: float, *, kill_after: bool = True) -> bool:
    """Bounded wait for one direct child, with optional exact-pidfd kill."""
    global HELPER_UNCONFIRMED
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        waited, _ = os.waitpid(pid, os.WNOHANG)
        if waited == pid:
            OWNED_HELPERS.pop(pid, None)
            return True
        if pidfd_ready(pidfd, min(0.1, max(0.0, deadline - time.monotonic()))):
            waited, _ = os.waitpid(pid, os.WNOHANG)
            if waited == pid:
                OWNED_HELPERS.pop(pid, None)
                return True
        time.sleep(0.01)
    if kill_after:
        try:
            signal_pidfd(pidfd, signal.SIGKILL)
        except ProcessLookupError:
            pass
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            waited, _ = os.waitpid(pid, os.WNOHANG)
            if waited == pid:
                OWNED_HELPERS.pop(pid, None)
                return True
            if pidfd_ready(pidfd, min(0.1, max(0.0, deadline - time.monotonic()))):
                waited, _ = os.waitpid(pid, os.WNOHANG)
                if waited == pid:
                    OWNED_HELPERS.pop(pid, None)
                    return True
            time.sleep(0.01)
    HELPER_UNCONFIRMED = True
    return False


def read_cgroup_events(path: Path) -> dict[str, int]:
    body = read_bounded(path / "cgroup.events", 4096, require_size_match=False).decode("ascii", "strict")
    parsed = {}
    for line in body.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].isdigit():
            parsed[parts[0]] = int(parts[1])
    if "populated" not in parsed or "frozen" not in parsed:
        raise QAFailure("cgroup.events lacked populated/frozen fields")
    return parsed


def drop_ids(uid: int, gid: int) -> None:
    os.setgroups([])
    os.setresgid(gid, gid, gid)
    os.setresuid(uid, uid, uid)
    if os.getresuid() != (uid, uid, uid) or os.getresgid() != (gid, gid, gid):
        raise OSError("credential drop did not stick")


def close_unlisted_fds(keep: set[int]) -> None:
    try:
        names = os.listdir("/proc/self/fd")
    except OSError:
        return
    for name in names:
        if name.isdigit():
            fd = int(name)
            if fd > 2 and fd not in keep:
                try: os.close(fd)
                except OSError: pass


def child_write_json(fd: int, value: dict) -> None:
    body = (json.dumps(value, separators=(",", ":"), sort_keys=True) + "\n").encode()
    if len(body) > MAX_RESULT:
        body = b'{"error":"child result exceeds cap"}\n'
    os.write(fd, body)


def spawn_client(uid: int, gid: int, sock_path: str, payload: bytes, *, hold: bool = False,
                 send_right: bool = False, attach_socket: bool = False,
                 private: Path | None = None) -> dict:
    result_r, result_w = os.pipe2(os.O_CLOEXEC)
    control_r, control_w = os.pipe2(os.O_CLOEXEC)
    if attach_socket:
        transfer_parent, transfer_child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
    else:
        transfer_parent = transfer_child = None
    pid = fork_owned_helper()
    if pid == 0:
        try:
            os.close(result_r); os.close(control_w)
            if transfer_parent is not None: transfer_parent.close()
            close_unlisted_fds({result_w, control_r} | ({transfer_child.fileno()} if transfer_child else set()))
            drop_ids(uid, gid)
            client = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
            client.settimeout(3.0); client.connect(sock_path)
            if attach_socket:
                assert transfer_child is not None
                rights = array.array("i", [client.fileno()])
                transfer_child.sendmsg([b"F"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights.tobytes())])
                child_write_json(result_w, {"connected": True, "pid": os.getpid(), "uid": os.getuid()})
                os.read(control_r, 1)
                client.close(); os._exit(0)
            if send_right:
                fd = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
                rights = array.array("i", [fd])
                client.sendmsg([payload], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights.tobytes())])
                os.close(fd)
            else:
                client.send(payload)
            response = client.recv(4096)
            child_write_json(result_w, {"response": response.decode("utf-8", "replace"), "pid": os.getpid(), "uid": os.getuid()})
            client.close()
            if hold:
                os.read(control_r, 1)
            os._exit(0)
        except BaseException as exc:
            try: child_write_json(result_w, {"error": type(exc).__name__ + ": " + str(exc), "pid": os.getpid(), "uid": os.getuid()})
            except BaseException: pass
            os._exit(90)
    os.close(result_w); os.close(control_r)
    if transfer_child is not None: transfer_child.close()
    pidfd = OWNED_HELPERS[pid]
    os.set_blocking(result_r, False)
    response = bytearray()
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        ready, _, _ = select.select([result_r], [], [], max(0, deadline - time.monotonic()))
        if not ready:
            break
        chunk = os.read(result_r, MAX_RESULT + 1 - len(response))
        if not chunk:
            break
        response.extend(chunk)
        if b"\n" in response:
            break
        if len(response) > MAX_RESULT:
            break
    if not response or len(response) > MAX_RESULT or b"\n" not in response:
        reaped = reap_exact_child(pid, pidfd, 1.0)
        if reaped: os.close(pidfd)
        os.close(result_r); os.close(control_w)
        if transfer_parent is not None: transfer_parent.close()
        raise QAFailure("caller child did not return one bounded result" + ("; exact-child cleanup unconfirmed" if not reaped else ""))
    value = json.loads(response.split(b"\n", 1)[0])
    actor = {"pid": pid, "pidfd": pidfd, "result_r": result_r, "control_w": control_w,
             "value": value, "transfer": transfer_parent, "released": False}
    if "error" in value:
        release_actor(actor)
        raise QAFailure("ordinary caller request failed: " + str(value["error"]))
    return actor


def release_actor(actor: dict, *, timeout: float = 3.0) -> None:
    if actor.get("released"):
        return
    control = actor.pop("control_w", None)
    if control is not None:
        try: os.write(control, b"X")
        except OSError: pass
        try: os.close(control)
        except OSError: pass
    if not reap_exact_child(actor["pid"], actor["pidfd"], timeout):
        actor["quarantine"] = True
        raise QAFailure("exact caller child exit remains unconfirmed; retaining QA fixture")
    actor["released"] = True
    for key in ("pidfd", "result_r"):
        try: os.close(actor[key])
        except OSError: pass
    if actor.get("transfer") is not None:
        actor["transfer"].close()


def request_as_c(sock_path: str, op: int, nonce: bytes, *, hold: bool = False,
                 send_right: bool = False, payload: bytes | None = None) -> dict:
    actor = spawn_client(RUNNER_UID, int(os.environ.get("SUDO_GID", "1001")), sock_path,
                         payload if payload is not None else request_frame(op, nonce), hold=hold, send_right=send_right)
    if not hold:
        release_actor(actor)
    return actor


def receive_json(actor: dict) -> dict:
    value = actor["value"]
    if "response" not in value:
        raise QAFailure("caller did not receive a protocol response")
    try:
        parsed = json.loads(value["response"])
    except (ValueError, TypeError) as exc:
        raise QAFailure("service returned malformed JSON") from exc
    if len(value["response"].encode()) > MAX_RESULT:
        raise QAFailure("service response exceeded bound")
    return parsed


def check(condition: bool, message: str) -> None:
    if not condition:
        raise QAFailure(message)


def poll_response(sock_path: str, nonce: bytes, predicate, timeout: float, label: str) -> tuple[dict, dict]:
    deadline = time.monotonic() + timeout
    last = {}
    while time.monotonic() < deadline:
        actor = request_as_c(sock_path, 4, nonce)
        last = receive_json(actor)
        if time.monotonic() <= deadline and predicate(last):
            return last, actor["value"]
        time.sleep(0.1)
    failure = QAFailure(f"timed out waiting for {label}; last service state={last.get('status')}")
    # Synthetic fixed QA actors only. Omit the canary address and private FDs.
    keys = {"status", "sequence", "worker_memory_denied", "init_exit_confirmed",
            "keeper_exit_confirmed", "cgroup_empty", "output_eof", "output_bytes",
            "stop_reason", "keeper_wait_status", "init_wait_status", "keeper_wait_known", "init_wait_known", "quarantine"}
    failure.native_observation = {key: value for key, value in last.items() if key in keys}
    raise failure


def validate_request_denied(sock_path: str, payload: bytes, *, send_right: bool = False) -> dict:
    actor = request_as_c(sock_path, 4, b"malformed-frame!", send_right=send_right, payload=payload)
    response = receive_json(actor)
    check(response.get("status") == "denied", "invalid/FD-bearing caller frame was not denied")
    return {"status": response["status"]}


def pass_exact_fd_to_worker(sock_path: str, nonce: bytes, worker_uid: int) -> dict:
    """Connect as C, pass that live accepted socket to an exact W child."""
    gid_c = int(os.environ.get("SUDO_GID", "1001"))
    connector = spawn_client(RUNNER_UID, gid_c, sock_path, b"", hold=True, attach_socket=True)
    transfer = connector["transfer"]
    if transfer is None:
        release_actor(connector); raise QAFailure("missing controlled FD transfer socket")
    transfer.settimeout(3.0)
    data, ancillary, flags, _ = transfer.recvmsg(8, socket.CMSG_SPACE(array.array("i").itemsize))
    fds = []
    for level, kind, body in ancillary:
        if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
            values = array.array("i"); values.frombytes(body[:len(body) - len(body) % values.itemsize]); fds.extend(values)
    if data != b"F" or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or len(fds) != 1:
        release_actor(connector)
        for fd in fds:
            try: os.close(fd)
            except OSError: pass
        raise QAFailure("caller did not delegate exactly one live socket FD")
    service_fd = fds[0]
    result_r, result_w = os.pipe2(os.O_CLOEXEC)
    pid = fork_owned_helper()
    if pid == 0:
        try:
            os.close(result_r)
            close_unlisted_fds({result_w, service_fd})
            drop_ids(worker_uid, worker_uid)
            client = socket.socket(fileno=service_fd); client.settimeout(3.0)
            client.send(request_frame(4, nonce))
            response = client.recv(4096)
            child_write_json(result_w, {"response": response.decode("utf-8", "replace"), "uid": os.getuid()})
            client.close(); os._exit(0)
        except BaseException as exc:
            try: child_write_json(result_w, {"error": type(exc).__name__ + ": " + str(exc)})
            except BaseException: pass
            os._exit(91)
    os.close(result_w); os.close(service_fd)
    pidfd = OWNED_HELPERS[pid]
    os.set_blocking(result_r, False)
    response = bytearray(); deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        ready, _, _ = select.select([result_r], [], [], max(0, deadline - time.monotonic()))
        if not ready: break
        part = os.read(result_r, MAX_RESULT + 1 - len(response))
        if not part: break
        response.extend(part)
        if b"\n" in response: break
    if not response or len(response) > MAX_RESULT or b"\n" not in response:
        reaped = reap_exact_child(pid, pidfd, 1.0)
        if reaped: os.close(pidfd)
        os.close(result_r)
        if reaped: release_actor(connector)
        raise QAFailure("W delegated socket child did not return a bounded response")
    value = json.loads(response.split(b"\n", 1)[0])
    if not reap_exact_child(pid, pidfd, 2.0):
        raise QAFailure("W delegated socket child exit remains unconfirmed; retaining QA fixture")
    os.close(pidfd); os.close(result_r)
    connector_alive = not pidfd_ready(connector["pidfd"])
    release_actor(connector)
    check(connector_alive and pid != connector["pid"] and value.get("uid") == worker_uid and json.loads(value.get("response", "{}" )).get("status") == "denied",
          "W frame on a socket connected by C was not denied")
    return {"connector_uid": RUNNER_UID, "frame_uid": worker_uid, "status": "denied",
            "sender_pid_distinct": True, "connector_alive_during_frame": True}


def memory_probe(uid: int, gid: int, authority_pid: int, authority_address: int,
                 authority_fd: int, authority_pidfd: int) -> dict:
    """Six bounded read/write/FD denial probes, executed by an exact C or W child."""
    result_r, result_w = os.pipe2(os.O_CLOEXEC)
    pid = fork_owned_helper()
    if pid == 0:
        try:
            os.close(result_r)
            close_unlisted_fds({result_w, authority_pidfd})
            drop_ids(uid, gid)
            libc = ctypes.CDLL(None, use_errno=True)
            cases: dict[str, dict] = {}

            class IOVec(ctypes.Structure):
                _fields_ = [("iov_base", ctypes.c_void_p), ("iov_len", ctypes.c_size_t)]

            local = ctypes.c_uint64(CANARY)
            local_vec = IOVec(ctypes.cast(ctypes.byref(local), ctypes.c_void_p), ctypes.sizeof(local))
            remote_vec = IOVec(ctypes.c_void_p(authority_address), ctypes.sizeof(local))
            libc.process_vm_readv.restype = ctypes.c_ssize_t
            ctypes.set_errno(0)
            read_rc = libc.process_vm_readv(authority_pid, ctypes.byref(local_vec), 1, ctypes.byref(remote_vec), 1, 0)
            read_errno = ctypes.get_errno()
            cases["process_vm_read"] = {"denied": read_rc == -1 and read_errno in (errno.EPERM, errno.EACCES), "errno": read_errno}

            local.value = CANARY
            ctypes.set_errno(0)
            write_rc = libc.process_vm_writev(authority_pid, ctypes.byref(local_vec), 1, ctypes.byref(remote_vec), 1, 0)
            write_errno = ctypes.get_errno()
            cases["process_vm_write"] = {"denied": write_rc == -1 and write_errno in (errno.EPERM, errno.EACCES), "errno": write_errno}

            # PEEK/POKE without an attached tracer yield ESRCH even without
            # an isolation boundary. Test admission with PTRACE_ATTACH itself.
            libc.ptrace.restype = ctypes.c_long
            libc.ptrace.argtypes = [ctypes.c_uint, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
            ctypes.set_errno(0)
            attach_rc = libc.ptrace(16, authority_pid, None, None)
            attach_errno = ctypes.get_errno()
            cases["ptrace_attach"] = {"denied": attach_rc == -1 and attach_errno in (errno.EPERM, errno.EACCES), "errno": attach_errno}
            if attach_rc == 0:
                # This failed negative must not become a pass. Exiting this
                # exact tracer also releases its unexpected attachment.
                raise QAFailure("unexpected authority ptrace admission")
            try:
                private_fd = os.open(f"/proc/{authority_pid}/fd/{authority_fd}", os.O_RDONLY | os.O_CLOEXEC)
            except OSError as exc:
                cases["proc_fd_read"] = {"denied": exc.errno in (errno.EPERM, errno.EACCES), "errno": exc.errno}
            else:
                os.close(private_fd)
                cases["proc_fd_read"] = {"denied": False, "errno": 0}

            mem_path = f"/proc/{authority_pid}/mem"
            mem_cases = []
            for flags, operation in ((os.O_RDONLY, "read"), (os.O_WRONLY, "write")):
                try:
                    fd = os.open(mem_path, flags | os.O_CLOEXEC)
                except OSError as exc:
                    mem_cases.append(exc.errno in (errno.EPERM, errno.EACCES))
                else:
                    try:
                        try:
                            if operation == "read":
                                os.pread(fd, 8, authority_address)
                            else:
                                os.pwrite(fd, struct.pack("<Q", CANARY), authority_address)
                            mem_cases.append(False)
                        except OSError as exc:
                            mem_cases.append(exc.errno in (errno.EPERM, errno.EACCES))
                    finally:
                        os.close(fd)
            cases["proc_mem_read_write"] = {"denied": len(mem_cases) == 2 and all(mem_cases), "operations": 2}

            # pidfd_getfd is syscall 438 on supported Linux architectures.
            ctypes.set_errno(0)
            libc.syscall.restype = ctypes.c_long
            duplicated = libc.syscall(ctypes.c_long(438), ctypes.c_int(authority_pidfd), ctypes.c_int(authority_fd), ctypes.c_uint(0))
            dup_errno = ctypes.get_errno()
            cases["pidfd_getfd"] = {"denied": duplicated == -1 and dup_errno in (errno.EPERM, errno.EACCES), "errno": dup_errno}
            if duplicated >= 0:
                os.close(duplicated)
            child_write_json(result_w, {"uid": os.getuid(), "cases": cases})
            os._exit(0)
        except BaseException as exc:
            try: child_write_json(result_w, {"error": type(exc).__name__ + ": " + str(exc), "uid": os.getuid()})
            except BaseException: pass
            os._exit(92)
    os.close(result_w)
    pidfd = OWNED_HELPERS[pid]
    os.set_blocking(result_r, False)
    body = bytearray(); deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        ready, _, _ = select.select([result_r], [], [], max(0, deadline - time.monotonic()))
        if not ready: break
        chunk = os.read(result_r, MAX_RESULT + 1 - len(body))
        if not chunk: break
        body.extend(chunk)
        if b"\n" in body: break
    if not body or len(body) > MAX_RESULT or b"\n" not in body:
        reaped = reap_exact_child(pid, pidfd, 1.0)
        if reaped: os.close(pidfd)
        os.close(result_r)
        raise QAFailure("memory probe child did not return one bounded result")
    value = json.loads(body.split(b"\n", 1)[0])
    if not reap_exact_child(pid, pidfd, 2.0):
        raise QAFailure("memory probe child exit remains unconfirmed; retaining QA fixture")
    os.close(pidfd); os.close(result_r)
    if value.get("error"):
        raise QAFailure("memory probe failed: " + value["error"])
    expected = {"process_vm_read", "process_vm_write", "ptrace_attach", "proc_fd_read", "proc_mem_read_write", "pidfd_getfd"}
    if value.get("uid") != uid or set(value.get("cases", {})) != expected or not all(row.get("denied") for row in value["cases"].values()):
        raise QAFailure("one or more of six memory/FD denial cases succeeded or was unverifiable")
    return {name: {"denied": row["denied"]} for name, row in value["cases"].items()}


def root_positive_authority_control(authority_pid: int, address: int, authority_fd: int) -> dict:
    """Prove the exact canary address and memfd are readable before negative probes."""
    libc = ctypes.CDLL(None, use_errno=True)

    class IOVec(ctypes.Structure):
        _fields_ = [("iov_base", ctypes.c_void_p), ("iov_len", ctypes.c_size_t)]

    local = ctypes.c_uint64(0)
    local_vec = IOVec(ctypes.cast(ctypes.byref(local), ctypes.c_void_p), ctypes.sizeof(local))
    remote_vec = IOVec(ctypes.c_void_p(address), ctypes.sizeof(local))
    libc.process_vm_readv.restype = ctypes.c_ssize_t
    ctypes.set_errno(0)
    read_bytes = libc.process_vm_readv(authority_pid, ctypes.byref(local_vec), 1,
                                       ctypes.byref(remote_vec), 1, 0)
    read_errno = ctypes.get_errno()
    if read_bytes != ctypes.sizeof(local) or local.value != CANARY:
        raise QAFailure(f"root positive process_vm_readv control failed (errno={read_errno})")
    memfd = os.open(f"/proc/{authority_pid}/mem", os.O_RDONLY | os.O_CLOEXEC)
    try:
        memory = os.pread(memfd, 8, address)
    finally:
        os.close(memfd)
    if memory != struct.pack("<Q", CANARY):
        raise QAFailure("root positive /proc/PID/mem control did not read the expected CANARY")
    procfd = os.open(f"/proc/{authority_pid}/fd/{authority_fd}", os.O_RDONLY | os.O_CLOEXEC)
    try:
        marker = os.pread(procfd, 64, 0)
    finally:
        os.close(procfd)
    if marker != b"QA_CANARY":
        raise QAFailure("root positive /proc/PID/fd control did not read QA_CANARY")
    # A global seccomp denial of syscall 438 must not masquerade as UID
    # isolation. Exercise the same syscall against this known readable canary.
    exact = os.pidfd_open(authority_pid, 0)
    libc.syscall.restype = ctypes.c_long
    try:
        duplicated = libc.syscall(ctypes.c_long(438), ctypes.c_int(exact), ctypes.c_int(authority_fd), ctypes.c_uint(0))
        if duplicated < 0:
            raise QAFailure(f"root pidfd_getfd positive control unavailable: errno={ctypes.get_errno()}")
        try:
            if os.pread(duplicated,64,0) != b"QA_CANARY":
                raise QAFailure("root pidfd_getfd did not read the exact canary")
        finally:
            os.close(duplicated)
    finally:
        os.close(exact)
    return {"process_vm_readv": "CANARY", "proc_mem_read": "CANARY",
            "proc_fd_read": "QA_CANARY", "pidfd_getfd": "QA_CANARY", "authority_fd_zero_valid": authority_fd == 0}


def root_harness_positive_fixture() -> dict:
    """Validate the read primitives on one root-owned direct-child canary."""
    result_r, result_w = os.pipe2(os.O_CLOEXEC)
    control_r, control_w = os.pipe2(os.O_CLOEXEC)
    pid = fork_owned_helper()
    if pid == 0:
        try:
            os.close(result_r); os.close(control_w)
            close_unlisted_fds({result_w, control_r})
            canary = ctypes.c_uint64(CANARY)
            fd = os.memfd_create("knowledge-admin-qa-positive", os.MFD_CLOEXEC)
            os.write(fd, b"QA_CANARY")
            child_write_json(result_w, {"address": ctypes.addressof(canary), "fd": fd,
                                        "pid": os.getpid(), "uid": os.getuid()})
            os.read(control_r, 1)
            os._exit(0)
        except BaseException as exc:
            try: child_write_json(result_w, {"error": type(exc).__name__ + ": " + str(exc)})
            except BaseException: pass
            os._exit(93)
    os.close(result_w); os.close(control_r)
    pidfd = OWNED_HELPERS[pid]
    os.set_blocking(result_r, False)
    body = bytearray(); deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        ready, _, _ = select.select([result_r], [], [], max(0, deadline - time.monotonic()))
        if not ready: break
        part = os.read(result_r, MAX_RESULT + 1 - len(body))
        if not part: break
        body.extend(part)
        if b"\n" in body: break
    if not body or len(body) > MAX_RESULT or b"\n" not in body:
        reaped = reap_exact_child(pid, pidfd, 1.0)
        if reaped: os.close(pidfd)
        os.close(result_r); os.close(control_w)
        raise QAFailure("root positive control child did not return bounded fixture metadata")
    value = json.loads(body.split(b"\n", 1)[0])
    if value.get("error") or value.get("uid") != 0:
        try: os.write(control_w, b"X")
        except OSError: pass
        reaped = reap_exact_child(pid, pidfd, 2.0)
        if reaped: os.close(pidfd)
        os.close(result_r); os.close(control_w)
        raise QAFailure("root positive control fixture was not root-owned")
    fd = int(value["fd"]); address = int(value["address"])
    try:
        return root_positive_authority_control(pid, address, fd)
    finally:
        # A failed positive control must close its own fixture too. Otherwise
        # a test failure could leave a root child waiting on this pipe while
        # the rest of the controller reports installation cleanup.
        try: os.write(control_w, b"X")
        except OSError: pass
        os.close(control_w)
        reaped = reap_exact_child(pid, pidfd, 2.0)
        if reaped: os.close(pidfd)
        os.close(result_r)
        if not reaped:
            raise QAFailure("root positive control child exit remained unconfirmed")


def prepare(scratch_arg: Path, history: bool = False) -> int:
    if os.geteuid() == 0 or os.getuid() != RUNNER_UID:
        raise QAFailure("prepare must run as the actual non-root Ubuntu runner UID 1001")
    if platform.machine().lower() not in ({"aarch64", "arm64", "x86_64"} if history else {"aarch64", "arm64"}):
        raise QAFailure("this workflow is deliberately restricted to Ubuntu ARM64")
    source_stat, source_bytes = physical_file(SERVICE_SOURCE, uid=RUNNER_UID, maximum=256 * 1024)
    token = uuid.uuid4().hex[:12]
    scratch = scratch_arg.absolute()
    if not scratch.parent.is_dir() or scratch.exists() or scratch.is_symlink():
        raise QAFailure("prepare scratch must be a fresh path below the runner temporary directory")
    scratch.mkdir(mode=0o700, parents=False)
    os.chmod(scratch, 0o700)
    unit = "knowledge-svc-" + token
    qa_root = f"/var/lib/{unit}"
    qa_cgroup = f"/sys/fs/cgroup/system.slice/{unit}.service"
    binary = scratch / "service.static"
    cc = Path("/usr/bin/cc")
    if not cc.is_file():
        raise QAFailure("fixed /usr/bin/cc compiler is unavailable")
    flags = [str(cc), "-std=gnu11", "-O2", "-static", "-no-pie", "-Wall", "-Wextra",
            "-Wno-misleading-indentation", "-Werror=implicit-function-declaration",
            f'-DQA_ROOT="{qa_root}"', f'-DQA_CGROUP="{qa_cgroup}"',
            f"-DQA_CALLER_UID={RUNNER_UID}", f"-DQA_UID_FIRST={UID_FIRST}"]
    history_sources = {}
    history_link = []
    if history:
        machine_id = Path('/etc/machine-id').read_text().strip()
        if not re.fullmatch('[0-9a-f]{32}', machine_id):
            raise QAFailure('machine-id must be the fixed 16-byte host binding')
        for source in HISTORY_SOURCES:
            _, body = physical_file(source, uid=RUNNER_UID, maximum=256 * 1024)
            history_sources[str(source)] = sha256(body)
        flags += ['-DQA_DURABLE_HISTORY', '-I', str(HISTORY_ROOT),
                  f'-DQA_HISTORY_INSTALLATION="{token + "0" * 20}"', f'-DQA_HISTORY_HOST="{machine_id}"']
        history_link = [str(HISTORY_SOURCES[1]), '-lcrypto']
    argv = [*flags, str(SERVICE_SOURCE), *history_link, "-o", str(binary)]
    started = time.monotonic()
    proc = subprocess.run(argv, cwd=HERE, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=150, check=False, shell=False,
                          env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "TMPDIR": str(scratch)})
    (scratch / "compile.stdout.log").write_bytes(proc.stdout)
    (scratch / "compile.stderr.log").write_bytes(proc.stderr)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr.decode("utf-8", "replace")[-8192:])
        raise QAFailure("fixed static service compile failed; compiler logs remain in runner scratch")
    # Exercise the exact parser with real ordinary-user Unix sockets before
    # any root installation. This regression fails on the previous EOF code.
    parser_binary = scratch / "event-parser.static"
    parser_source = HERE / "native_event_qa.c"
    _, parser_source_bytes = physical_file(parser_source, uid=RUNNER_UID, maximum=64 * 1024)
    parser_argv = [*flags, str(parser_source), *history_link, "-o", str(parser_binary)]
    parser_build = subprocess.run(parser_argv, cwd=HERE, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=150, check=False,
        env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "TMPDIR": str(scratch)})
    if parser_build.returncode != 0:
        sys.stderr.write(parser_build.stderr.decode("utf-8", "replace")[-8192:])
        raise QAFailure("ordinary-user socket parser regression did not compile")
    parser_check = subprocess.run([str(parser_binary)], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10, check=False,
        env={"PATH": "/usr/bin:/bin", "LANG": "C"})
    if parser_check.returncode != 0 or json.loads(parser_check.stdout) != {
            "status": "PASS_SOCKET_PARSER", "checks": 6, "privileged": False}:
        sys.stderr.write(parser_check.stderr.decode("utf-8", "replace")[-8192:])
        raise QAFailure("ordinary-user physical socket parser regression failed")
    binary_stat, binary_bytes = physical_file(binary, uid=RUNNER_UID)
    if not elf_static_arm64(binary_bytes):
        raise QAFailure("compiled service is not a static ARM64 ELF without PT_INTERP")
    if binary_stat.st_mode & (stat.S_ISUID | stat.S_ISGID):
        raise QAFailure("prepared service binary unexpectedly has set-id bits")
    plan = {
        "schema_version": "linux-admin-service-qa-plan.v1", "run_id": token,
        "runner_uid": RUNNER_UID, "runner_gid": os.getgid(), "architecture": platform.machine().lower(),
        "durable_history": history, "history_source_sha256": history_sources,
        "source_path": str(SERVICE_SOURCE), "source_sha256": sha256(source_bytes), "source_bytes": len(source_bytes),
        "binary_path": str(binary), "binary_sha256": sha256(binary_bytes), "binary_bytes": len(binary_bytes),
        "root_path": qa_root, "unit": unit, "cgroup_path": qa_cgroup,
        "caller_uid": RUNNER_UID, "uid_first": UID_FIRST, "uid_last": UID_LAST,
        "compiled_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "compile_elapsed_seconds": round(time.monotonic() - started, 3),
        "compile_exit_code": proc.returncode,
        "event_parser_qa": {"source_sha256": sha256(parser_source_bytes),
            "status": "PASS_SOCKET_PARSER", "checks": 6, "privileged": False,
            "stdout_sha256": sha256(parser_check.stdout)},
        "compile_stdout_sha256": sha256(proc.stdout), "compile_stderr_sha256": sha256(proc.stderr),
    }
    json_write(scratch / "plan.json", plan, 0o600)
    print(json.dumps({"status": "PREPARED", "run_id": token, "source_sha256": plan["source_sha256"],
                      "binary_sha256": plan["binary_sha256"], "binary_bytes": len(binary_bytes)}, sort_keys=True))
    return 0


class ServiceQA:
    def __init__(self, scratch: Path, public: Path, history: bool = False):
        if os.geteuid() != 0 or os.environ.get("SUDO_UID") != str(RUNNER_UID):
            raise QAFailure("run must be invoked as the fixed sudo controller with SUDO_UID=1001")
        if platform.machine().lower() not in ({"aarch64", "arm64", "x86_64"} if history else {"aarch64", "arm64"}):
            raise QAFailure("run is restricted to the Ubuntu ARM64 workflow")
        self.scratch = scratch.absolute()
        self.public = public.absolute()
        self.plan_path = self.scratch / "plan.json"
        self.plan: dict = {}
        self.history = history
        self.history_directories = {}
        self.history_initializer_created = False
        self.private = self.scratch / "private-root"
        self.result = {"schema_version": "linux-admin-service-boundary-qa.v1",
                       "status": "RUNNING", "scope": "Fixed native service lifecycle plus durable UID history QA; not production qualification." if history else "Manual restricted Ubuntu ARM64 native service boundary QA; not production qualification.",
                       "durable_history_component": history,
                       "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                       "architecture": platform.machine(), "checks": {}, "admin_operations": [],
                       "qa_checks_passed": [], "non_product_observations": {}}
        self.qa_root: Path | None = None
        self.unit: str | None = None
        self.root_inode: tuple[int, int] | None = None
        self.binary_hash: str | None = None
        self.service_cgroup: Path | None = None
        self.cgroup_rel: str | None = None
        self.active_actors: list[dict] = []
        self.resume_fd: int | None = None
        self.install_created = False
        self.unit_created = False
        self.snap_before: dict = {}
        self.uid_reservation = None
        self.qa_anchor_pidfd = None

    def save_public(self) -> None:
        self.public.mkdir(mode=0o755, parents=True, exist_ok=True)
        os.chmod(self.public, 0o755)
        public_result = json.loads(json.dumps(self.result))
        public_result.pop("_pidfds", None)
        public_result.pop("private_runtime", None)
        json_write(self.public / "RESULT.json", public_result, 0o644)

    def record_pass(self, name: str, detail: dict | None = None) -> None:
        values = dict(detail or {})
        if "status" in values:
            values["observed_status"] = values.pop("status")
        self.result["checks"][name] = {**values, "status": "PASS"}
        self.result["qa_checks_passed"].append(name)
        self.save_public()

    def record_observation(self, name: str, detail: dict) -> None:
        self.result["non_product_observations"][name] = {"status": "OBSERVED_ONLY_NOT_PRODUCT_PASS", **detail}
        self.save_public()

    def load_plan(self) -> None:
        scratch_st = self.scratch.lstat()
        if not stat.S_ISDIR(scratch_st.st_mode) or stat.S_ISLNK(scratch_st.st_mode) or scratch_st.st_uid != RUNNER_UID:
            raise QAFailure("runner scratch directory is not a physical UID 1001 directory")
        plan_st, raw = physical_file(self.plan_path, uid=RUNNER_UID, maximum=32768)
        if plan_st.st_mode & 0o077:
            raise QAFailure("runner plan must remain private")
        self.plan = json.loads(raw)
        token = self.plan.get("run_id", "")
        if not re.fullmatch(r"[a-f0-9]{12}", token):
            raise QAFailure("invalid unique run id in runner plan")
        expected = {
            "schema_version": "linux-admin-service-qa-plan.v1", "runner_uid": RUNNER_UID,
            "architecture": platform.machine().lower(), "caller_uid": RUNNER_UID, "uid_first": UID_FIRST, "uid_last": UID_LAST,
            "durable_history": self.history,
            "root_path": f"/var/lib/knowledge-svc-{token}", "unit": f"knowledge-svc-{token}",
            "cgroup_path": f"/sys/fs/cgroup/system.slice/knowledge-svc-{token}.service",
            "source_path": str(SERVICE_SOURCE), "binary_path": str((self.scratch / "service.static").absolute()),
        }
        if any(self.plan.get(key) != value for key, value in expected.items()):
            raise QAFailure("runner plan did not match fixed source, UID interval or install paths")
        source_stat, source_bytes = physical_file(SERVICE_SOURCE, uid=RUNNER_UID, maximum=256 * 1024)
        if sha256(source_bytes) != self.plan.get("source_sha256"):
            raise QAFailure("service.c changed after unprivileged static build")
        if self.history:
            for source in HISTORY_SOURCES:
                _, body = physical_file(source, uid=RUNNER_UID, maximum=256 * 1024)
                if self.plan.get('history_source_sha256', {}).get(str(source)) != sha256(body):
                    raise QAFailure('native history source changed after ordinary-user build')
        binary_stat, binary_bytes = physical_file(self.scratch / "service.static", uid=RUNNER_UID)
        if sha256(binary_bytes) != self.plan.get("binary_sha256") or len(binary_bytes) != self.plan.get("binary_bytes") or \
                not elf_static_arm64(binary_bytes) or binary_stat.st_mode & (stat.S_ISUID | stat.S_ISGID):
            raise QAFailure("prepared static service bytes changed or failed ELF policy")
        self.qa_root = Path(self.plan["root_path"])
        self.unit = self.plan["unit"]
        self.service_cgroup = Path(self.plan["cgroup_path"])
        self.cgroup_rel = "/system.slice/" + self.unit + ".service"
        self.binary_hash = self.plan["binary_sha256"]
        self.private.mkdir(mode=0o700)
        os.chmod(self.private, 0o700)
        self.result.update({"run_id": token, "service_source_sha256": self.plan["source_sha256"],
                            "prepared_binary_sha256": self.plan["binary_sha256"],
                            "prepared_binary_bytes": self.plan["binary_bytes"],
                            "event_parser_qa": self.plan["event_parser_qa"],
                            "caller_uid": RUNNER_UID, "uid_interval": [UID_FIRST, UID_LAST],
                            "workflow_commit": os.environ.get("GITHUB_SHA"),
                            "driver_sha256": sha256(Path(__file__).read_bytes()),
                            "kernel_release": platform.release(),
                            "kernel_version": platform.version(),
                            "history_source_sha256": self.plan.get('history_source_sha256', {})})

    def snapshot_host_policy(self) -> dict:
        return {"sysctl": sysctl_fingerprint(), "apparmor": apparmor_fingerprint(),
                "controller_namespaces": namespace_fingerprint()}

    def verify_system_ready(self) -> None:
        check = Path("/sys/fs/cgroup/cgroup.controllers")
        if not check.is_file():
            raise QAFailure("unified cgroup v2 is not mounted at /sys/fs/cgroup")
        mounts = Path("/proc/mounts").read_text(encoding="ascii", errors="replace").splitlines()
        if not any(len(row.split()) >= 3 and row.split()[1] == "/sys/fs/cgroup" and row.split()[2] == "cgroup2" for row in mounts):
            raise QAFailure("system cgroup v2 mount type was not confirmed")
        if not Path("/run/systemd/system").is_dir():
            raise QAFailure("systemd system manager is unavailable")
        root = Path("/var/lib")
        for parent in (Path("/"), Path("/var"), root):
            st = parent.lstat()
            if not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode) or st.st_uid != 0 or stat.S_IMODE(st.st_mode) & 0o022:
                raise QAFailure("/var/lib ancestor is symlinked, non-root-owned, or group/world writable")
        self.record_pass("host_service_prerequisites", {"cgroup_v2": True, "systemd_system_manager": True,
                         "root_ancestors_nonwritable": True, "apparmor_before": self.snap_before.get("apparmor", {}).get("status")})

    def occupied_uid_preflight(self) -> dict:
        # Installation-time local checks, not runtime NSS or a claim that a
        # free-UID search itself reserves anything. The fixed admin claim below
        # is exclusive for this ephemeral, single-job test host only.
        for filename, column in (("/etc/passwd",2),("/etc/group",2)):
            for line in read_bounded(Path(filename),4*1024*1024).decode("utf-8").splitlines():
                if not line or line.startswith("#"): continue
                fields=line.split(":")
                if len(fields)<=column or not fields[column].isdigit(): raise QAFailure("invalid local account table")
                if UID_FIRST<=int(fields[column])<=UID_LAST: raise QAFailure("QA interval overlaps an account")
        for filename in ("/etc/subuid","/etc/subgid"):
            if not Path(filename).exists(): continue
            for line in read_bounded(Path(filename),4*1024*1024).decode("utf-8").splitlines():
                if not line or line.startswith("#"): continue
                fields=line.split(":")
                if len(fields)!=3 or not fields[1].isdigit() or not fields[2].isdigit(): raise QAFailure("invalid subordinate ID table")
                start,count=int(fields[1]),int(fields[2])
                if count and start<=UID_LAST and start+count-1>=UID_FIRST: raise QAFailure("QA interval overlaps subordinate IDs")
        deadline=time.monotonic()+10; checked=0
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit(): continue
            if checked>=8192 or time.monotonic()>deadline: raise QAFailure("bounded UID occupancy scan incomplete")
            try: body=read_bounded(entry/"status",65536,require_size_match=False).decode("ascii")
            except (FileNotFoundError,ProcessLookupError): continue
            checked+=1
            for line in body.splitlines():
                if line.startswith(("Uid:","Gid:")) and any(UID_FIRST<=int(value)<=UID_LAST for value in line.split()[1:]):
                    raise QAFailure("QA reserved UID/GID interval already has a live process")
        return {"local_account_tables_checked":True,"subordinate_id_tables_checked":True,
                "live_processes_checked":checked,"interval_unoccupied_at_install":True}

    def reserve_qa_interval(self) -> None:
        preflight=self.occupied_uid_preflight()
        root=Path("/run");st=root.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid!=0 or st.st_mode&0o022: raise QAFailure("unsafe QA reservation parent")
        claim=root/f"knowledge-qa-uid-reservation-{UID_FIRST}-{UID_LAST}"
        body=json.dumps({"schema":"ephemeral-admin-qa-uid-reservation.v1","run_id":self.plan["run_id"],
                         "first":UID_FIRST,"last":UID_LAST},sort_keys=True,separators=(",",":")).encode()
        fd=os.open(claim,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
        try:
            info=os.fstat(fd);self.uid_reservation=(claim,info.st_dev,info.st_ino,sha256(body))
            view=memoryview(body)
            while view:
                n=os.write(fd,view)
                if n<=0: raise QAFailure("short QA reservation write")
                view=view[n:]
            os.fsync(fd)
        finally: os.close(fd)
        self.record_pass("ephemeral_uid_reservation",{**preflight,"root_owned_exclusive_claim":True,
            "scope":"fixed interval on this ephemeral QA host only; not a production allocator"})

    def release_qa_interval(self) -> None:
        if self.uid_reservation is None:return
        if HELPER_UNCONFIRMED or self.unit_created or self.history_initializer_created or self.result.get("cleanup",{}).get("systemd_stop_error"):
            self.result.setdefault("cleanup",{})["uid_reservation"]="preserved_unconfirmed";return
        self.occupied_uid_preflight()
        claim,device,inode,digest=self.uid_reservation
        info,body=physical_file(claim,uid=0,maximum=4096)
        if (info.st_dev,info.st_ino)!=(device,inode) or sha256(body)!=digest:raise QAFailure("QA reservation identity changed")
        claim.unlink();self.uid_reservation=None
        self.result.setdefault("cleanup",{})["uid_reservation"]="removed_exact_owned_claim"

    def install_fresh(self) -> None:
        assert self.qa_root is not None and self.plan
        if self.qa_root.exists() or self.qa_root.is_symlink():
            raise QAFailure("unique root installation path already exists")
        os.mkdir(self.qa_root, 0o755)
        os.chown(self.qa_root, 0, 0); os.chmod(self.qa_root, 0o755)
        root_st = self.qa_root.lstat()
        if not stat.S_ISDIR(root_st.st_mode) or stat.S_ISLNK(root_st.st_mode) or root_st.st_uid != 0 or \
                stat.S_IMODE(root_st.st_mode) != 0o755 or root_st.st_nlink != 2:
            raise QAFailure("fresh service root is not exact root:root 0755 directory")
        self.root_inode = (root_st.st_dev, root_st.st_ino)
        self.install_created = True
        _, payload = physical_file(self.scratch / "service.static", uid=RUNNER_UID)
        if sha256(payload) != self.binary_hash:
            raise QAFailure("prepared binary changed before root install")
        destination = self.qa_root / "service"
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o755)
        try:
            os.fchown(fd, 0, 0); os.fchmod(fd, 0o755)
            view = memoryview(payload)
            while view:
                written = os.write(fd, view)
                if written <= 0: raise OSError("short installed-binary write")
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
        installed_st, installed = physical_file(destination, uid=0)
        if sha256(installed) != self.binary_hash or installed != payload or stat.S_IMODE(installed_st.st_mode) != 0o755 or \
                installed_st.st_mode & (stat.S_ISUID | stat.S_ISGID):
            raise QAFailure("installed service binary readback/hash/mode mismatch")
        if installed_st.st_mode & 0o022 or installed_st.st_nlink != 1:
            raise QAFailure("installed binary is caller/group/world writable or hardlinked")
        self.record_pass("fresh_root_install", {"root_mode": "0755", "binary_mode": "0755",
                         "binary_root_owned": True, "binary_not_setid": True, "binary_not_caller_writable": True,
                         "binary_readback_sha256": self.binary_hash, "binary_bytes": len(installed)})
        if self.history:
            for name in ('history-anchor', 'history-journal'):
                directory = self.qa_root / name
                directory.mkdir(mode=0o700)
                os.chown(directory, 0, 0)
                info = directory.lstat()
                self.history_directories[name] = (info.st_dev, info.st_ino)
            # Dispatch may time out after systemd accepted the request. Track
            # this separate native root actor BEFORE dispatch, so no cleanup
            # can unlink its installation while its exit is unconfirmed.
            self.history_initializer_created = True
            bounded_command('systemd-run-explicit-native-history-init',
                ['systemd-run', '--system', '--wait', '--collect', '--quiet',
                 f'--unit={self.unit}-initialize', '--property=RuntimeMaxSec=10',
                 '--property=TimeoutStopSec=5', '--', str(destination), '--initialize-history'],
                ADMIN_TIMEOUT, self.private, self.result)
            self.confirm_history_initializer_stopped()
            self.verify_native_history(0, False)
            self.record_pass('explicit_root_native_history_initialization',
                             {'journal_and_anchor_mode': '0700', 'auto_initialize_on_restart': False})

    def systemd_args(self) -> list[str]:
        assert self.unit and self.qa_root
        return ["systemd-run", "--system", "--no-block", f"--unit={self.unit}", "--service-type=exec",
                "--property=Delegate=yes", "--property=KillMode=control-group", "--property=ExitType=cgroup",
                "--property=RuntimeMaxSec=180", "--property=TimeoutStopSec=15", "--", str(self.qa_root / "service")]

    def start_first_service(self) -> dict[str, str]:
        assert self.unit and self.qa_root and self.service_cgroup
        # Mark the unique unit as possibly created before dispatch. If the
        # client times out after systemd accepted the request, finally must
        # still look up and stop this exact unit.
        self.unit_created = True
        bounded_command("systemd-run-initial", self.systemd_args(), ADMIN_TIMEOUT, self.private, self.result)
        deadline = time.monotonic() + 15
        values = {}
        while time.monotonic() < deadline:
            proc = bounded_command("systemctl-show-initial", ["systemctl", "show", "--no-pager", self.unit,
                "--property=MainPID", "--property=ControlGroup", "--property=ActiveState", "--property=ExitType", "--property=Delegate", "--property=KillMode"],
                ADMIN_TIMEOUT, self.private, self.result)
            values = parse_systemd_show(proc.stdout)
            if time.monotonic() <= deadline and values.get("ActiveState") == "active" and int(values.get("MainPID", "0")) > 0:
                break
            time.sleep(0.1)
        if time.monotonic() > deadline or values.get("ActiveState") != "active" or values.get("ControlGroup") != self.cgroup_rel or \
                values.get("ExitType") != "cgroup" or values.get("Delegate") != "yes" or \
                values.get("KillMode") != "control-group":
            raise QAFailure("transient system service did not retain required cgroup delegation/exit properties")
        cg_st = self.service_cgroup.lstat()
        if not stat.S_ISDIR(cg_st.st_mode) or stat.S_ISLNK(cg_st.st_mode) or cg_st.st_uid != 0 or \
                not (self.service_cgroup / "cgroup.procs").is_file() or not (self.service_cgroup / "cgroup.events").is_file():
            raise QAFailure("systemd ControlGroup did not resolve to the expected root-owned cgroup v2 directory")
        main_pid = int(values["MainPID"])
        process = process_stat(main_pid)
        if process["ppid"] != 1:
            raise QAFailure("system service main process is not a direct PID 1 child")
        status = read_bounded(Path(f"/proc/{main_pid}/status"), 65536, require_size_match=False).decode("ascii", "replace")
        uid_rows = [line for line in status.splitlines() if line.startswith("Uid:")]
        if uid_rows != ["Uid:\t0\t0\t0\t0"]:
            raise QAFailure("native broker main process is not root:root")
        self.service_main_pid = main_pid
        self.service_main_pidfd, self.service_main_identity = exact_pidfd(main_pid, self.cgroup_rel)
        self.record_pass("systemd_root_service", {"parent_pid_is_systemd": True, "delegate": True,
                         "kill_mode_control_group": True, "exit_type_cgroup": True,
                         "runtime_max_seconds": 180, "timeout_stop_seconds": 15})
        self.verify_installed_root_after_start()
        self.verify_socket()
        return values

    def verify_installed_root_after_start(self) -> None:
        assert self.qa_root and self.root_inode
        st = self.qa_root.lstat()
        if (st.st_dev, st.st_ino) != self.root_inode or st.st_uid != 0 or stat.S_IMODE(st.st_mode) != 0o755:
            raise QAFailure("service root inode/owner/mode changed after startup")
        st_bin, body = physical_file(self.qa_root / "service", uid=0)
        if sha256(body) != self.binary_hash or st_bin.st_mode & 0o022 or st_bin.st_mode & (stat.S_ISUID | stat.S_ISGID):
            raise QAFailure("running installation binary lost protected identity")

    def verify_socket(self) -> None:
        assert self.qa_root
        path = self.qa_root / "control.sock"
        st = path.lstat()
        if not stat.S_ISSOCK(st.st_mode) or st.st_uid != 0 or stat.S_IMODE(st.st_mode) != 0o666 or st.st_nlink != 1:
            raise QAFailure("public control socket mode/owner/type differs from the fixed contract")
        self.record_pass("public_socket_credentials_gate", {"socket_mode": "0666", "socket_root_owned": True,
                         "server_checks_scm_credentials_and_peer_pidfd": True})

    def hello(self) -> dict:
        assert self.qa_root
        actor = request_as_c(str(self.qa_root / "control.sock"), 1, b"\0" * 16)
        response = receive_json(actor)
        if response.get("protocol") != "knowledge-linux-service-qa.v1" or response.get("status") != "ready" or \
                response.get("broker_parent") != 1 or response.get("broker_pid") != self.service_main_pid or \
                response.get("attempts") != 0 or response.get("quarantine") is not False:
            raise QAFailure("service hello did not prove expected broker identity and fresh state")
        anchor = response.get("qa_anchor_pid")
        if type(anchor) is not int or anchor<=1 or process_stat(anchor)["ppid"]!=self.service_main_pid:
            raise QAFailure("QA observation anchor lacks exact broker parent")
        self.qa_anchor_pidfd,_=exact_pidfd(anchor,self.cgroup_rel or "")
        self.record_pass("protocol_hello_and_so_peerpidfd", {"request_bytes": REQUEST.size,
                         "broker_parent_pid1": True, "fresh_attempt_count": 0})
        return response

    def invalid_frames(self) -> None:
        assert self.qa_root
        sock = str(self.qa_root / "control.sock")
        valid = request_frame(4, b"malformed-frame!")
        cases = {
            "short": valid[:7],
            "oversized": valid + b"X",
            "bad_magic": struct.pack("<IIII16s", MAGIC ^ 1, VERSION, 4, ORDINAL, b"malformed-frame!"),
            "bad_version": struct.pack("<IIII16s", MAGIC, VERSION + 1, 4, ORDINAL, b"malformed-frame!"),
            "bad_ordinal": struct.pack("<IIII16s", MAGIC, VERSION, 4, 2, b"malformed-frame!"),
            "bad_operation": struct.pack("<IIII16s", MAGIC, VERSION, 9, ORDINAL, b"malformed-frame!"),
        }
        for name, payload in cases.items():
            self.result.setdefault("checks", {}).setdefault("malformed_frames", {})[name] = validate_request_denied(sock, payload)
        right = validate_request_denied(sock, request_frame(4, b"malformed-frame!"), send_right=True)
        self.result["checks"]["scm_rights_denied"] = {"status": "PASS", **right}
        self.record_pass("malformed_and_scm_rights_denied", {"malformed_frames_denied": len(cases), "scm_rights_denied": True})

    def start_scope(self, sequence: int) -> tuple[bytes, dict, dict]:
        assert self.qa_root
        nonce = os.urandom(16)
        actor = request_as_c(str(self.qa_root / "control.sock"), 2, nonce, hold=True)
        self.active_actors.append(actor)
        if pidfd_ready(actor["pidfd"]):
            raise QAFailure("persistent C START caller exited before its service pidfd was exercised")
        first = receive_json(actor)
        if first.get("status") != "starting" or first.get("sequence") != sequence:
            raise QAFailure(f"scope {sequence} was not admitted as the expected sequence")
        last, _ = poll_response(str(self.qa_root / "control.sock"), nonce,
                                lambda row: row.get("status") == "running" and row.get("output_bytes", 0) > 0,
                                START_TIMEOUT, "worker output readiness")
        self.validate_running_status(last, sequence)
        return nonce, actor, last

    def validate_running_status(self, value: dict, sequence: int) -> dict:
        expected_authority = UID_FIRST + 2 * (sequence - 1)
        expected_worker = expected_authority + 1
        if value.get("status") != "running" or value.get("sequence") != sequence or \
                value.get("authority_uid") != expected_authority or value.get("worker_uid") != expected_worker or \
                value.get("worker_memory_denied") is not True or value.get("output_bytes", 0) <= 0 or value.get("output_eof") is not False:
            raise QAFailure(f"scope {sequence} did not report A/W credential gate and live worker output")
        if min(value.get("keeper_pid", 0), value.get("init_pid", 0), value.get("authority_pid", 0), value.get("worker_pid", 0)) <= 0:
            raise QAFailure("scope status omitted a live actor PID")
        assert self.cgroup_rel
        attempt_group = f"{self.cgroup_rel}/attempt-{sequence}"
        members_path = Path("/sys/fs/cgroup") / attempt_group.lstrip("/") / "cgroup.procs"
        members = {int(row) for row in read_bounded(members_path, 65536, require_size_match=False).decode("ascii").split() if row.isdigit()}
        actor_ids = {"keeper": value["keeper_pid"], "init": value["init_pid"],
                     "authority": value["authority_pid"], "worker": value["worker_pid"]}
        pidfds = {}
        identities = {}
        for name, pid in actor_ids.items():
            if pid not in members:
                raise QAFailure(f"{name} was not a member of its attempt cgroup")
            fd, identity = exact_pidfd(pid, attempt_group)
            pidfds[name] = fd; identities[name] = identity
        self.result.setdefault("_pidfds", {})[sequence] = pidfds
        for name,expected in (("authority",expected_authority),("worker",expected_worker)):
            pid=actor_ids[name]
            status=read_bounded(Path(f"/proc/{pid}/status"),65536,require_size_match=False).decode("ascii")
            fields={line.split(":",1)[0]:line.split(":",1)[1].strip() for line in status.splitlines() if ":" in line}
            after=process_stat(pid)
            if any(fields.get(key,"").split()!=[str(expected)]*4 for key in ("Uid","Gid")) or fields.get("Groups")!="" or \
                    fields.get("NoNewPrivs")!="1" or any(int(fields.get(key,"-1"),16)!=0 for key in ("CapInh","CapPrm","CapEff","CapAmb")) or \
                    (after['ppid'],after['starttime'])!=(identities[name]['ppid'],identities[name]['starttime_ticks']) or pidfd_ready(pidfds[name]):
                raise QAFailure("independent A/W credential, capability or birth verification failed")
        self.record_pass(f"scope_{sequence}_independent_credentials",{
            "real_effective_saved_fs_ids_match":True,"supplementary_groups_empty":True,
            "effective_permitted_inheritable_ambient_caps_zero":True,"no_new_privileges":True,
            "birth_and_pidfd_rechecked":True})
        self.result.setdefault("private_runtime", {}).setdefault("scope_identities", {})[str(sequence)] = identities
        self.result.setdefault("_pidfds", {})[sequence] = pidfds
        return {"attempt_cgroup": attempt_group, "actor_members_confirmed": True,
                "worker_memory_denied": True, "worker_output_observed": True,
                "authority_uid": expected_authority, "worker_uid": expected_worker}

    def run_memory_negatives(self, scope_status: dict) -> None:
        pid = scope_status["authority_pid"]
        addr = scope_status["authority_address"]
        authority_fd_number = scope_status["authority_fd"]
        target_fd = self.result["_pidfds"][1]["authority"]
        runner_gid = int(os.environ.get("SUDO_GID", "1001"))
        per_caller = {}
        for name, uid, gid in (("C", RUNNER_UID, runner_gid), ("W", UID_FIRST + 1, UID_FIRST + 1)):
            per_caller[name] = memory_probe(uid, gid, pid, addr, authority_fd_number, target_fd)
        self.result["checks"]["memory_fd_negative_cases"] = per_caller
        self.record_pass("per_caller_memory_fd_denials", {"callers": ["C", "W"], "cases_per_caller": 6})

    def stop_scope(self, sequence: int, nonce: bytes, stop_reason: int, timeout: int = NORMAL_CLOSE_TIMEOUT) -> dict:
        assert self.qa_root
        actor = request_as_c(str(self.qa_root / "control.sock"), 3, nonce)
        response = receive_json(actor)
        if response.get("status") not in {"running", "closed"}:
            raise QAFailure("STOP request was denied")
        last, _ = poll_response(str(self.qa_root / "control.sock"), nonce,
                                lambda row: row.get("status") == "closed", timeout, "native scope closure")
        pidfds = self.result["_pidfds"][sequence]
        deadline = time.monotonic() + 12
        for key in ("init", "keeper"):
            if not pidfd_ready(pidfds[key]):
                wait_pidfd(pidfds[key], max(0, deadline - time.monotonic()))
        external = {"init_pidfd_exited": pidfd_ready(pidfds["init"]),
                    "keeper_pidfd_exited": pidfd_ready(pidfds["keeper"])}
        assert self.service_cgroup
        events = read_cgroup_events(self.service_cgroup / f"attempt-{sequence}")
        if not all(external.values()) or events.get("populated") != 0 or last.get("stop_reason") != stop_reason or \
                last.get("init_exit_confirmed") is not True or last.get("keeper_exit_confirmed") is not True or \
                last.get("cgroup_empty") is not True or last.get("output_eof") is not True or last.get("output_bytes", 0) <= 0:
            raise QAFailure(f"scope {sequence} lacked product/native stop proof or exact external closure evidence")
        release_actor(self.active_actors[-1])
        self.record_pass(f"scope_{sequence}_native_close", {"stop_reason": stop_reason,
                         "output_eof": True, "output_bytes_observed": True,
                         "init_exit_confirmed": True, "keeper_exit_confirmed": True,
                         "cgroup_populated": 0, **external})
        return last

    def replay_closed_stop(self, old_nonce: bytes, old_status: dict,
                           current_nonce: bytes, current_status: dict) -> None:
        assert self.qa_root
        old_slot, new_slot = old_status.get("qa_channel_slot"), current_status.get("qa_channel_slot")
        if type(old_slot) is not int or old_slot < 0 or old_slot != new_slot:
            raise QAFailure("STOP replay regression requires actual numeric channel FD reuse")
        before = current_status["output_bytes"]
        reply = receive_json(request_as_c(str(self.qa_root / "control.sock"), 3, old_nonce))
        if reply.get("status") != "closed" or reply.get("sequence") != 1:
            raise QAFailure("old STOP did not remain bound to the closed old attempt")
        after, _ = poll_response(str(self.qa_root / "control.sock"), current_nonce,
            lambda row: row.get("status") == "running" and row.get("output_bytes", 0) > before + 384,
            3, "current worker continuing after old STOP with reused numeric channel FD")
        if after.get("sequence") != 2 or after.get("stop_reason") != 0 or any(
                pidfd_ready(fd) for fd in self.result["_pidfds"][2].values()):
            raise QAFailure("old STOP affected the newer active attempt")
        self.record_pass("old_stop_after_numeric_fd_reuse", {
            "numeric_channel_fd_reused": True, "old_attempt_stayed_closed": True,
            "new_attempt_alive_and_output_advancing": True, "no_new_stop_reason": True})

    def stop_broker_paused_scope(self, sequence: int, nonce: bytes, status: dict) -> dict:
        assert self.service_main_pidfd is not None and self.service_main_pid is not None and self.service_cgroup
        mainfd, identity = exact_pidfd(self.service_main_pid, self.cgroup_rel or "")
        if identity["ppid"] != 1:
            os.close(mainfd); raise QAFailure("broker no longer has systemd PID 1 as parent")
        self.resume_fd = mainfd
        pidfds = self.result["_pidfds"][sequence]
        group_path = self.service_cgroup / f"attempt-{sequence}"
        signal_pidfd(mainfd, signal.SIGSTOP)
        self.result["checks"]["scope_2_broker_pause"] = {"status": "RUNNING_NATIVE_WAIT"}
        self.save_public()
        deadline = time.monotonic() + (WORK_MS + CLEANUP_MS) / 1000 + 8
        while time.monotonic() < deadline:
            if pidfd_ready(mainfd):
                raise QAFailure("SIGSTOP broker exited instead of remaining paused")
            if pidfd_ready(pidfds["init"]) and pidfd_ready(pidfds["keeper"]):
                events = read_cgroup_events(group_path)
                if time.monotonic() <= deadline and events.get("populated") == 0:
                    break
            time.sleep(0.1)
        else:
            raise QAFailure("independent keeper did not complete the 15s+10s work/cleanup while broker was SIGSTOP")
        root_observation = {"exact_init_pidfd_exited": pidfd_ready(pidfds["init"]),
                            "exact_keeper_pidfd_exited": pidfd_ready(pidfds["keeper"]),
                            "root_read_cgroup_populated": read_cgroup_events(group_path).get("populated")}
        if time.monotonic() > deadline or not all((root_observation["exact_init_pidfd_exited"], root_observation["exact_keeper_pidfd_exited"])) or \
                root_observation["root_read_cgroup_populated"] != 0:
            raise QAFailure("root external observation did not confirm init/keeper exact pidfds and empty cgroup during broker pause")
        signal_pidfd(mainfd, signal.SIGCONT)
        self.resume_fd = None
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and pidfd_ready(mainfd):
            time.sleep(0.02)
        if pidfd_ready(mainfd):
            raise QAFailure("broker did not resume as the same exact process after SIGCONT")
        last, _ = poll_response(str(self.qa_root / "control.sock"), nonce,
                                lambda row: row.get("status") == "closed" and row.get("output_eof") is True,
                                8, "broker-observed paused-scope close")
        if last.get("stop_reason") != 3 or last.get("init_exit_confirmed") is not True or \
                last.get("keeper_exit_confirmed") is not True or last.get("cgroup_empty") is not True or \
                last.get("output_bytes", 0) <= 0:
            raise QAFailure("resumed broker did not publish exact watchdog timeout closure")
        release_actor(self.active_actors[-1])
        os.close(mainfd)
        self.result["checks"]["scope_2_broker_pause"] = {"status": "COMPLETED", "terminal_check": "scope_2_sigstop_independent_keeper"}
        self.record_pass("scope_2_sigstop_independent_keeper", {"work_budget_ms": WORK_MS,
                         "cleanup_budget_ms": CLEANUP_MS, "broker_paused_by_pidfd": True,
                         "root_observed_before_sigcont": root_observation,
                         "resumed_broker_stop_reason": 3, "output_eof": True,
                         "qa_native_proof": True})
        return last

    def caller_death_scope(self, sequence: int = 3) -> dict:
        assert self.qa_root
        nonce = os.urandom(16)
        actor = request_as_c(str(self.qa_root / "control.sock"), 2, nonce, hold=True)
        self.active_actors.append(actor)
        start = receive_json(actor)
        if start.get("status") != "starting" or start.get("sequence") != sequence:
            raise QAFailure("caller-death scope was not admitted at expected ordinal")
        running, _ = poll_response(str(self.qa_root / "control.sock"), nonce,
                                   lambda row: row.get("status") == "running" and row.get("output_bytes", 0) > 0,
                                   START_TIMEOUT, "caller-death scope worker readiness")
        self.validate_running_status(running, sequence)
        # Closing the exact C caller process is the action under test. The
        # service retains SO_PEERPIDFD from that request frame.
        release_actor(actor)
        last, _ = poll_response(str(self.qa_root / "control.sock"), nonce,
                                lambda row: row.get("status") == "closed", CALLER_DEATH_TIMEOUT,
                                "keeper stop after caller pidfd exits")
        pidfds = self.result["_pidfds"][sequence]
        if last.get("stop_reason") != 6 or last.get("output_eof") is not True or \
                last.get("init_exit_confirmed") is not True or last.get("keeper_exit_confirmed") is not True or \
                last.get("cgroup_empty") is not True or last.get("worker_memory_denied") is not True or \
                not pidfd_ready(pidfds["init"]) or not pidfd_ready(pidfds["keeper"]):
            raise QAFailure("caller-death scope did not report stop_reason=6 and complete native closure")
        self.record_pass("scope_3_caller_pidfd_death", {"stop_reason": 6, "caller_uid": RUNNER_UID,
                         "worker_output_observed": last.get("output_bytes", 0) > 0,
                         "output_eof": True, "init_exit_confirmed": True,
                         "keeper_exit_confirmed": True, "cgroup_empty": True})
        return last

    def crash_broker_scope(self, sequence: int = 4) -> dict:
        assert self.qa_root and self.service_cgroup and self.service_main_pid is not None
        nonce, actor, status = self.start_scope(sequence)
        pidfds = self.result["_pidfds"][sequence]
        mainfd, identity = exact_pidfd(self.service_main_pid, self.cgroup_rel or "")
        if identity["ppid"] != 1:
            os.close(mainfd); raise QAFailure("crash target was not exact PID 1 child")
        signal_pidfd(mainfd, signal.SIGKILL)
        if not wait_pidfd(mainfd, 5):
            raise QAFailure("exact pidfd SIGKILL did not terminate owned broker")
        deadline = time.monotonic() + CRASH_CLOSE_TIMEOUT
        events = {"populated": -1}
        while time.monotonic() < deadline:
            if pidfd_ready(pidfds["init"]) and pidfd_ready(pidfds["keeper"]):
                try:
                    events = read_cgroup_events(self.service_cgroup / f"attempt-{sequence}")
                except FileNotFoundError:
                    events = {"populated": -1}
                if time.monotonic() <= deadline and events.get("populated") == 0:
                    break
            time.sleep(0.1)
        external = {"broker_exact_pidfd_exited": pidfd_ready(mainfd),
                    "init_exact_pidfd_exited": pidfd_ready(pidfds["init"]),
                    "keeper_exact_pidfd_exited": pidfd_ready(pidfds["keeper"]),
                    "root_read_attempt_cgroup_populated": events.get("populated", -1)}
        os.close(mainfd)
        release_actor(actor)
        if time.monotonic() > deadline or not all((external["broker_exact_pidfd_exited"], external["init_exact_pidfd_exited"],
                    external["keeper_exact_pidfd_exited"])) or external["root_read_attempt_cgroup_populated"] != 0:
            raise QAFailure("broker-crash external root cleanup observation incomplete")
        observed = {"status": "OBSERVED_ONLY_NOT_PRODUCT_PASS",
                    "product_native_proof": "UNAVAILABLE_AFTER_BROKER_CRASH; no API status/receipt exists",
                    "external_root_observation": external,
                    "systemd_exit_type_cgroup": True,
                    "keeper_and_init_exact_pidfds_opened_before_signal": True}
        self.record_observation("scope_4_broker_crash", {
            "product_native_proof": observed["product_native_proof"],
            "external_root_observation": external,
            "systemd_exit_type_cgroup": True,
            "keeper_and_init_exact_pidfds_opened_before_signal": True,
        })
        if self.qa_anchor_pidfd is None or pidfd_ready(self.qa_anchor_pidfd):
            raise QAFailure("QA observation anchor did not survive until empty-cgroup observation")
        signal_pidfd(self.qa_anchor_pidfd,signal.SIGKILL)
        if not select.select([self.qa_anchor_pidfd],[],[],5)[0]:
            raise QAFailure("QA observation anchor exit unconfirmed")
        os.close(self.qa_anchor_pidfd);self.qa_anchor_pidfd=None
        self.restart_same_installation_quarantine()
        return observed

    def restart_same_installation_quarantine(self) -> None:
        assert self.unit and self.qa_root and self.root_inode
        old_main_pidfd = self.service_main_pidfd
        if old_main_pidfd is None or not pidfd_ready(old_main_pidfd):
            raise QAFailure("crashed broker exact pidfd was not ready before same-installation restart")
        # Keep the installation/burn history, but do not rely on retention of
        # an inactive transient unit definition after manager GC.
        self.stop_owned_unit()
        bounded_command("systemctl-reset-failed-before-restart", ["systemctl", "reset-failed", self.unit],
                        ADMIN_TIMEOUT, self.private, self.result, expected={0,1})
        gc_deadline=time.monotonic()+10
        while True:
            state=bounded_command("systemctl-transient-gc",["systemctl","show","--no-pager",self.unit,"--property=LoadState"],
                                  ADMIN_TIMEOUT,self.private,self.result,expected={0,1})
            if parse_systemd_show(state.stdout).get("LoadState")=="not-found":break
            if time.monotonic()>=gc_deadline:raise QAFailure("old transient unit definition not collected")
            time.sleep(.1)
        self.unit_created=True
        bounded_command("systemd-run-same-installation",self.systemd_args(),
                        ADMIN_TIMEOUT,self.private,self.result)
        deadline = time.monotonic() + 15
        values = {}
        while time.monotonic() < deadline:
            proc = bounded_command("systemctl-show-restarted", ["systemctl", "show", "--no-pager", self.unit,
                "--property=MainPID", "--property=ControlGroup", "--property=ActiveState", "--property=ExitType", "--property=Delegate", "--property=KillMode"],
                ADMIN_TIMEOUT, self.private, self.result)
            values = parse_systemd_show(proc.stdout)
            if time.monotonic() <= deadline and values.get("ActiveState") == "active" and int(values.get("MainPID", "0")) > 0:
                break
            time.sleep(0.1)
        new_pid = int(values.get("MainPID", "0"))
        if time.monotonic() > deadline or values.get("ActiveState") != "active" or values.get("ControlGroup") != self.cgroup_rel or \
                values.get("ExitType") != "cgroup" or values.get("Delegate") != "yes" or \
                values.get("KillMode") != "control-group" or new_pid <= 0:
            raise QAFailure("same systemd installation did not restart as a distinct PID")
        main = process_stat(new_pid)
        if main["ppid"] != 1:
            raise QAFailure("restarted broker is not a direct systemd PID 1 child")
        new_main_pidfd, new_identity = exact_pidfd(new_pid, self.cgroup_rel or "")
        if new_main_pidfd == old_main_pidfd or pidfd_ready(new_main_pidfd):
            os.close(new_main_pidfd)
            raise QAFailure("restart did not produce a fresh live exact broker process")
        self.service_main_pid = new_pid
        self.service_main_pidfd, self.service_main_identity = new_main_pidfd, new_identity
        try: os.close(old_main_pidfd)
        except OSError: pass
        hello = request_as_c(str(self.qa_root / "control.sock"), 1, b"\0" * 16)
        ready = receive_json(hello)
        if ready.get("status") != "ready" or ready.get("quarantine") is not True or ready.get("attempts") != 0 or \
                ready.get("broker_pid") != new_pid or ready.get("broker_parent") != 1:
            raise QAFailure("service restart did not expose quarantine state for prior UID burn history")
        denied = request_as_c(str(self.qa_root / "control.sock"), 2, os.urandom(16))
        response = receive_json(denied)
        if response.get("status") != "unavailable" or response.get("quarantine") is not True or response.get("attempts") != 0:
            raise QAFailure("restarted service did not deny START in quarantined state")
        records = self.verify_uid_burn_history()
        self.verify_installed_root_after_start()
        self.record_pass("same_installation_restart_quarantine", {"new_broker_pid_distinct": True,
                         "start_denied": True, "attempt_count_after_restart": 0,
                         "uid_burn_records": records, "uid_reuse": False})

    def restart_closed_history(self) -> None:
        assert self.history and self.unit and self.qa_root
        self.verify_native_history(1, False)
        old_pid = self.service_main_pid
        self.stop_owned_unit()
        if self.service_main_pidfd is None or not pidfd_ready(self.service_main_pidfd):
            raise QAFailure('closed-history restart lacks exact old broker exit')
        os.close(self.service_main_pidfd)
        self.service_main_pidfd = None
        if self.qa_anchor_pidfd is not None:
            if not pidfd_ready(self.qa_anchor_pidfd):
                raise QAFailure('closed-history restart lacks exact old QA anchor exit')
            os.close(self.qa_anchor_pidfd)
            self.qa_anchor_pidfd = None
        deadline = time.monotonic() + 10
        while True:
            state = bounded_command('systemctl-closed-history-gc',
                ['systemctl', 'show', '--no-pager', self.unit, '--property=LoadState'],
                ADMIN_TIMEOUT, self.private, self.result, expected={0, 1})
            if parse_systemd_show(state.stdout).get('LoadState') == 'not-found':
                break
            if time.monotonic() >= deadline:
                raise QAFailure('closed-history transient unit definition not collected')
            time.sleep(.1)
        self.start_first_service()
        self.hello()
        if self.service_main_pid == old_pid:
            raise QAFailure('restart did not produce a distinct broker process')
        self.verify_native_history(1, False)
        self.record_pass('closed_history_restart_retains_allocation',
                         {'durable_allocations': 1, 'new_broker_pid': True, 'next_pair_required': True})

    def verify_native_history(self, allocations: int, pending: bool) -> list[dict]:
        assert self.qa_root
        anchor, directory = self.qa_root / 'history-anchor', self.qa_root / 'history-journal'
        for name, location in (('history-anchor', anchor), ('history-journal', directory)):
            info = location.lstat()
            if (info.st_dev, info.st_ino) != self.history_directories[name] or info.st_uid != 0 or \
                    stat.S_IMODE(info.st_mode) != 0o700 or not stat.S_ISDIR(info.st_mode):
                raise QAFailure('native history directory identity/mode changed')
        read = lambda location: physical_file(location, uid=0, maximum=256 * 16)
        marker_info, marker = read(anchor / 'marker')
        head_info, head = read(anchor / 'head')
        journal_info, journal = read(directory / 'journal')
        lock_info, lock = read(directory / 'lock')
        for info in (marker_info, head_info, journal_info, lock_info):
            if stat.S_IMODE(info.st_mode) != 0o600:
                raise QAFailure('native history file protection differs from root0600')
        if lock or len(marker) != 256 or len(head) != 256 or not journal or len(journal) % 256:
            raise QAFailure('native history fixed record lengths invalid')
        records = [journal[offset:offset+256] for offset in range(0, len(journal), 256)]
        if records[0] != marker or records[-1] != head:
            raise QAFailure('native history marker/head do not match full journal')
        if struct.unpack_from('<QQQQQ', marker, 184) != \
                (journal_info.st_dev, journal_info.st_ino, lock_info.st_dev, lock_info.st_ino, 1):
            raise QAFailure('native history does not bind protected journal/lock inodes')
        found, active, nonces, rows = 0, None, set(), []
        for index, record in enumerate(records):
            kind, version = struct.unpack_from('<II', record, 8)
            seq, allocation = struct.unpack_from('<QQ', record, 16)
            authority, worker = struct.unpack_from('<II', record, 32)
            if record[:8] != b'KVLH001\0' or version != 1 or seq != index or \
                    hashlib.sha256(record[:224]).digest() != record[224:]:
                raise QAFailure('independent native history chain verification failed')
            if not index:
                if kind != 1 or authority != UID_FIRST or worker != UID_LAST:
                    raise QAFailure('native history genesis range mismatch')
                continue
            if record[152:184] != records[index-1][224:] or record[40:72] != marker[40:72] or any(record[184:224]):
                raise QAFailure('native history chain, epoch or reserved bytes mismatch')
            binding = (allocation, authority, worker, record[72:120])
            if kind == 2:
                found += 1
                if active is not None or allocation != found or authority != UID_FIRST + (found-1)*2 or \
                        worker != authority+1 or record[88:120] in nonces or any(record[120:152]):
                    raise QAFailure('native allocation duplicated or pair sequence changed')
                nonces.add(record[88:120]); active = binding
                rows.append({'sequence': allocation, 'authority_uid': authority, 'worker_uid': worker,
                             'record_sha256': sha256(record), 'mode': '0600'})
            elif kind == 3:
                if active != binding or not any(record[120:152]):
                    raise QAFailure('native closure did not match its pending burn')
                active = None
            else:
                raise QAFailure('unexpected native history record kind')
        if found != allocations or (active is not None) != pending:
            raise QAFailure('native history pending/allocation state differs from real lifecycle')
        self.result.setdefault('native_history_checkpoints', []).append({
            'allocations': found, 'pending_cleanup': active is not None,
            'records': len(records)-1, 'journal_sha256': sha256(journal),
            'head_sha256': sha256(head), 'marker_sha256': sha256(marker),
            'journal_inode': str(journal_info.st_ino), 'lock_inode': str(lock_info.st_ino),
            'independent_sha256_replay': True})
        # Preserve exact bytes alongside public facts; this is an ephemeral QA
        # installation. Production history has no deletion/reset operation.
        for name, body in (('marker', marker), ('head', head), ('journal', journal)):
            evidence = self.public / f'history-{allocations}-{int(pending)}-{name}.bin'
            evidence.write_bytes(body); evidence.chmod(0o644)
        return rows

    def verify_uid_burn_history(self) -> list[dict]:
        assert self.qa_root
        if self.history:
            return self.verify_native_history(4, True)
        records = []
        for sequence in range(1, 5):
            path = self.qa_root / f"uid-burn-{sequence}"
            st, body = physical_file(path, uid=0, maximum=64)
            if stat.S_IMODE(st.st_mode) != 0o600 or len(body) != 24:
                raise QAFailure("UID burn record has unsafe mode or unexpected size")
            nonce, authority, worker = struct.unpack("<16sII", body)
            expected_a = UID_FIRST + (sequence - 1) * 2
            if authority != expected_a or worker != expected_a + 1:
                raise QAFailure("burned UID interval was reused, skipped, or widened")
            records.append({"sequence": sequence, "authority_uid": authority, "worker_uid": worker,
                            "record_sha256": sha256(body), "mode": "0600"})
        for path in (self.qa_root / f"uid-burn-{i}" for i in (5,)):
            if path.exists() or path.is_symlink():
                raise QAFailure("quarantined restart allocated a UID beyond the four-attempt interval")
        return records

    def stop_owned_unit(self) -> None:
        if self.history_initializer_created:
            assert self.unit
            bounded_command('systemctl-stop-history-initializer',
                            ['systemctl', 'stop', self.unit + '-initialize'],
                            ADMIN_TIMEOUT, self.private, self.result, expected={0, 5})
            self.confirm_history_initializer_stopped()
        if not self.unit or not self.unit_created:
            return
        if self.resume_fd is not None:
            try:
                signal_pidfd(self.resume_fd, signal.SIGCONT)
                os.close(self.resume_fd)
            except OSError:
                pass
            self.resume_fd = None
        proc = bounded_command("systemctl-stop-owned-unit", ["systemctl", "stop", self.unit],
                               ADMIN_TIMEOUT, self.private, self.result, expected={0, 5})
        self.result.setdefault("cleanup", {})["systemd_stop_exit_code"] = proc.returncode
        state = bounded_command("systemctl-show-after-stop", ["systemctl", "show", "--no-pager", self.unit,
            "--property=LoadState", "--property=MainPID", "--property=ActiveState", "--property=ControlGroup"],
            ADMIN_TIMEOUT, self.private, self.result)
        values = parse_systemd_show(state.stdout)
        if values.get("LoadState") == "not-found":
            if self.service_cgroup is not None and self.service_cgroup.exists():
                events = read_cgroup_events(self.service_cgroup)
                if events.get("populated") != 0:
                    raise QAFailure("exact owned unit is absent but its cgroup still has processes")
            self.unit_created = False
            self.result.setdefault("cleanup", {})["systemd_unit"] = "not_found_after_bounded_lookup"
            return
        if values.get("LoadState") != "loaded":
            raise QAFailure("exact systemd unit lookup did not prove a known unit state")
        if values.get("ControlGroup") not in {None, "", self.cgroup_rel}:
            raise QAFailure("exact unit lookup resolved to a different ControlGroup")
        if values.get("ActiveState") == "active" or int(values.get("MainPID", "0")) != 0:
            raise QAFailure("owned systemd unit still has a live MainPID after bounded stop")
        if self.service_cgroup is not None and self.service_cgroup.exists():
            events = read_cgroup_events(self.service_cgroup)
            if events.get("populated") != 0:
                raise QAFailure("owned service cgroup was not empty after bounded systemd stop")
        self.unit_created = False

    def confirm_history_initializer_stopped(self) -> None:
        if not self.history_initializer_created:
            return
        assert self.unit
        name = self.unit + '-initialize'
        observed = bounded_command('systemctl-show-history-initializer',
            ['systemctl', 'show', '--no-pager', name, '--property=LoadState',
             '--property=ActiveState', '--property=MainPID', '--property=ControlGroup'],
            ADMIN_TIMEOUT, self.private, self.result, expected={0, 1})
        value = parse_systemd_show(observed.stdout)
        expected_group = '/system.slice/' + name + '.service'
        if value.get('LoadState') == 'not-found':
            pass
        elif value.get('LoadState') == 'loaded' and value.get('ActiveState') in {'inactive', 'failed'} and \
                value.get('MainPID') == '0' and value.get('ControlGroup') in {'', expected_group}:
            pass
        else:
            raise QAFailure('native history initializer exit remains unconfirmed')
        group = Path('/sys/fs/cgroup') / expected_group.lstrip('/')
        if group.exists() and read_cgroup_events(group).get('populated') != 0:
            raise QAFailure('native history initializer cgroup remains populated')
        self.history_initializer_created = False
        self.result.setdefault('cleanup', {})['history_initializer'] = 'confirmed_stopped_or_absent'

    def cleanup_installation(self) -> None:
        if HELPER_UNCONFIRMED:
            self.result.setdefault("cleanup", {})["installation"] = "preserved_quarantine_fixture_exact_child_unconfirmed"
            return
        if self.unit_created or self.history_initializer_created or "systemd_stop_error" in self.result.get("cleanup", {}):
            self.result.setdefault("cleanup", {})["installation"] = "preserved_quarantine_fixture_unit_cleanup_unconfirmed"
            return
        if not self.install_created or self.qa_root is None or self.root_inode is None:
            self.result.setdefault("cleanup", {})["installation"] = "not_created"
            return
        if self.uid_reservation is not None:
            # Preserve the binary/history too if an exact helper failed to
            # report its exit or an unexpected UID consumer remains.
            self.occupied_uid_preflight()
        st = self.qa_root.lstat()
        if (st.st_dev, st.st_ino) != self.root_inode or st.st_uid != 0 or stat.S_IMODE(st.st_mode) != 0o755:
            raise QAFailure("refusing to clean an installation path whose inode/owner/mode changed")
        if self.history:
            for name, allowed_files in (('history-anchor', {'marker', 'head'}), ('history-journal', {'lock', 'journal'})):
                directory = self.qa_root / name
                info = directory.lstat()
                if (info.st_dev, info.st_ino) != self.history_directories.get(name) or info.st_uid != 0 or \
                        stat.S_IMODE(info.st_mode) != 0o700 or not stat.S_ISDIR(info.st_mode):
                    raise QAFailure('owned history directory identity changed before QA cleanup')
                if not set(os.listdir(directory)).issubset(allowed_files):
                    raise QAFailure('unexpected history file; preserve incomplete QA fixture')
                for child in directory.iterdir():
                    item, _ = physical_file(child, uid=0, maximum=256*16)
                    if stat.S_IMODE(item.st_mode) != 0o600:
                        raise QAFailure('history file mode changed before QA cleanup')
                    child.unlink()
                directory.rmdir()
        allowed = {"service", "control.sock", *(f"uid-burn-{i}" for i in range(1, 5))}
        names = set(os.listdir(self.qa_root))
        if not names.issubset(allowed):
            raise QAFailure("installation contains an unexpected file; refusing cleanup")
        for name in sorted(names, reverse=True):
            path = self.qa_root / name
            item = path.lstat()
            if item.st_uid != 0 or item.st_nlink != 1 or stat.S_ISLNK(item.st_mode):
                raise QAFailure("owned cleanup entry changed identity")
            if name == "control.sock" and not stat.S_ISSOCK(item.st_mode):
                raise QAFailure("control.sock changed type")
            if name != "control.sock" and not stat.S_ISREG(item.st_mode):
                raise QAFailure("owned installation file changed type")
            path.unlink()
        os.rmdir(self.qa_root)
        if self.qa_root.exists() or self.qa_root.is_symlink():
            raise QAFailure("owned installation root remained after exact cleanup")
        self.install_created = False
        self.result.setdefault("cleanup", {})["installation"] = "removed_exact_owned_root"

    def close_pidfds(self) -> None:
        for actor in self.active_actors:
            try: release_actor(actor)
            except Exception: pass
        for values in self.result.pop("_pidfds", {}).values():
            for fd in values.values():
                try: os.close(fd)
                except OSError: pass
        for name in ("service_main_pidfd", "resume_fd", "qa_anchor_pidfd"):
            fd = getattr(self, name, None)
            if fd is not None:
                try: os.close(fd)
                except OSError: pass
                setattr(self, name, None)

    def run_all(self) -> int:
        completed_all_checks = False
        self.save_public()
        try:
            self.load_plan()
            self.save_public()
            self.snap_before = self.snapshot_host_policy()
            self.result["host_policy_before"] = self.snap_before
            self.verify_system_ready()
            self.reserve_qa_interval()
            self.install_fresh()
            self.start_first_service()
            self.hello()
            self.invalid_frames()

            nonce1, actor1, status1 = self.start_scope(1)
            harness_control = root_harness_positive_fixture()
            authority_control = root_positive_authority_control(
                status1["authority_pid"], status1["authority_address"], status1["authority_fd"])
            self.result["checks"]["root_positive_controls"] = {
                "harness_fixture": harness_control,
                "service_authority": authority_control,
            }
            self.record_pass("root_positive_canary_controls", {
                "harness_fixture_readable": True,
                "service_authority_canary_readable": True,
                "service_authority_memfd_readable": True,
                "authority_fd_zero_valid": status1["authority_fd"] == 0,
            })
            self.run_memory_negatives(status1)
            delegation = pass_exact_fd_to_worker(str(self.qa_root / "control.sock"), nonce1, UID_FIRST + 1)
            if delegation.get("status") != "denied":
                raise QAFailure("delegated C socket frame from W was not denied")
            self.record_pass("caller_socket_fd_delegation", delegation)
            same_uid = pass_exact_fd_to_worker(str(self.qa_root / "control.sock"), nonce1, RUNNER_UID)
            self.record_pass("same_uid_different_pid_socket_delegation", same_uid)
            self.stop_scope(1, nonce1, 1)
            if self.history:
                self.verify_native_history(1, False)
                self.restart_closed_history()

            nonce2, actor2, status2 = self.start_scope(2)
            if self.history:
                stale = receive_json(request_as_c(str(self.qa_root / 'control.sock'), 3, nonce1))
                if stale.get('status') != 'unavailable':
                    raise QAFailure('old daemon nonce was accepted as current live attempt')
                self.record_pass('new_daemon_next_uid_pair', {
                    'authority_uid': status2['authority_uid'], 'worker_uid': status2['worker_uid'],
                    'old_nonce_stop_rejected': True, 'uid_reuse': False})
            else:
                self.replay_closed_stop(nonce1, status1, nonce2, status2)
            self.stop_broker_paused_scope(2, nonce2, status2)

            self.caller_death_scope(3)

            self.crash_broker_scope(4)
            self.record_pass("four_attempt_uid_interval", {"max_attempts": 4,
                             "uid_first": UID_FIRST, "uid_last": UID_LAST,
                             "exact_burn_records": 4, "uids_reused": False})
            completed_all_checks = True
        except BaseException as exc:
            self.result["error"] = {"type": type(exc).__name__, "message": str(exc)[:500]}
            if isinstance(exc, QAFailure) and hasattr(exc, "native_observation"):
                self.result["error"]["native_observation"] = exc.native_observation
        finally:
            try:
                self.stop_owned_unit()
            except Exception as exc:
                self.result.setdefault("cleanup", {})["systemd_stop_error"] = f"{type(exc).__name__}: {str(exc)[:300]}"
            self.close_pidfds()
            self.result.setdefault("cleanup", {})["helper_cleanup_confirmed"] = cleanup_owned_helpers()
            try:
                self.cleanup_installation()
            except Exception as exc:
                self.result.setdefault("cleanup", {})["installation_error"] = f"{type(exc).__name__}: {str(exc)[:300]}"
            try:
                self.release_qa_interval()
            except Exception as exc:
                self.result.setdefault("cleanup",{})["uid_reservation_error"]=type(exc).__name__+": "+str(exc)[:300]
            try:
                after = self.snapshot_host_policy()
                self.result["host_policy_after"] = after
                policy_unchanged = self.snap_before == after and self.snap_before.get("sysctl", {}).get("status") == "captured" and \
                    self.snap_before.get("apparmor", {}).get("status") == "captured"
            except Exception as exc:
                self.result["host_policy_after_error"] = f"{type(exc).__name__}: {str(exc)[:300]}"
                policy_unchanged = False
            self.result["checks"]["host_policy_unchanged"] = {"status": "PASS" if policy_unchanged else "FAIL_OR_UNAVAILABLE"}
            cleanup_ok = self.result.get("cleanup", {}).get("installation") in {"removed_exact_owned_root", "not_created"} and \
                "systemd_stop_error" not in self.result.get("cleanup", {}) and not self.history_initializer_created and self.uid_reservation is None and not OWNED_HELPERS and not HELPER_UNCONFIRMED
            self.result["completed_all_checks"] = completed_all_checks
            self.result["status"] = "PASS_SCOPED_QA" if completed_all_checks and not self.result.get("error") and policy_unchanged and cleanup_ok else "FAIL_OR_INCOMPLETE"
            self.result["finished_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            self.result["release_qualification"] = False
            self.result["production_backend_qualified"] = False
            self.result["product_crash_proof_available"] = False
            self.result.pop("_pidfds", None)
            self.save_public()
        return 0 if self.result["status"] == "PASS_SCOPED_QA" else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    prep = sub.add_parser("prepare", help="compile the exact service.c as the ordinary runner")
    prep.add_argument("--scratch", type=Path, required=True)
    prep.add_argument('--history', action='store_true', help='compose native history with fixed daemon lifecycle (x64/ARM64)')
    run = sub.add_parser("run", help="run the fixed root system-service boundary controller")
    run.add_argument("--scratch", type=Path, required=True)
    run.add_argument("--public", type=Path, required=True)
    run.add_argument('--history', action='store_true')
    args = parser.parse_args()
    if args.command == "prepare":
        return prepare(args.scratch, args.history)
    return ServiceQA(args.scratch, args.public, args.history).run_all()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except QAFailure as exc:
        print(json.dumps({"status": "FAIL_OR_INCOMPLETE", "error": str(exc)[:500]}), file=sys.stderr)
        raise SystemExit(1)
