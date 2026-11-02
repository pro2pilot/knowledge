#!/usr/bin/env python3
"""One bounded ordinary Linux socket/pipe probe; never starts Main, H or a child.

This observes kernel transport mechanics only. Both connection endpoints belong
to this one Python process, so their credentials cannot prove a biological
parent. Any prerequisite refusal is recorded once as BLOCKED and stops the
probe. No alternate transport, privilege change, retry, or host setup exists.
"""
from __future__ import annotations

import argparse
import array
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import sys


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--review-json", type=Path, required=True)
    args = parser.parse_args()
    source = Path(__file__).resolve()
    data = source.read_bytes()
    pin = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    review = json.loads(args.review_json.read_text())
    rel = "intake-slice/tests/ordinary_socket_probe.py"
    if not review.get("allow_ordinary_socket_probe") or review.get("source_pins", {}).get(rel) != pin:
        print(json.dumps({"status": "NOT_RUN", "reason": "exact_source_review_missing_or_stale", "source": pin}))
        return 78

    report = {
        "schema": "a2-ordinary-kernel-mechanics-probe.v1",
        "source": pin,
        "argv": sys.argv,
        "python": sys.version,
        "uname": dict(zip(("sysname", "nodename", "release", "version", "machine"), os.uname())),
        "euid": os.geteuid(),
        "subject_Main_H_bundle": "NOT_RUN",
        "child_processes_created": 0,
        "physical_birth_or_intake_proof": False,
        "socket_creator_credentials_are_parent_proof": False,
        "deadline_interruptibility_claim": False,
        "events": [],
    }
    events = report["events"]
    sockets: list[socket.socket] = []
    owned: set[int] = set()
    current = "prerequisites"
    result = 0
    cleanup_fault = False

    def note(label: str, **fields: object) -> None:
        events.append({"label": label, **fields})

    def release(fd: int) -> None:
        owned.remove(fd)  # no retry even if close reports EINTR
        os.close(fd)
        note("close_received_or_owned", fd=fd, rc=0)

    def receive(connection: socket.socket, space: int) -> tuple[bytes, int, list[tuple[int, int, bytes]]]:
        payload, ancillary, flags, address = connection.recvmsg(64, space, socket.MSG_DONTWAIT | socket.MSG_CMSG_CLOEXEC)
        installed: list[int] = []
        descriptions = []
        for level, kind, raw in ancillary:
            entry = {"level": level, "type": kind, "bytes": len(raw)}
            if level == socket.SOL_SOCKET and kind in (socket.SCM_RIGHTS, 4):
                descriptors = array.array("i")
                descriptors.frombytes(raw[:len(raw) - len(raw) % descriptors.itemsize])
                for fd in descriptors:
                    assert fd >= 0 and fd not in owned and fd not in installed
                    owned.add(fd)
                    installed.append(fd)
                    assert fcntl.fcntl(fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC
                entry["installed_fds"] = list(descriptors)
            elif level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS:
                assert len(raw) == struct.calcsize("3i")
                entry["credentials"] = list(struct.unpack("3i", raw))
            descriptions.append(entry)
        note("recvmsg", payload_bytes=len(payload), flags=flags, ancillary=descriptions, address=repr(address))
        for fd in installed:
            release(fd)
        for fd in installed:
            try:
                fcntl.fcntl(fd, fcntl.F_GETFD)
            except OSError as exc:
                assert exc.errno == errno.EBADF
            else:
                raise AssertionError("received descriptor remained open")
        return payload, flags, ancillary

    try:
        assert sys.platform == "linux" and struct.calcsize("i") == 4
        assert hasattr(socket, "MSG_CMSG_CLOEXEC")
        current = "AF_UNIX_SEQPACKET_listener_socket"
        server = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_NONBLOCK | socket.SOCK_CLOEXEC)
        sockets.append(server)
        note(current, rc=0)
        # The private abstract name is routing data only; it is never authority.
        address = b"\0knowledge-a2-ordinary-" + str(os.getpid()).encode("ascii")
        current = "bind_listen_private_abstract_socket"
        server.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        server.bind(address)
        server.listen(1)
        note(current, rc=0)
        current = "same_process_connect_accept"
        client = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_NONBLOCK | socket.SOCK_CLOEXEC)
        sockets.append(client)
        client.connect(address)
        accepted, _ = server.accept()
        sockets.append(accepted)
        accepted.setblocking(False)
        accepted.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        note(current, rc=0)

        current = "SO_PEERCRED_SO_PEERPIDFD_SO_PASSPIDFD"
        credentials = struct.unpack("3i", accepted.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
        # Exact Linux asm-generic/socket.h UAPI: 76 SO_PASSPIDFD, 77 SO_PEERPIDFD.
        peer_pidfd = struct.unpack("i", accepted.getsockopt(socket.SOL_SOCKET, 77, struct.calcsize("i")))[0]
        assert peer_pidfd >= 0
        owned.add(peer_pidfd)
        accepted.setsockopt(socket.SOL_SOCKET, 76, 1)
        assert credentials == (os.getpid(), os.geteuid(), os.getegid())
        assert fcntl.fcntl(peer_pidfd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC
        note(current, rc=0, peer_credentials=list(credentials), peer_pidfd=peer_pidfd, parent_proof=False)

        current = "independent_pipe_objects_and_OFD_alias"
        out = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
        owned.update(out)
        err = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
        owned.update(err)
        identity = lambda fd: (os.fstat(fd).st_dev, os.fstat(fd).st_ino)
        assert identity(out[0]) == identity(out[1])
        assert identity(err[0]) == identity(err[1])
        assert identity(out[0]) != identity(err[0])
        alias = os.dup(out[0])
        owned.add(alias)
        before = fcntl.fcntl(out[0], fcntl.F_GETFL)
        fcntl.fcntl(alias, fcntl.F_SETFL, before & ~os.O_NONBLOCK)
        assert not fcntl.fcntl(out[0], fcntl.F_GETFL) & os.O_NONBLOCK
        fcntl.fcntl(alias, fcntl.F_SETFL, before)
        assert fcntl.fcntl(out[0], fcntl.F_GETFL) & os.O_NONBLOCK
        note(current, rc=0, out_object=identity(out[0]), err_object=identity(err[0]), alias_mutated_reader_OFD=True)
        release(alias)

        current = "credential_and_unexpected_rights_pidfd_receipt_retirement"
        sent = client.sendmsg([b"A" * 64], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [out[0], err[0]]))], socket.MSG_DONTWAIT | socket.MSG_NOSIGNAL)
        assert sent == 64
        payload, flags, ancillary = receive(accepted, 4096)
        assert payload == b"A" * 64 and not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
        types = [kind for level, kind, raw in ancillary if level == socket.SOL_SOCKET]
        assert types.count(socket.SCM_CREDENTIALS) == 1 and types.count(socket.SCM_RIGHTS) == 1 and types.count(4) == 1

        current = "truncated_ancillary_receipt_retirement"
        assert client.sendmsg([b"B"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [out[0], err[0]]))], socket.MSG_DONTWAIT | socket.MSG_NOSIGNAL) == 1
        payload, flags, _ = receive(accepted, socket.CMSG_SPACE(struct.calcsize("3i")))
        assert payload == b"B" and flags & socket.MSG_CTRUNC

        current = "EOF_without_child_or_birth"
        client.close()
        sockets.remove(client)
        payload, _, _ = receive(accepted, 4096)
        assert payload == b""
        report["status"] = "PASS_ORDINARY_TRANSPORT_MECHANICS_ONLY"
    except OSError as exc:
        result = 77
        report.update(status="BLOCKED_PREREQUISITE", blocked_at=current, errno=exc.errno, error=str(exc), retries=0, alternative_routes=0)
    except (AssertionError, AttributeError) as exc:
        result = 1
        report.update(status="FAIL_ORDINARY_ASSERTION", failed_at=current, error=str(exc))
    finally:
        for connection in reversed(sockets):
            try:
                connection.close()
            except OSError as exc:
                note("socket_close_error", errno=exc.errno)
                result = result or 1
                cleanup_fault = True
        for fd in sorted(owned):
            try:
                os.close(fd)
                note("final_owned_close", fd=fd, rc=0)
            except OSError as exc:
                note("final_owned_close", fd=fd, rc=-1, errno=exc.errno)
                result = result or 1
                cleanup_fault = True
        report["cleanup_fault"] = cleanup_fault
        if cleanup_fault and report.get("status") == "PASS_ORDINARY_TRANSPORT_MECHANICS_ONLY":
            report["status"] = "FAIL_CLEANUP"
        report["rc"] = result
        print(json.dumps(report, ensure_ascii=False, indent=2))
    return result


if __name__ == "__main__":
    raise SystemExit(main())
