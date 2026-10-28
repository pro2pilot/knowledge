#!/usr/bin/env python3
"""Physical public-socket rejection checks; no execution or cleanup is claimed.

The eligible ordinary UID sends malformed native frames to the real installed
service. Every refusal must leave a fresh correctly framed client admissible.
No OPEN, storage registration, security-policy change or root Node is used.
"""
from __future__ import annotations

import argparse
import array
import fcntl
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import stat
import struct
import time

MAX_SECONDS = 15
SCHEMA = "knowledge-linux-native-service.v1"


def digest(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


class Client:
    def __init__(self, configuration):
        self.configuration = configuration
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.socket.settimeout(2)
        self.cancel_descriptor = None
        self.nonce = secrets.token_bytes(32)
        self.work_deadline = time.monotonic_ns() + 10_000_000_000
        self.socket.connect(str(Path(configuration["broker"]).parent / "control.sock"))
        self.peer = struct.unpack("3i", self.socket.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        assert self.peer[0] > 1 and self.peer[1] == 0, "root_service_peer_required"

    def frame(self, op, ordinal):
        return struct.pack("<IIIIIIQQ32sQ", 0x4B4C5331, 1, op, ordinal, 0, 0,
                           self.work_deadline, 1000, self.nonce, 0)

    def send(self, op, ordinal, descriptors=()):
        ancillary = []
        if descriptors:
            ancillary.append((socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", descriptors)))
        body = self.frame(op, ordinal)
        assert self.socket.sendmsg([body], ancillary) == len(body), "incomplete_frame"

    def receive(self, *, capability=False, retain_cancel=False):
        body, ancillary, flags, _ = self.socket.recvmsg(8192, socket.CMSG_SPACE(16 * 4))
        received = []
        try:
            assert body and not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC), "truncated_reply"
            for level, kind, data in ancillary:
                assert (level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS), "unexpected_reply_ancillary"
                values = array.array("i")
                assert len(data) % values.itemsize == 0, "malformed_rights"
                values.frombytes(data)
                received.extend(values)
            assert len(received) == (1 if capability else 0), "unexpected_reply_descriptor_count"
            if capability:
                assert stat.S_ISFIFO(os.fstat(received[0]).st_mode), "cancel_channel_not_fifo"
                assert fcntl.fcntl(received[0], fcntl.F_GETFL) & os.O_ACCMODE == os.O_WRONLY, "cancel_channel_not_write_only"
            value = json.loads(body)
            assert value["schema_version"] == SCHEMA
            observation = {"raw_utf8": body.decode(), "raw_sha256": digest(body), "descriptors_received": len(received)}
            if retain_cancel:
                assert capability and self.cancel_descriptor is None
                self.cancel_descriptor = received.pop()
            return value, observation
        finally:
            for descriptor in received:
                os.close(descriptor)

    def hello(self, *, retain_cancel=False):
        self.send(1, 1)
        value, raw = self.receive(capability=True, retain_cancel=retain_cancel)
        assert value["event"] == "capability" and value["status"] == "ready" and value["busy"] is False
        assert value["client_pid"] == os.getpid() and value["controller_pid"] == os.getppid()
        assert value["controller_uid"] == os.getuid()
        for key in ("installation_id", "host_id", "native_source_sha256", "trusted_runtime_manifest_sha256",
                    "trusted_source_manifest_sha256", "node_sha256", "broker_binary_sha256"):
            assert value[key] == self.configuration[key], key
        return value, raw

    def denial(self, reason):
        value, raw = self.receive()
        assert value == {"schema_version": SCHEMA, "event": "denied", "status": "rejected", "reason": reason}, value
        # A rejection is terminal for this transport, not a reusable channel.
        assert self.socket.recv(1) == b"", "rejected_connection_still_open"
        return {"reply": value, **raw}

    def close(self):
        if self.cancel_descriptor is not None:
            os.close(self.cancel_descriptor)
            self.cancel_descriptor = None
        self.socket.close()


def fresh_admission(config):
    client = Client(config)
    try:
        value, raw = client.hello()
        return {"reply": value, **raw}
    finally:
        client.close()


def wait_own_child(pid, deadline):
    while time.monotonic() < deadline:
        observed, status = os.waitpid(pid, os.WNOHANG)
        if observed == pid:
            assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0, "inherited_sender_failed"
            return
        time.sleep(0.001)
    # This unreaped child is our exact direct child; its PID cannot be reused.
    os.kill(pid, signal.SIGKILL)
    os.waitpid(pid, 0)
    raise AssertionError("inherited_sender_deadline")


def run_case(config, name, overall_end):
    assert time.monotonic() < overall_end, "overall_deadline"
    client = Client(config)
    try:
        if name == "extra_descriptors":
            descriptor = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
            try:
                client.send(1, 1, [descriptor, descriptor])
            finally:
                os.close(descriptor)
            denial = client.denial("invalid_request_or_origin")
        elif name == "cancel_fd_status_flags":
            client.hello(retain_cancel=True)
            descriptor = client.cancel_descriptor
            flags = fcntl.fcntl(descriptor, fcntl.F_GETFL)
            fcntl.fcntl(descriptor, fcntl.F_SETFL, flags | os.O_NONBLOCK)
            filled = 0
            while True:
                assert filled < 2 * 1024 * 1024 and time.monotonic() < overall_end, "unexpected_cancel_pipe_capacity"
                try:
                    filled += os.write(descriptor, b"x" * 4096)
                except BlockingIOError:
                    break
            assert filled > 0
            # SCM_RIGHTS duplicates an OFD. The service must retain a distinct
            # private nonblocking OFD so a caller cannot block its root write.
            fcntl.fcntl(descriptor, fcntl.F_SETFL, flags & ~os.O_NONBLOCK)
            assert not fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_NONBLOCK
            client.send(4, 2)
            value, raw = client.receive()
            assert value == {"schema_version": SCHEMA, "event": "stop_requested", "status": "stopping", "ordinal": 2}
            denial = {"reply": value, **raw, "filled_bytes": filled,
                      "caller_cleared_nonblock": True, "broker_stop_response_observed": True}
        else:
            client.hello()
            if name == "duplicate_ordinal":
                client.send(5, 1)
                denial = client.denial("ordinal_identity_or_descriptor")
            elif name == "inherited_sender":
                child = os.fork()
                if child == 0:
                    try:
                        client.send(5, 2)
                        client.close()
                    except BaseException:
                        os._exit(1)
                    os._exit(0)
                try:
                    denial = client.denial("invalid_request_or_origin")
                finally:
                    wait_own_child(child, min(overall_end, time.monotonic() + 3))
                denial["inherited_sender_pid"] = child
                denial["original_sender_pid"] = os.getpid()
                assert child != os.getpid()
            else:
                raise AssertionError(name)
    finally:
        client.close()
    return {"scenario": name, "status": "PASS", "denial": denial,
            "subsequent_admission": fresh_admission(config)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=Path("/var/lib/knowledge-linux-native-v1/installation.json"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    assert os.getuid() != 0 and os.geteuid() != 0, "ordinary_uid_required"
    configuration_bytes = args.config.read_bytes()
    configuration = json.loads(configuration_bytes)
    assert configuration["caller_uid"] == os.getuid()
    start = time.monotonic()
    report = {"schema_version": "knowledge-linux-service-protocol-mutations.v1", "status": "FAIL",
              "configuration_sha256": digest(configuration_bytes), "scenarios": [],
              "execution_qualified": False, "release_qualified": False,
              "scope": "Real service socket admission only; no OPEN or writer registration."}
    try:
        report["initial_admission"] = fresh_admission(configuration)
        for name in ("duplicate_ordinal", "extra_descriptors", "inherited_sender", "cancel_fd_status_flags"):
            report["scenarios"].append(run_case(configuration, name, start + MAX_SECONDS))
        assert time.monotonic() - start < MAX_SECONDS, "overall_deadline"
        report["status"] = "PASS"
    except BaseException as error:
        report["error"] = {"type": type(error).__name__, "message": str(error)}
        raise
    finally:
        report["elapsed_seconds"] = round(time.monotonic() - start, 6)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"status": "PASS", "scenarios": 4, "output": str(args.output)}))


if __name__ == "__main__":
    main()
