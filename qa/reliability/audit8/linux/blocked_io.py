#!/usr/bin/env python3
"""Last-only disposable-CI test of actual blocked kernel I/O.

Only fixed OS utilities run as root. The image is new, <=64MiB, and exposed
read-only through a new loop/dm-delay mapping. Python and S always use the
ordinary caller UID. Late kernel closure is diagnostic; it never turns an
expired native deadline into a successful cleanup receipt. The late-D branch
deliberately leaves the service's durable writer quarantine intact.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import mmap
import os
from pathlib import Path
import re
import secrets
import select
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import time

from physical_native import Bridge
from protocol_mutations import Client

TOTAL_SECONDS = 75
IMAGE_BYTES = 32 * 1024 * 1024
DELAY_MS = 15000
SCHEMA = "knowledge-linux-blocked-io-qa.v1"


def actor(kind, filename):
    assert os.getuid() != 0 and os.geteuid() != 0
    assert sys.stdin.buffer.readline() == b"permit\n"
    flags = os.O_RDONLY | os.O_CLOEXEC | (os.O_DIRECT if kind == "dm_delay" else 0)
    descriptor = os.open(filename, flags)
    buffer = mmap.mmap(-1, 4096) if kind == "dm_delay" else None
    os.write(1, b"io-enter\n")
    if buffer is not None:
        os.preadv(descriptor, [buffer], 0)
    else:
        os.read(descriptor, 4096)
    os.write(1, b"io-returned\n")
    os.close(descriptor)


def identity(pid):
    text = Path(f"/proc/{pid}/stat").read_text()
    fields = text[text.rfind(")") + 2:].split()
    return {"pid": pid, "state": fields[0], "parent_pid": int(fields[1]), "birth_ticks": fields[19]}


def dead(descriptor):
    poller = select.poll()
    poller.register(descriptor, select.POLLIN)
    return any(flags & (select.POLLIN | select.POLLHUP | select.POLLERR) for _, flags in poller.poll(0))


class DisposableDevice:
    def __init__(self, root, report, deadline):
        self.root, self.report, self.deadline = root, report, deadline
        self.loop = self.name = self.image = self.image_identity = self.table_observation = None
        self.commands = report["admin_commands"] = []

    def command(self, arguments, timeout=5, check=True):
        assert arguments[0] in {"/usr/sbin/modprobe", "/usr/sbin/losetup", "/usr/sbin/dmsetup",
                                "/usr/sbin/blockdev", "/usr/bin/chown", "/usr/bin/chmod",
                                "/usr/bin/cat", "/usr/bin/test"}
        remaining = min(timeout, self.deadline - time.monotonic())
        if remaining <= 0:
            raise AssertionError("cohort_deadline")
        argv = ["/usr/bin/sudo", "-n", "/usr/bin/timeout", "--signal=KILL", str(max(1, int(remaining))), *arguments]
        started = time.monotonic()
        result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=remaining + 1, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"})
        assert len(result.stdout) + len(result.stderr) <= 65536
        self.commands.append({"argv": argv, "exit_code": result.returncode,
                              "elapsed_ms": round((time.monotonic() - started) * 1000, 3),
                              "stdout": result.stdout.decode(errors="replace"), "stderr": result.stderr.decode(errors="replace")})
        if check and result.returncode:
            raise RuntimeError(f"admin_command_failed:{arguments[0]}:{result.returncode}")
        return result

    def prepare(self):
        required = ["/usr/bin/sudo", "/usr/bin/timeout", "/usr/sbin/losetup", "/usr/sbin/dmsetup", "/usr/sbin/blockdev"]
        if any(not Path(name).is_file() for name in required):
            return None, "fixed_OS_utilities_unavailable"
        available = self.command(["/usr/sbin/dmsetup", "targets"], check=False)
        if not re.search(rb"^delay\s", available.stdout, re.M):
            if Path("/usr/sbin/modprobe").is_file():
                self.command(["/usr/sbin/modprobe", "dm_delay"], check=False)
            available = self.command(["/usr/sbin/dmsetup", "targets"], check=False)
        if available.returncode or not re.search(rb"^delay\s", available.stdout, re.M):
            return None, "dm_delay_target_unavailable"
        self.image = self.root / "owned-readonly-image.bin"
        with self.image.open("xb") as image:
            image.truncate(IMAGE_BYTES)
            image.write(b"knowledge-audit8-disposable-readonly\0".ljust(4096, b"\0"))
            image.flush()
            os.fsync(image.fileno())
        observed = self.image.stat()
        assert observed.st_nlink == 1 and observed.st_uid == os.getuid() and observed.st_size == IMAGE_BYTES
        self.image_identity = (observed.st_dev, observed.st_ino)
        loop = self.command(["/usr/sbin/losetup", "--find", "--show", "--read-only", "--nooverlap", str(self.image)]).stdout.decode().strip()
        assert re.fullmatch(r"/dev/loop[0-9]+", loop)
        self.loop = loop
        binding = json.loads(self.command(["/usr/sbin/losetup", "--list", "--json", "--output", "NAME,BACK-FILE,RO", loop]).stdout)
        rows = binding["loopdevices"]
        assert len(rows) == 1 and rows[0]["name"] == loop and rows[0]["ro"] in (True, 1)
        assert Path(rows[0]["back-file"]).resolve() == self.image.resolve()
        self.report["loop_binding"] = binding
        self.name = "knowledge-audit8-dstate-" + secrets.token_hex(8)
        table = f"0 {IMAGE_BYTES // 512} delay {loop} 0 {DELAY_MS}"
        self.command(["/usr/sbin/dmsetup", "create", self.name, "--readonly", "--noudevsync", "--noudevrules",
                      "--addnodeoncreate", "--readahead", "none", "--table", table])
        self.table_observation = self.command(["/usr/sbin/dmsetup", "table", self.name]).stdout.decode().split()
        device_number = os.stat(loop).st_rdev
        own_device = f"{os.major(device_number)}:{os.minor(device_number)}"
        assert self.table_observation[:3] == ["0", str(IMAGE_BYTES // 512), "delay"]
        parameters = self.table_observation[3:]
        assert len(parameters) in (3, 6, 9) and all(parameters[i:i+3] == [own_device, "0", str(DELAY_MS)] for i in range(0, len(parameters), 3))
        mapped = Path("/dev/mapper") / self.name
        observed = mapped.stat()
        assert stat.S_ISBLK(observed.st_mode)
        assert self.command(["/usr/sbin/blockdev", "--getro", str(mapped)]).stdout.strip() == b"1"
        self.command(["/usr/bin/chown", f"{os.getuid()}:0", str(mapped)])
        self.command(["/usr/bin/chmod", "0600", str(mapped)])
        self.report["device"] = {"name": self.name, "path": str(mapped), "major": os.major(observed.st_rdev),
                                 "minor": os.minor(observed.st_rdev), "table": table, "read_only": True,
                                 "image_bytes": IMAGE_BYTES, "delay_ms": DELAY_MS}
        return str(mapped), None

    def read_group(self, group, filename):
        assert filename in {"cgroup.events", "cgroup.procs"}
        assert re.fullmatch(r"/sys/fs/cgroup/[A-Za-z0-9_.:/-]+/writer-[a-f0-9]{64}-0", group)
        assert "/../" not in group and "/./" not in group
        return self.command(["/usr/bin/cat", group + "/" + filename], timeout=3).stdout.decode()

    def cleanup(self):
        receipt = {"mapping_removed": self.name is None, "loop_detached": self.loop is None, "image_removed": self.image is None}
        try:
            if self.name is not None:
                current = self.command(["/usr/sbin/dmsetup", "table", self.name], check=False)
                if current.returncode:
                    # A failed preparation never authorizes deleting a mapping
                    # whose ownership was not established by our exact table.
                    receipt["mapping_removed"] = False
                else:
                    assert self.table_observation is not None and current.stdout.decode().split() == self.table_observation
                    result = self.command(["/usr/sbin/dmsetup", "remove", "--noudevsync", "--noudevrules", self.name], timeout=6, check=False)
                    receipt["mapping_removed"] = result.returncode == 0
            if self.loop is not None and receipt["mapping_removed"]:
                result = self.command(["/usr/sbin/losetup", "--detach", self.loop], check=False)
                binding = self.command(["/usr/sbin/losetup", "--list", "--json", "--output", "NAME,BACK-FILE,RO", self.loop], check=False)
                rows = json.loads(binding.stdout).get("loopdevices") if binding.returncode == 0 else None
                receipt["loop_detached"] = (result.returncode == 0 and isinstance(rows, list)
                                            and not any(row.get("back-file") == str(self.image) for row in rows))
            if self.image is not None and receipt["mapping_removed"] and receipt["loop_detached"]:
                current = self.image.stat()
                assert (current.st_dev, current.st_ino) == self.image_identity
                self.image.unlink()
                receipt["image_removed"] = True
        except BaseException as error:
            receipt["error"] = str(error)
        self.report["fixture_retirement"] = receipt
        return all(receipt[key] for key in ("mapping_removed", "loop_detached", "image_removed"))


def run_registered_io(config, kind, filename, device, report, deadline):
    bridge = Bridge(config, "positive")
    bridge.deadline = time.monotonic_ns() + 8_000_000_000
    bridge.cleanup_ms = 2000
    maximum = bridge.deadline + bridge.cleanup_ms * 1_000_000
    writer = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "--actor", kind, filename],
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              env={"PATH": "/usr/bin:/bin", "LANG": "C"})
    writerfd = os.pidfd_open(writer.pid)
    guardianfd = None
    raw = bytearray()
    stream = bytearray()
    eof = False
    records = []
    report["native_events"] = records
    report["deadlines"] = {"work_deadline_ns": str(bridge.deadline), "cleanup_budget_ms": bridge.cleanup_ms,
                           "original_maximum_ns": str(maximum), "extended": False}

    def pump():
        nonlocal eof
        for _ in range(8):
            readable, _, _ = select.select([bridge.child.stdout], [], [], 0)
            if not readable or eof:
                break
            block = os.read(bridge.child.stdout.fileno(), 65536)
            if not block:
                eof = True
                break
            raw.extend(block)
        while len(raw) >= 16:
            magic, version, kind_id, size = struct.unpack_from("<IIII", raw)
            assert (magic, version) == (0x4B4C4F31, 1) and kind_id == 1 and 0 < size < 8192
            if len(raw) < 16 + size:
                break
            body = bytes(raw[16:16 + size])
            del raw[:16 + size]
            records.append({"observed_ns": str(time.monotonic_ns()), "value": json.loads(body),
                            "raw_utf8": body.decode(), "raw_sha256": hashlib.sha256(body).hexdigest()})
        readable, _, _ = select.select([writer.stdout], [], [], 0)
        if readable:
            block = os.read(writer.stdout.fileno(), 65536)
            stream.extend(block)
            assert len(stream) <= 65536
        assert not any(row["value"].get("event") in {"terminal", "opened", "authority_bound"} for row in records), "no_execution_was_opened"

    try:
        original = identity(writer.pid)
        bridge.send(1)
        capability, _ = bridge.until("capability")
        assert capability["status"] == "ready" and capability["busy"] is False
        assert capability["controller_pid"] == os.getpid() and capability["client_pid"] == bridge.child.pid
        assert capability["broker_binary_sha256"] == config["broker_binary_sha256"]
        bridge.send(2, writer.pid)
        registration, _ = bridge.until("writer_registered")
        raw.extend(bridge.pending)
        bridge.pending.clear()
        assert registration["birth_ticks"] == original["birth_ticks"] and registration["pid"] == writer.pid
        assert registration["registered_before_storage_permit"] is True and int(registration["deadline_ns"]) == maximum
        group_row = Path(f"/proc/{writer.pid}/cgroup").read_text().strip()
        assert group_row.startswith("0::/") and "\n" not in group_row
        group = "/sys/fs/cgroup" + group_row[3:]
        assert group.endswith("/writer-" + bridge.nonce.hex() + "-0")
        group_stat = os.stat(group)
        pids = [int(value) for value in device.read_group(group, "cgroup.procs").split()]
        assert writer.pid in pids and len(pids) == 2
        guardian = next(pid for pid in pids if pid != writer.pid)
        guardian_identity = identity(guardian)
        guardianfd = os.pidfd_open(guardian)
        report["custody"] = {"capability": capability, "writer": original, "registration": registration,
                             "guardian": guardian_identity, "cgroup": group,
                             "cgroup_dev": group_stat.st_dev, "cgroup_ino": group_stat.st_ino,
                             "writer_pidfd_retained": True, "guardian_pidfd_retained": True}
        writer.stdin.write(b"permit\n")
        writer.stdin.flush()
        entered = None
        while time.monotonic_ns() < bridge.deadline and time.monotonic() < deadline:
            pump()
            current = identity(writer.pid)
            assert current["birth_ticks"] == original["birth_ticks"] and not dead(writerfd)
            if b"io-enter\n" in stream and current["state"] == ("D" if kind == "dm_delay" else "S"):
                entered = {**current, "observed_ns": str(time.monotonic_ns())}
                break
            time.sleep(0.005)
        assert entered is not None, "actual_blocked_io_state_not_observed"
        report["blocked_state"] = entered
        report["d_state_observed"] = entered["state"] == "D"
        stopped = time.monotonic_ns()
        report["stop_sent_ns"] = str(stopped)
        bridge.send(4)
        observed_live_past_maximum = False
        samples = []
        while not dead(writerfd) and time.monotonic() < deadline - 10:
            pump()
            if dead(writerfd):
                break
            assert not any(row["value"].get("event") == "writer_closed" for row in records), "false_native_closure_while_exact_writer_alive"
            current = identity(writer.pid)
            assert current["birth_ticks"] == original["birth_ticks"]
            stamp = time.monotonic_ns()
            if stamp >= maximum:
                observed_live_past_maximum = True
            if len(samples) < 128 and (not samples or stamp - int(samples[-1]["observed_ns"]) >= 100_000_000):
                samples.append({"state": current["state"], "observed_ns": str(stamp), "pidfd_dead": False})
            time.sleep(0.01)
        report["blocked_samples"] = samples
        assert dead(writerfd), "writer_still_kernel_blocked_at_fixture_deadline"
        writer.wait(timeout=1)
        report["writer_exit"] = {"pidfd_exit_observed": True, "creator_reaped": True,
                                 "exit_code": writer.returncode, "observed_ns": str(time.monotonic_ns())}
        assert writer.returncode == -signal.SIGKILL and b"io-returned" not in stream
        while not dead(guardianfd) and time.monotonic() < deadline - 8:
            pump()
            time.sleep(0.01)
        assert dead(guardianfd), "guardian_finality_not_observed"
        group_after = os.stat(group)
        assert (group_after.st_dev, group_after.st_ino) == (group_stat.st_dev, group_stat.st_ino)
        group_events = device.read_group(group, "cgroup.events")
        assert re.search(r"^populated 0$", group_events, re.M)
        report["late_physical_closure"] = {"writer_pidfd_exit_observed": True, "guardian_pidfd_exit_observed": True,
                                          "original_cgroup_empty": True, "cgroup_events": group_events,
                                          "observed_ns": str(time.monotonic_ns()), "acceptance_authority": False}
        if observed_live_past_maximum:
            assert kind == "dm_delay" and report["d_state_observed"]
            pump()
            assert not any(row["value"].get("event") == "writer_closed" for row in records), "expired_native_deadline_relabelled_closed"
            value = None
            for _ in range(20):
                observer = Client(config)
                try:
                    observer.send(1, 1)
                    value, raw_cap = observer.receive(capability=True)
                    assert value["event"] == "capability"
                    if value["status"] == "quarantined":
                        report["late_service_fence"] = {"value": value, **raw_cap}
                        break
                finally:
                    observer.close()
                time.sleep(0.01)
            assert value["status"] == "quarantined"
            record = str(Path(config["broker"]).parent / f"writer-{bridge.child.pid}-0.bin")
            assert device.command(["/usr/bin/test", "-f", record]).returncode == 0
            report["durable_writer_fence_retained"] = True
            report["status"] = "PASS_D_STATE_LATE_CLOSURE_REMAINS_UNCONFIRMED"
        else:
            while time.monotonic_ns() < maximum and time.monotonic() < deadline - 8:
                pump()
                if any(row["value"].get("event") == "writer_closed" for row in records):
                    break
                time.sleep(0.01)
            closures = [row["value"] for row in records if row["value"].get("event") == "writer_closed"]
            assert len(closures) == 1
            closed = closures[0]
            assert closed["pid"] == writer.pid and closed["birth_ticks"] == registration["birth_ticks"] and closed["registration_ordinal"] == registration["ordinal"]
            assert all(closed[key] is True for key in ("pidfd_exit_observed", "guardian_reaped", "writer_cgroup_empty", "registration_removed", "closed_in_budget"))
            assert int(closed["observed_ns"]) < int(closed["deadline_ns"]) == maximum
            report["status"] = "PASS_PHYSICAL_D_STATE_CANCELLED_IN_BUDGET" if kind == "dm_delay" else "PASS_FIFO_IO_CANCELLED_D_STATE_UNAVAILABLE"
        report["observed_live_past_original_maximum"] = observed_live_past_maximum
        report["no_acceptance_released"] = True
        report["writer_stdout"] = stream.decode()
        bridge.child.stdin.close()
        bridge.child.wait(timeout=2)
        report["client_exit_code"] = bridge.child.returncode
    finally:
        if writer.poll() is None:
            signal.pidfd_send_signal(writerfd, signal.SIGKILL)
            try:
                writer.wait(timeout=max(0.1, min(20, deadline - time.monotonic() - 7)))
            except subprocess.TimeoutExpired:
                report["writer_cleanup_unconfirmed"] = True
        if bridge.child.poll() is None:
            bridge.child.kill()
            bridge.child.wait(timeout=2)
        os.close(writerfd)
        if guardianfd is not None:
            os.close(guardianfd)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=Path("/var/lib/knowledge-linux-native-v1/installation.json"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    assert os.getuid() != 0 and os.geteuid() != 0
    assert os.environ.get("GITHUB_ACTIONS") == "true", "disposable_CI_only_last_step"
    root = Path(tempfile.mkdtemp(prefix="knowledge-audit8-dstate-", dir=os.environ["RUNNER_TEMP"])).resolve()
    started = time.monotonic()
    deadline = started + TOTAL_SECONDS
    report = {"schema_version": SCHEMA, "status": "FAIL", "caller_uid": os.getuid(), "fixture_root": str(root),
              "d_state_observed": False, "no_acceptance_released": False, "release_qualified": False,
              "scope": "Registered native S custody under real blocked I/O; no public verification execution or ACK is requested.",
              "cohort_seconds": TOTAL_SECONDS, "preexisting_active_devices_modified": False}
    device = DisposableDevice(root, report, deadline)
    fifo_holder = None
    try:
        config = json.loads(args.config.read_bytes())
        assert config["caller_uid"] == os.getuid()
        filename, unavailable = device.prepare()
        if filename is None:
            report["dm_delay_prerequisite"] = unavailable
            filename = str(root / "owned-read-fifo")
            os.mkfifo(filename, 0o600)
            fifo_holder = os.open(filename, os.O_RDWR | os.O_NONBLOCK | os.O_CLOEXEC)
            kind = "fifo"
        else:
            kind = "dm_delay"
        report["physical_io"] = kind
        run_registered_io(config, kind, filename, device, report, deadline)
    except BaseException as error:
        report["status"] = "FAIL"
        report["error"] = {"type": type(error).__name__, "message": str(error)}
        raise
    finally:
        if fifo_holder is not None:
            os.close(fifo_holder)
        retired = device.cleanup()
        if not retired and report["status"].startswith("PASS"):
            report["status"] = "FAIL_FIXTURE_RETIREMENT_UNCONFIRMED"
        report["elapsed_seconds"] = round(time.monotonic() - started, 6)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n")
    assert report["status"].startswith("PASS") and report["elapsed_seconds"] < TOTAL_SECONDS
    print(json.dumps({"status": report["status"], "d_state_observed": report["d_state_observed"], "output": str(args.output)}))


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--actor":
        actor(sys.argv[2], sys.argv[3])
    else:
        main()
