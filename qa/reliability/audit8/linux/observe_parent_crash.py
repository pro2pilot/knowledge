#!/usr/bin/env python3
"""Exact retained-handle observation of the public controller crash fixture.

Ordinary UID only. These independent pidfd exits are diagnostics, not a
substitute for the dead controller's native terminal/ACK or root reaping.
"""
import argparse
import json
import os
from pathlib import Path
import select
import signal
import sys
import time


def identity(pid):
    text = Path(f"/proc/{pid}/stat").read_text()
    fields = text[text.rfind(")") + 2:].split()
    status = Path(f"/proc/{pid}/status").read_text().splitlines()
    uids = next(line.split()[1:] for line in status if line.startswith("Uid:"))
    assert len(uids) == 4 and len(set(uids)) == 1, "Mixed UID identity"
    return {"pid": pid, "ppid": int(fields[1]), "birth_ticks": fields[19], "uid": int(uids[0])}


def children(pid):
    return [int(value) for value in Path(f"/proc/{pid}/task/{pid}/children").read_text().split()]


input_buffer = bytearray()


def input_line(limit, deadline):
    while True:
        end = input_buffer.find(b"\n")
        if end >= 0:
            assert end + 1 <= limit
            result = bytes(input_buffer[:end + 1]); del input_buffer[:end + 1]
            return result
        assert len(input_buffer) < limit
        remaining = (deadline - time.monotonic_ns()) / 1e9
        assert remaining > 0, "Observer input exceeded original deadline"
        readable, _, _ = select.select([sys.stdin.fileno()], [], [], remaining)
        assert readable, "Observer input exceeded original deadline"
        part = os.read(sys.stdin.fileno(), min(4096, limit - len(input_buffer)))
        assert part, "Observer input closed before complete instruction"
        input_buffer.extend(part)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    assert os.getuid() != 0, "Observer must use the ordinary fixture UID"
    line = input_line(65536, time.monotonic_ns() + 10_000_000_000)
    request = json.loads(line)
    required = {"controller_pid", "controller_birth_ticks", "caller_pid", "client_pid", "keeper_pid", "init_pid",
                "allocation_sequence", "worker_uid", "cleanup_budget_ms", "original_max_end_ns"}
    assert set(request) == required
    handles, observations = {}, {}
    result = {"schema_version": "knowledge-audit8-public-controller-crash-observer.v1", "status": "FAIL",
              "native_terminal_proof": False, "root_reaping_observed": False, "cgroup_empty_observed": False}

    def retain(pid, role):
        if pid in handles:
            poll = select.poll(); poll.register(handles[pid], select.POLLIN)
            if poll.poll(0):
                return None
            current = identity(pid)
            prior = observations[pid]
            assert current["birth_ticks"] == prior["birth_ticks"] and current["ppid"] == prior["ppid"]
            # The native W gate may have forked this same retained process just
            # before its one-way credential drop; refresh credentials only.
            prior["uid"] = current["uid"]
            return observations[pid]
        before = identity(pid)
        descriptor = os.pidfd_open(pid)
        try:
            after = identity(pid)
            assert after["birth_ticks"] == before["birth_ticks"] and after["ppid"] == before["ppid"]
            before = after
            poll = select.poll(); poll.register(descriptor, select.POLLIN)
            if poll.poll(0):
                raise ProcessLookupError("Process exited before capture")
        except BaseException:
            os.close(descriptor)
            raise
        handles[pid] = descriptor
        observations[pid] = {**before, "role": role, "pidfd_exit_observed": False}
        return observations[pid]

    try:
        controller = retain(request["controller_pid"], "controller")
        assert controller["uid"] == os.getuid() and controller["ppid"] == request["caller_pid"]
        assert controller["birth_ticks"] == request["controller_birth_ticks"]
        keeper = retain(request["keeper_pid"], "native_keeper")
        init = retain(request["init_pid"], "native_namespace_init")
        assert keeper["uid"] == init["uid"] == 0 and init["ppid"] == keeper["pid"]
        cgroup = Path(f"/proc/{init['pid']}/cgroup").read_text().strip()
        assert cgroup.startswith("0::/") and cgroup.endswith(
            "/knowledge-linux-native-v1.service/attempt-" + str(request["allocation_sequence"]))
        result["captured_init_cgroup"] = cgroup
        direct = children(controller["pid"])
        assert request["client_pid"] in direct and len(direct) >= 2
        for pid in direct:
            row = retain(pid, "native_client" if pid == request["client_pid"] else "storage_child")
            assert row["ppid"] == controller["pid"] and row["uid"] == os.getuid()
        # Traverse only the already identified private namespace. Require an
        # actual live W birth, not a timer or a published 'running' label.
        search_end = min(time.monotonic_ns() + 5_000_000_000, int(request["original_max_end_ns"]))
        worker = None
        while time.monotonic_ns() < search_end and worker is None:
            queue = [init["pid"]]; seen = set()
            while queue and worker is None:
                parent = queue.pop(0)
                if parent in seen:
                    continue
                seen.add(parent); assert len(seen) <= 64
                try:
                    if retain(parent, "authority_or_command_descendant") is None:
                        continue
                    descendants = children(parent)
                except (FileNotFoundError, ProcessLookupError):
                    continue
                for pid in descendants:
                    try:
                        row = retain(pid, "authority_or_command_descendant")
                        if row is None:
                            continue
                        assert row["ppid"] == parent
                        if row["uid"] == request["worker_uid"]:
                            row["role"] = "actual_private_worker"; worker = row; break
                        queue.append(pid)
                    except (FileNotFoundError, ProcessLookupError):
                        continue
            if worker is None:
                time.sleep(0.01)
        assert worker is not None, "No actual private worker was observed"
        result["actual_worker_observed"] = True
        print(json.dumps({"status": "READY_WITH_RETAINED_PIDFDS", "identities": list(observations.values())}), flush=True)
        assert input_line(16, int(request["original_max_end_ns"])) == b"KILL\n"
        killed = time.monotonic_ns()
        deadline = min(killed + int(request["cleanup_budget_ms"]) * 1_000_000,
                       int(request["original_max_end_ns"]))
        assert deadline > killed
        signal.pidfd_send_signal(handles[controller["pid"]], signal.SIGKILL)
        result["kill_sent_through_retained_pidfd"] = True
        result["killed_ns"], result["original_cleanup_endpoint_ns"] = str(killed), str(deadline)
        poll = select.poll()
        by_fd = {descriptor: pid for pid, descriptor in handles.items()}
        for descriptor in by_fd:
            poll.register(descriptor, select.POLLIN)
        pending = set(by_fd)
        while pending and time.monotonic_ns() < deadline:
            for descriptor, mask in poll.poll(max(0, min(100, (deadline - time.monotonic_ns()) // 1_000_000))):
                assert not mask & (select.POLLERR | select.POLLNVAL)
                if mask & (select.POLLIN | select.POLLHUP):
                    observations[by_fd[descriptor]]["pidfd_exit_observed"] = True
                    observations[by_fd[descriptor]]["observed_ns"] = str(time.monotonic_ns())
                    pending.discard(descriptor); poll.unregister(descriptor)
        assert not pending and time.monotonic_ns() < deadline, "Exact process handles did not all signal within original endpoint"
        result["status"] = "PASS_RETAINED_PIDFD_CRASH_OBSERVATION"
    finally:
        result["identities"] = list(observations.values())
        for descriptor in handles.values():
            os.close(descriptor)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"status": result["status"], "output": str(args.output)}), flush=True)


if __name__ == "__main__":
    main()
