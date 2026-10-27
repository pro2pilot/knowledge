#!/usr/bin/env python3
"""Prepare and drive one private Linux component-slice experiment.

This is bounded QA scaffolding, not a production backend, public RPC service,
KVE integration, release gate, or publication workflow. The root phase uses a
single generated systemd unit and the exact fixed native binary; it never
accepts project commands or caller-selected executable paths.
"""
from __future__ import annotations

import argparse
import base64
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import secrets
import selectors
import signal
import stat
import struct
import subprocess
import sys
import time
import uuid


HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[2]
OLD_QA_HELPER = REPO_ROOT / "qa/reliability/linux-admin-service-27/native_boundary_qa.py"
HOST_ARCH = {"aarch64": "arm64", "arm64": "arm64", "x86_64": "x64", "amd64": "x64"}.get(platform.machine().lower())
NODE_PATH = Path(f"/opt/hostedtoolcache/node/22.17.1/{HOST_ARCH or 'unsupported'}/bin/node")
CC_PATH = Path("/usr/bin/cc")
READELF_PATH = Path("/usr/bin/readelf")
LDD_PATH = Path("/usr/bin/ldd")
RUNNER_UID = 1001
AUTHORITY_UID = 1000010300
WORKER_UID = 1000010301
MAX_PLAN_BYTES = 256 * 1024
MAX_INPUT_BYTES = 2 * 1024 * 1024
MAX_SMALL_FILE = 64 * 1024
MAX_NATIVE_JSON = 160 * 1024
MAX_WORKER_OUTPUT = 64 * 1024
MAX_COMMAND_OUTPUT = 128 * 1024
MAX_DEPENDENCIES = 64
MAX_TREE_ENTRIES = 4096
MAX_TREE_DEPTH = 16
MAX_TREE_BYTES = 512 * 1024 * 1024
MAX_RUNTIME_BYTES = 512 * 1024 * 1024
ROOT_STAGE_TIMEOUT = 135
UNIT_STOP_TIMEOUT = 25
WORK_BUDGET_MS = 30000
CLEANUP_BUDGET_MS = 10000
FAULT_PROFILES = {"none": 0, "import-receipt-held": 1, "result-held": 2,
                  "keeper-during-drain": 3, "broker-during-drain": 4}
DRAIN_BOOLS = {"drain_entered", "drain_stop_dispatched", "drain_observer_verified",
               "drain_fault_signal_sent", "drain_fault_exit_confirmed", "drain_survivor_confirmed",
               "drain_observer_emergency_cleanup", "drain_init_exit_before_fault", "drain_init_not_observer_child"}
DRAIN_INTS = {"drain_broker_wait_status", "drain_target_pid", "drain_survivor_pid", "drain_init_pid"}
DRAIN_FIELDS = DRAIN_BOOLS | DRAIN_INTS
CLAIM_PATH = Path(f"/run/knowledge-slice-uid-reservation-{AUTHORITY_UID}-{WORKER_UID}")
NODE_VERSION = "v22.17.1"
EXPECTED_INPUT_TEXT = "component-slice-input-v1\n"
EXPECTED_TEST_NAME = "the imported source is readable, read-only, and worker descendants stay scoped"
SCHEMA = "knowledge-linux-service-component-plan.v1"
O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)


class SliceFailure(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise SliceFailure(code, message)


def sha256(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def strict_json(body: bytes | str):
    """Reject ambiguous protocol bytes before any custody or success decision."""
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate JSON member")
            value[key] = item
        return value
    def finite(_value):
        raise ValueError("nonfinite JSON number")
    text = body.decode("utf-8", "strict") if isinstance(body, bytes) else body
    return json.loads(text, object_pairs_hook=unique, parse_constant=finite)


def architecture_profile() -> tuple[str, int, str]:
    require(HOST_ARCH in {"arm64", "x64"}, "architecture_unsupported", "Only fixed Linux ARM64 and x64 profiles are supported")
    return (("aarch64", 183, "/lib/ld-linux-aarch64.so.1") if HOST_ARCH == "arm64" else
            ("x86_64", 62, "/lib64/ld-linux-x86-64.so.2"))


def elf_static_native(data: bytes) -> bool:
    _, machine, _ = architecture_profile()
    if len(data) < 64 or data[:6] != b"\x7fELF\x02\x01":
        return False
    e_type, observed_machine = struct.unpack_from("<HH", data, 16)
    phoff = struct.unpack_from("<Q", data, 32)[0]
    phentsize, phnum = struct.unpack_from("<HH", data, 54)
    if e_type != 2 or observed_machine != machine or phentsize < 56 or not 1 <= phnum <= 128 or phoff + phentsize * phnum > len(data):
        return False
    types = [struct.unpack_from("<I", data, phoff + i * phentsize)[0] for i in range(phnum)]
    return 1 in types and 2 not in types and 3 not in types


def load_old_helpers():
    require(OLD_QA_HELPER.is_file(), "qa_helper_missing", "Existing bounded QA helper module is unavailable")
    spec = importlib.util.spec_from_file_location("knowledge_linux_admin_qa_helpers", OLD_QA_HELPER)
    require(spec is not None and spec.loader is not None, "qa_helper_import", "Cannot load existing QA helpers")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def component_sources() -> Path:
    names = ("native-slice.c", "authority.js", "importer.js")
    require(all((HERE / name).is_file() for name in names), "component_source_missing",
            "Fixed native, authority, and importer sources must be sibling files")
    return HERE


def physical_read(path: Path, maximum: int, expected_uid: int | None = None) -> tuple[os.stat_result, bytes]:
    named = path.lstat()
    require(stat.S_ISREG(named.st_mode) and not stat.S_ISLNK(named.st_mode) and named.st_nlink == 1 and
            named.st_size <= maximum, "source_file_unsafe", f"Expected a bounded single-link file: {path.name}")
    if expected_uid is not None:
        require(named.st_uid == expected_uid, "source_owner_mismatch", f"Unexpected owner for {path.name}")
    fd = os.open(path, os.O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
    try:
        opened = os.fstat(fd)
        ident = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_nlink, value.st_size,
                               value.st_mtime_ns, value.st_ctime_ns)
        require(ident(opened) == ident(named), "source_changed", f"File identity changed: {path.name}")
        chunks = bytearray()
        while len(chunks) <= maximum:
            block = os.read(fd, min(65536, maximum + 1 - len(chunks)))
            if not block:
                break
            chunks.extend(block)
        after = os.fstat(fd)
        current = path.lstat()
        require(len(chunks) <= maximum and len(chunks) == opened.st_size and
                ident(after) == ident(opened) and ident(current) == ident(opened),
                "source_changed", f"File changed during bounded read: {path.name}")
        return opened, bytes(chunks)
    finally:
        os.close(fd)


def bounded_process(argv: list[str], timeout: int, maximum: int, cwd: Path, env: dict[str, str]) -> tuple[int, bytes, bytes, float]:
    """Stream a fixed tool under an anchored private process session.

    The leader is observed with WNOWAIT until group termination, so a reused
    PID/group can never be signalled. This is preparation/admin scaffolding;
    arbitrary worker trees require the native namespace/cgroup boundary.
    """
    started = time.monotonic()
    deadline = started + timeout
    process = None
    selector = selectors.DefaultSelector()
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    problem = None
    stop_sent = False
    cleanup_end = None
    leader_exited = False
    reaped = False

    def stop_group():
        nonlocal stop_sent, cleanup_end
        if process is None or reaped or stop_sent:
            return
        # The unreaped direct leader anchors this newly created session ID.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        stop_sent = True
        cleanup_end = time.monotonic() + 3

    try:
        process = subprocess.Popen(argv, cwd=cwd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, shell=False, env=env, start_new_session=True, close_fds=True)
        for label, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, label)
        while True:
            # Never use poll()/wait() here: those would release the PID anchor.
            state = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            leader_exited = state is not None
            now = time.monotonic()
            if now >= deadline and problem is None:
                problem = "prepare_command_timeout"
            if leader_exited or problem is not None:
                stop_group()
            if leader_exited and not selector.get_map():
                break
            if cleanup_end is not None and now >= cleanup_end:
                problem = "prepare_command_cleanup_unconfirmed"
                break
            for event, _ in selector.select(0.025):
                try:
                    block = os.read(event.fd, 65536)
                except BlockingIOError:
                    continue
                if not block:
                    selector.unregister(event.fileobj)
                    continue
                target = buffers[event.data]
                available = maximum + 1 - len(target)
                if available > 0:
                    target.extend(block[:available])
                if len(target) > maximum and problem is None:
                    problem = "prepare_command_output_limit"
                    stop_group()
        stop_group()
        try:
            return_code = process.wait(timeout=3)
            reaped = process.returncode is not None
        except subprocess.TimeoutExpired:
            problem = "prepare_command_cleanup_unconfirmed"
        require(reaped, "prepare_command_cleanup_unconfirmed", "Fixed-tool leader could not be reaped")
        require(problem is None, problem or "prepare_command_failed", "Fixed tool exceeded its output/time or cleanup contract")
        return return_code, bytes(buffers["stdout"]), bytes(buffers["stderr"]), time.monotonic() - started
    finally:
        if process is not None and not reaped:
            stop_group()
            try:
                process.wait(timeout=3)
                reaped = process.returncode is not None
            except subprocess.TimeoutExpired:
                pass
        selector.close()
        if process is not None:
            for stream in (process.stdout, process.stderr):
                if stream is not None:
                    stream.close()
        if process is not None and not reaped:
            raise SliceFailure("prepare_command_cleanup_unconfirmed", "Fixed-tool direct-child custody is still unresolved")


def command(argv: list[str], timeout: int, maximum: int, cwd: Path, env: dict[str, str]) -> tuple[int, bytes, bytes, float]:
    require(argv and argv[0] in {str(CC_PATH), str(READELF_PATH), str(LDD_PATH), str(NODE_PATH)},
            "command_not_allowlisted", "Prepare command is outside the fixed tool allowlist")
    return bounded_process(argv, timeout, maximum, cwd, env)


def write_new_file(path: Path, body: bytes, mode: int, uid: int | None = None, gid: int | None = None) -> os.stat_result:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode)
    try:
        if uid is not None or gid is not None:
            os.fchown(fd, -1 if uid is None else uid, -1 if gid is None else gid)
        view = memoryview(body)
        while view:
            n = os.write(fd, view)
            require(n > 0, "short_write", "Short write while creating bounded artifact")
            view = view[n:]
        os.fsync(fd)
        os.fchmod(fd, mode)
        st = os.fstat(fd)
        require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_size == len(body) and
                (st.st_mode & 0o7777) == mode, "created_file_invalid", "Created artifact identity did not match contract")
        return st
    finally:
        os.close(fd)


def node_run_id() -> str:
    return uuid.uuid4().hex


def utf8_order(name: str) -> bytes:
    return name.encode("utf-8", "strict")


def manifest_digest(files: list[dict]) -> str:
    ordered = sorted(files, key=lambda item: utf8_order(item["path"]))
    body = [{"bytes": item["bytes"], "mode": item["mode"], "path": item["path"], "sha256": item["sha256"]}
            for item in ordered]
    return sha256(json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))


def directories_digest(names: list[str]) -> str:
    return sha256(json.dumps(sorted(names, key=utf8_order), ensure_ascii=False, separators=(",", ":")).encode("utf-8"))


def test_script_bytes() -> bytes:
    return b'''\
'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');

test('the imported source is readable, read-only, and worker descendants stay scoped', async () => {
  const scratch = process.env.KNOWLEDGE_SLICE_SCRATCH;
  assert.equal(scratch, '/scratch');
  assert.equal(process.version, 'v22.17.1');
  assert.equal(process.getuid(), 1000010301);
  assert.equal(process.geteuid(), 1000010301);
  assert.equal(process.getgid(), 1000010301);
  assert.equal(fs.readFileSync(path.join(process.cwd(), 'input.txt'), 'utf8'), 'component-slice-input-v1\\n');
  fs.writeFileSync(path.join(scratch, 'worker.txt'), 'worker scratch write\\n', { flag: 'wx' });
  assert.throws(() => fs.writeFileSync(path.join(process.cwd(), 'input.txt'), 'overwrite\\n'),
    error => ['EROFS', 'EACCES', 'EPERM'].includes(error.code));
  await new Promise(resolve => setTimeout(resolve, 2000));
  const marker = path.join(scratch, 'descendant.txt');
  const readyPath = path.join(scratch, 'descendant-ready.json');
  const code = `const fs=require('node:fs');const ready=${JSON.stringify(readyPath)};const marker=${JSON.stringify(marker)};` +
    `fs.writeFileSync(ready,JSON.stringify({pid:process.pid,uid:process.getuid(),version:process.version}),{flag:'wx'});` +
    `let tick=0;setInterval(()=>fs.appendFileSync(marker,String(++tick)+'\\\\n'),20);`;
  const child = spawn(process.execPath, ['-e', code], { detached: true, stdio: 'ignore',
    env: { PATH: '/runtime', LD_LIBRARY_PATH: '/runtime/lib', HOME: scratch, TMPDIR: scratch,
      KNOWLEDGE_SLICE_SCRATCH: scratch } });
  await new Promise((resolve, reject) => {
    let settled = false;
    const fail = error => {
      if (settled) return;
      settled = true;
      reject(error);
    };
    child.once('error', fail);
    const deadline = Date.now() + 5000;
    const inspect = () => {
      if (settled) return;
      try {
        const ready = JSON.parse(fs.readFileSync(readyPath, 'utf8'));
        const ticks = fs.readFileSync(marker, 'utf8').trim().split('\\n').filter(Boolean);
        if (ready.pid === child.pid && ready.uid === 1000010301 && ready.version === 'v22.17.1' && ticks.length >= 2) {
          settled = true;
          resolve();
          return;
        }
      } catch (_) {}
      if (Date.now() >= deadline) {
        fail(new Error('detached writer readiness/tick proof timed out'));
        return;
      }
      setTimeout(inspect, 10);
    };
    child.once('exit', (code, signal) => {
      if (!settled) fail(new Error('detached writer exited before readiness (code=' + code + ', signal=' + signal + ')'));
    });
    child.once('spawn', inspect);
  });
  child.unref();
});
'''


def make_blob() -> tuple[bytes, dict]:
    input_body = EXPECTED_INPUT_TEXT.encode("ascii")
    test_body = test_script_bytes()
    files = [
        {"path": "input.txt", "bytes": len(input_body), "mode": 0o644,
         "sha256": sha256(input_body), "data_base64": base64.b64encode(input_body).decode("ascii")},
        {"path": "tests/read-only.test.js", "bytes": len(test_body), "mode": 0o644,
         "sha256": sha256(test_body), "data_base64": base64.b64encode(test_body).decode("ascii")},
    ]
    files.sort(key=lambda item: utf8_order(item["path"]))
    directories = ["tests"]
    value = {"schema_version": "knowledge-linux-service-copy-input.v1", "directories": directories,
             "files": files, "manifest_sha256": manifest_digest(files),
             "directories_sha256": directories_digest(directories)}
    body = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    require(len(body) <= MAX_INPUT_BYTES, "input_wire_limit", "Prepared component input exceeds native cap")
    return body, value


def physical_source_dir() -> Path:
    sources = component_sources()
    st = sources.lstat()
    require(stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode), "component_dir_unsafe", "Component source directory must be physical")
    for name in ("native-slice.c", "authority.js", "importer.js"):
        physical_read(sources / name, 512 * 1024)
    return sources


def run_prepare(fault: str = "none") -> int:
    require(fault in FAULT_PROFILES, "fault_profile_invalid", "Only fixed component fault profiles are supported")
    fault_mode = FAULT_PROFILES[fault]
    require(os.getuid() == RUNNER_UID and os.geteuid() == RUNNER_UID,
            "prepare_identity", "Prepare must run as the ordinary Ubuntu Actions caller UID 1001")
    architecture, elf_machine, expected_loader = architecture_profile()
    global NODE_PATH, CC_PATH, READELF_PATH, LDD_PATH
    requested = {"node": NODE_PATH, "cc": CC_PATH, "readelf": READELF_PATH, "ldd": LDD_PATH}
    resolved = {}
    for name, tool in requested.items():
        try:
            canonical = tool.resolve(strict=True)
        except OSError as exc:
            raise SliceFailure("prepare_tool_missing", f"Expected fixed tool is unavailable: {tool.name}") from exc
        st, _ = physical_read(canonical, 256 * 1024 * 1024 if name == "node" else 64 * 1024 * 1024)
        allowed_owners = {0, RUNNER_UID} if name == "node" else {0}
        require(st.st_uid in allowed_owners and (st.st_mode & 0o022) == 0 and
                not (st.st_mode & (stat.S_ISUID | stat.S_ISGID)),
                "prepare_tool_identity", f"Resolved fixed tool is writable or has unexpected ownership: {tool.name}")
        if name != "node":
            for parent in (canonical.parent, *canonical.parents[1:]):
                parent_st = parent.lstat()
                require(stat.S_ISDIR(parent_st.st_mode) and not stat.S_ISLNK(parent_st.st_mode) and
                        parent_st.st_uid == 0 and (parent_st.st_mode & 0o022) == 0,
                        "prepare_tool_parent", f"Resolved system tool parent is not protected: {parent.name}")
        resolved[name] = canonical
    NODE_PATH, CC_PATH, READELF_PATH, LDD_PATH = (resolved["node"], resolved["cc"],
                                                   resolved["readelf"], resolved["ldd"])
    helpers = load_old_helpers()
    source_dir = physical_source_dir()
    node_st, node_body = physical_read(NODE_PATH, 256 * 1024 * 1024)
    env = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
    code, out, err, version_elapsed = command([str(NODE_PATH), "--version"], 10, 4096, source_dir, env)
    require(code == 0 and out.strip().decode("ascii", "strict") == NODE_VERSION and not err,
            "node_version_mismatch", "Setup-node executable must report exactly v22.17.1")

    token = node_run_id()
    unit = f"knowledge-slice-{token}"
    slice_root = f"/var/lib/{unit}"
    service_cgroup = f"/sys/fs/cgroup/system.slice/{unit}.service"
    work_cgroup = f"{service_cgroup}/work"
    temp_root = Path("/tmp")
    temp_st = temp_root.lstat()
    require(stat.S_ISDIR(temp_st.st_mode) and not stat.S_ISLNK(temp_st.st_mode) and temp_st.st_uid == 0 and
            (temp_st.st_mode & stat.S_ISVTX) != 0, "prepare_tmp_unsafe", "Fixed /tmp must be root-owned sticky directory")
    scratch = temp_root / f"knowledge-slice-prep-{token}"
    os.mkdir(scratch, 0o700)
    os.chmod(scratch, 0o700)
    artifacts = scratch / "prepare-private"
    inputs = scratch / "inputs"
    public = scratch / "public"
    for directory, mode in ((artifacts, 0o700), (inputs, 0o700), (public, 0o755)):
        os.mkdir(directory, mode)
        os.chmod(directory, mode)

    source_files = {}
    for name in ("native-slice.c", "authority.js", "importer.js"):
        _, body = physical_read(source_dir / name, 512 * 1024)
        target = inputs / name
        st = write_new_file(target, body, 0o600)
        source_files[name] = {"staged": f"inputs/{name}", "sha256": sha256(body), "bytes": len(body),
                              "source_path": str(source_dir / name), "staged_inode": st.st_ino}

    blob, blob_value = make_blob()
    write_new_file(scratch / "blobinput.json", blob, 0o400)

    compiler_argv = [str(CC_PATH), "-std=gnu11", "-O2", "-static", "-no-pie", "-Wall", "-Wextra",
                     "-Werror=implicit-function-declaration", "-Werror=return-type",
                     f'-DSLICE_ROOT="{slice_root}"', f'-DSLICE_CGROUP="{work_cgroup}"',
                     f"-DSLICE_A_UID={AUTHORITY_UID}", f"-DSLICE_W_UID={WORKER_UID}",
                     f"-DSLICE_FAULT_MODE={fault_mode}",
                     str(inputs / "native-slice.c"), "-o", str(scratch / "native-slice")]
    compile_stdout = artifacts / "compile.stdout.bin"
    compile_stderr = artifacts / "compile.stderr.bin"
    code, out, err, elapsed = command(compiler_argv, 45, MAX_COMMAND_OUTPUT, scratch, env)
    proc = subprocess.CompletedProcess(compiler_argv, code, out, err)
    write_new_file(compile_stdout, proc.stdout, 0o600)
    write_new_file(compile_stderr, proc.stderr, 0o600)
    require(proc.returncode == 0, "compile_failed", "Static native component compile failed; private logs retained")
    native_stat, native_body = physical_read(scratch / "native-slice", 16 * 1024 * 1024, RUNNER_UID)
    require(elf_static_native(native_body) and not (native_stat.st_mode & (stat.S_ISUID | stat.S_ISGID)),
            "native_binary_invalid", "Prepared native component is not the exact host-profile static ELF")

    readelf_status, readelf_out, readelf_err, readelf_elapsed = command(
        [str(READELF_PATH), "-hW", str(NODE_PATH)], 15, MAX_COMMAND_OUTPUT, source_dir, env)
    require(readelf_status == 0 and len(node_body) >= 20 and node_body[:6] == b"\x7fELF\x02\x01" and
            struct.unpack_from("<H", node_body, 18)[0] == elf_machine, "node_elf_arch", "Pinned Node binary differs from the fixed host architecture")
    ph_status, ph_out, ph_err, ph_elapsed = command(
        [str(READELF_PATH), "-lW", str(NODE_PATH)], 15, MAX_COMMAND_OUTPUT, source_dir, env)
    require(ph_status == 0, "node_readelf_failed", "Cannot inspect the pinned Node ELF program headers")
    match = re.search(rb"Requesting program interpreter:\s*(/[^\s\]]+)", ph_out)
    require(match is not None, "node_interpreter_missing", "Node ELF interpreter was not reported")
    requested_loader = os.fsdecode(match.group(1))
    interp_path = Path(os.path.realpath(requested_loader))
    require(requested_loader == expected_loader and
            str(interp_path).startswith(("/lib/", "/usr/lib/")),
            "node_interpreter_unexpected", "Node uses an unsupported ARM64 loader path")
    ldd_status, ldd_out, ldd_err, ldd_elapsed = command(
        [str(LDD_PATH), str(NODE_PATH)], 15, MAX_COMMAND_OUTPUT, source_dir, env)
    require(ldd_status == 0 and b"not found" not in ldd_out and b"not found" not in ldd_err,
            "node_ldd_failed", "Unprivileged ldd did not resolve every Node dependency")
    dependencies = {}
    for line in ldd_out.decode("utf-8", "strict").splitlines():
        row = re.match(r"^\s*([A-Za-z0-9._+\-]+)\s+=>\s+(/\S+)\s+\(", line)
        if not row:
            if ("linux-vdso" in line or "statically linked" in line or
                    re.fullmatch(r"\s*" + re.escape(expected_loader) + r"\s+\(0x[0-9a-fA-F]+\)\s*", line)):
                continue
            if line.strip():
                raise SliceFailure("ldd_output_unrecognized", "ldd emitted an unrecognized dependency record")
            continue
        soname, resolved = row.group(1), Path(os.path.realpath(row.group(2)))
        require(re.fullmatch(r"[A-Za-z0-9._+\-]+", soname) is not None and
                resolved.is_absolute() and str(resolved).startswith(("/lib/", "/usr/lib/")),
                "node_dependency_path", "Node dependency lies outside fixed system library roots")
        dep_stat, dep_body = physical_read(resolved, 64 * 1024 * 1024)
        previous = dependencies.get(soname)
        record = {"name": soname, "source_path": str(resolved), "sha256": sha256(dep_body),
                  "bytes": len(dep_body), "source_mode": dep_stat.st_mode & 0o7777}
        require(previous is None or previous["sha256"] == record["sha256"],
                "node_dependency_collision", "Two resolved libraries share a runtime name with different bytes")
        dependencies[soname] = record
    require(0 < len(dependencies) <= MAX_DEPENDENCIES, "node_dependency_count", "Node dependency count is outside fixed bounds")
    _loader_stat, loader_body = physical_read(interp_path, 16 * 1024 * 1024)
    runtime_bytes = len(node_body) + len(loader_body) + sum(item["bytes"] for item in dependencies.values()) + \
        sum(record["bytes"] for record in source_files.values()) + len(native_body)
    require(runtime_bytes <= MAX_RUNTIME_BYTES, "runtime_size_limit", "Pinned Node runtime closure exceeds bounded install size")

    prepare_log = {"node_version": NODE_VERSION, "node_sha256": sha256(node_body), "node_bytes": len(node_body),
                   "compile_elapsed_seconds": round(elapsed, 3), "readelf_header_elapsed_seconds": round(readelf_elapsed, 3),
                   "readelf_program_headers_elapsed_seconds": round(ph_elapsed, 3), "ldd_elapsed_seconds": round(ldd_elapsed, 3),
                   "compiler_stdout_sha256": sha256(proc.stdout), "compiler_stderr_sha256": sha256(proc.stderr),
                   "readelf_header_stdout_sha256": sha256(readelf_out), "readelf_header_stderr_sha256": sha256(readelf_err),
                   "readelf_program_headers_stdout_sha256": sha256(ph_out), "readelf_program_headers_stderr_sha256": sha256(ph_err),
                   "ldd_stdout_sha256": sha256(ldd_out), "ldd_stderr_sha256": sha256(ldd_err),
                   "node_version_command_elapsed_seconds": round(version_elapsed, 3)}
    for name, body in (("node-version.stdout.bin", out), ("node-version.stderr.bin", err),
                       ("readelf-header.stdout.bin", readelf_out), ("readelf-header.stderr.bin", readelf_err),
                       ("readelf-program.stdout.bin", ph_out), ("readelf-program.stderr.bin", ph_err),
                       ("ldd.stdout.bin", ldd_out), ("ldd.stderr.bin", ldd_err)):
        write_new_file(artifacts / name, body, 0o600)
    fixtures = [{"path": item["path"], "bytes": item["bytes"], "mode": item["mode"], "sha256": item["sha256"]}
                for item in blob_value["files"]]
    plan = {"schema_version": SCHEMA, "run_id": token, "architecture": architecture, "runner_uid": RUNNER_UID,
            "fault_mode": fault_mode,
            "authority_uid": AUTHORITY_UID, "worker_uid": WORKER_UID, "slice_root": slice_root,
            "unit": unit, "service_cgroup": service_cgroup, "work_cgroup": work_cgroup,
            "node": {"path": str(NODE_PATH), "version": NODE_VERSION, "sha256": sha256(node_body), "bytes": len(node_body)},
            "loader": {"path": str(interp_path), "requested_path": requested_loader,
                       "sha256": sha256(loader_body), "bytes": len(loader_body)},
            "dependencies": [dependencies[name] for name in sorted(dependencies)],
            "component_sources": source_files,
            "native_binary": {"path": "native-slice", "sha256": sha256(native_body), "bytes": len(native_body)},
            "blob": {"path": "blobinput.json", "sha256": sha256(blob), "bytes": len(blob),
                     "manifest_sha256": blob_value["manifest_sha256"], "directories_sha256": blob_value["directories_sha256"],
                     "files": len(blob_value["files"]), "total_bytes": sum(item["bytes"] for item in blob_value["files"]),
                     "fixtures": fixtures},
            "tap_inventory": {"node_version": NODE_VERSION, "expected_names": [EXPECTED_TEST_NAME],
                              "tests": 1, "pass": 1, "fail": 0, "skipped": 0, "cancelled": 0, "todo": 0},
            "prepare_private": prepare_log}
    plan_body = json.dumps(plan, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    require(len(plan_body) <= MAX_PLAN_BYTES, "plan_limit", "Prepared plan exceeds its fixed bound")
    write_new_file(scratch / "plan.json", plan_body, 0o600)
    print(json.dumps({"status": "PREPARED_COMPONENT_QA", "run_id": token, "architecture": architecture,
                      "fault_mode": fault_mode,
                      "node_version": NODE_VERSION, "node_sha256": plan["node"]["sha256"],
                      "native_sha256": plan["native_binary"]["sha256"], "input_sha256": plan["blob"]["sha256"]},
                     sort_keys=True))
    return 0


def verify_input_blob(body: bytes, expected: dict) -> dict:
    require(len(body) == expected["bytes"] and sha256(body) == expected["sha256"],
            "blob_changed", "Prepared input blob changed after unprivileged prepare")
    try:
        blob = json.loads(body.decode("utf-8", "strict"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise SliceFailure("blob_invalid", "Prepared input blob is invalid") from exc
    require(set(blob) == {"schema_version", "directories", "files", "manifest_sha256", "directories_sha256"} and
            blob["schema_version"] == "knowledge-linux-service-copy-input.v1" and
            blob["manifest_sha256"] == expected["manifest_sha256"] and
            blob["directories_sha256"] == expected["directories_sha256"] and
            blob["directories"] == ["tests"] and len(blob["files"]) == expected["files"] == 2,
            "blob_manifest_mismatch", "Input blob metadata mismatch")
    require(manifest_digest(blob["files"]) == blob["manifest_sha256"] and
            directories_digest(blob["directories"]) == blob["directories_sha256"],
            "blob_manifest_mismatch", "Input blob manifest digests do not match the current copy contract")
    expected_files = {
        "input.txt": EXPECTED_INPUT_TEXT.encode("ascii"),
        "tests/read-only.test.js": test_script_bytes(),
    }
    require([file.get("path") for file in blob["files"]] == sorted(expected_files, key=utf8_order),
            "blob_fixture_mismatch", "Input file inventory is not exact")
    total = 0
    for file in blob["files"]:
        require(set(file) == {"path", "bytes", "mode", "sha256", "data_base64"} and
                file["path"] in expected_files and type(file["bytes"]) is int and file["mode"] == 0o644 and
                isinstance(file["data_base64"], str), "blob_fixture_mismatch", "Input fixture record is malformed")
        data = base64.b64decode(file["data_base64"], validate=True)
        require(base64.b64encode(data).decode("ascii") == file["data_base64"] and
                data == expected_files[file["path"]] and file["bytes"] == len(data) and file["sha256"] == sha256(data),
                "blob_fixture_mismatch", "Input fixture bytes or digest differ from fixed experiment")
        total += len(data)
    require(total == expected["total_bytes"] and expected["fixtures"] == [
        {"path": file["path"], "bytes": file["bytes"], "mode": file["mode"], "sha256": file["sha256"]}
        for file in blob["files"]], "blob_fixture_mismatch", "Prepared fixture pins do not match the blob")
    return blob


def exact_scratch(run_id: str) -> Path:
    require(re.fullmatch(r"[a-f0-9]{32}", run_id) is not None, "run_id_invalid", "Run ID is not canonical")
    scratch = Path("/tmp") / f"knowledge-slice-prep-{run_id}"
    st = scratch.lstat()
    require(stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode) and st.st_uid == RUNNER_UID and
            (st.st_mode & 0o7777) == 0o700, "scratch_invalid", "Prepare scratch is not a private physical caller directory")
    return scratch


def load_plan(scratch: Path, helpers) -> tuple[dict, bytes, Path]:
    architecture, _, expected_loader = architecture_profile()
    plan_st, plan_raw = physical_read(scratch / "plan.json", MAX_PLAN_BYTES, RUNNER_UID)
    require((plan_st.st_mode & 0o7777) == 0o600, "plan_permissions", "Prepared plan must remain caller-private")
    try:
        plan = strict_json(plan_raw)
    except (UnicodeError, ValueError) as exc:
        raise SliceFailure("plan_invalid", "Prepared plan JSON is invalid") from exc
    required = {"schema_version", "run_id", "architecture", "runner_uid", "authority_uid", "worker_uid", "slice_root",
                "unit", "service_cgroup", "work_cgroup", "node", "loader", "dependencies", "component_sources",
                "native_binary", "blob", "tap_inventory", "prepare_private", "fault_mode"}
    require(set(plan) == required and plan["schema_version"] == SCHEMA and plan["run_id"] == scratch.name.removeprefix("knowledge-slice-prep-") and
            plan["architecture"] == architecture and plan["runner_uid"] == RUNNER_UID and
            plan["authority_uid"] == AUTHORITY_UID and plan["worker_uid"] == WORKER_UID,
            "plan_contract", "Prepared plan fields or fixed identities do not match")
    require(type(plan["fault_mode"]) is int and plan["fault_mode"] in FAULT_PROFILES.values(),
            "plan_fault_profile", "Prepared fault profile is not a fixed native mode")
    unit = "knowledge-slice-" + plan["run_id"]
    root = "/var/lib/" + unit
    service_cgroup = "/sys/fs/cgroup/system.slice/" + unit + ".service"
    require(plan["unit"] == unit and plan["slice_root"] == root and plan["service_cgroup"] == service_cgroup and
            plan["work_cgroup"] == service_cgroup + "/work", "plan_paths", "Prepared install paths are not generated fixed paths")
    require(plan["node"] == {"path": str(NODE_PATH), "version": NODE_VERSION,
                             "sha256": plan["node"].get("sha256"), "bytes": plan["node"].get("bytes")} and
            re.fullmatch(r"[0-9a-f]{64}", plan["node"]["sha256"] or "") is not None and
            isinstance(plan["node"]["bytes"], int) and not isinstance(plan["node"]["bytes"], bool) and
            0 < plan["node"]["bytes"] <= 256 * 1024 * 1024,
            "node_plan_invalid", "Setup-node source pin is invalid")
    require(isinstance(plan["dependencies"], list) and 0 < len(plan["dependencies"]) <= MAX_DEPENDENCIES,
            "dependency_plan_invalid", "Node dependency list exceeds fixed bounds")
    names = set()
    for dep in plan["dependencies"]:
        require(set(dep) == {"name", "source_path", "sha256", "bytes", "source_mode"} and
                re.fullmatch(r"[A-Za-z0-9._+\-]+", dep["name"] or "") is not None and dep["name"] not in names and
                re.fullmatch(r"[0-9a-f]{64}", dep["sha256"] or "") is not None and
                isinstance(dep["bytes"], int) and not isinstance(dep["bytes"], bool) and 0 < dep["bytes"] <= 64 * 1024 * 1024,
                "dependency_plan_invalid", "Node dependency record is malformed")
        names.add(dep["name"])
        source = Path(dep["source_path"])
        require(source.is_absolute() and str(source).startswith(("/lib/", "/usr/lib/")) and
                os.path.realpath(source) == str(source), "dependency_path_invalid", "Dependency source is outside fixed system paths")
    loader = plan["loader"]
    require(set(loader) == {"path", "requested_path", "sha256", "bytes"} and
            loader["requested_path"] == expected_loader and
            loader["path"].startswith(("/lib/", "/usr/lib/")) and os.path.realpath(loader["path"]) == loader["path"],
            "loader_plan_invalid", "ELF loader path is outside fixed ARM64 roots")
    require(re.fullmatch(r"[0-9a-f]{64}", loader["sha256"] or "") is not None and
            isinstance(loader["bytes"], int) and not isinstance(loader["bytes"], bool) and 0 < loader["bytes"] <= 16 * 1024 * 1024,
            "loader_plan_invalid", "ELF loader digest or size is invalid")
    tap = plan["tap_inventory"]
    require(tap == {"node_version": NODE_VERSION, "expected_names": [EXPECTED_TEST_NAME],
                    "tests": 1, "pass": 1, "fail": 0, "skipped": 0, "cancelled": 0, "todo": 0},
            "tap_inventory_invalid", "Prepared TAP acceptance inventory is not the fixed single test")
    sources = plan["component_sources"]
    require(set(sources) == {"native-slice.c", "authority.js", "importer.js"},
            "component_source_plan", "Component source file list is incomplete")
    for name, record in sources.items():
        require(set(record) == {"staged", "sha256", "bytes", "source_path", "staged_inode"} and
                record["staged"] == f"inputs/{name}" and Path(record["source_path"]).resolve() == component_sources().joinpath(name).resolve() and
                re.fullmatch(r"[0-9a-f]{64}", record["sha256"] or "") is not None,
                "component_source_plan", "Component source pin differs from its fixed sibling file")
        st, body = physical_read(scratch / record["staged"], 512 * 1024, RUNNER_UID)
        require(st.st_ino == record["staged_inode"] and len(body) == record["bytes"] and sha256(body) == record["sha256"],
                "component_source_changed", "Staged component source changed after prepare")
        _, current = physical_read(Path(record["source_path"]), 512 * 1024)
        require(sha256(current) == record["sha256"], "component_source_changed", "Fixed component source changed after prepare")
    native = plan["native_binary"]
    native_st, native_body = physical_read(scratch / "native-slice", 16 * 1024 * 1024, RUNNER_UID)
    require(native["path"] == "native-slice" and len(native_body) == native["bytes"] and
            sha256(native_body) == native["sha256"] and elf_static_native(native_body) and
            not (native_st.st_mode & (stat.S_ISUID | stat.S_ISGID)),
            "native_binary_changed", "Prepared static native bytes failed their bound hash/ELF check")
    blob_st, blob_body = physical_read(scratch / "blobinput.json", MAX_INPUT_BYTES, RUNNER_UID)
    require((blob_st.st_mode & 0o7777) == 0o400, "blob_permissions", "blobinput.json must be fresh mode 0400")
    verify_input_blob(blob_body, plan["blob"])
    return plan, blob_body, scratch


def no_symlink_dir(path: Path, uid: int, mode: int | None = None) -> os.stat_result:
    st = path.lstat()
    require(stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode) and st.st_uid == uid and
            (mode is None or (st.st_mode & 0o7777) == mode), "directory_identity", f"Directory identity failed: {path.name}")
    return st


def write_root_file(destination: Path, body: bytes, mode: int, expected_digest: str, max_bytes: int) -> dict:
    require(len(body) <= max_bytes and sha256(body) == expected_digest,
            "copy_source_digest", f"Input bytes changed before root copy: {destination.name}")
    fd = os.open(destination, os.O_RDWR | os.O_CREAT | os.O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
    try:
        os.fchown(fd, 0, 0)
        view = memoryview(body)
        while view:
            count = os.write(fd, view)
            require(count > 0, "copy_short_write", "Short write during root-owned fresh copy")
            view = view[count:]
        os.fchmod(fd, mode)
        os.fsync(fd)
        st = os.fstat(fd)
        require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_gid == 0 and st.st_nlink == 1 and
                st.st_size == len(body) and (st.st_mode & 0o7777) == mode,
                "copy_destination_identity", f"Root-created file has wrong identity: {destination.name}")
        os.lseek(fd, 0, os.SEEK_SET)
        readback = bytearray()
        while len(readback) <= max_bytes:
            block = os.read(fd, min(65536, max_bytes + 1 - len(readback)))
            if not block:
                break
            readback.extend(block)
        require(bytes(readback) == body and sha256(bytes(readback)) == expected_digest,
                "copy_readback", f"Root-created file readback mismatch: {destination.name}")
        return {"sha256": expected_digest, "bytes": len(body), "mode": f"{mode:04o}", "inode": st.st_ino}
    finally:
        os.close(fd)


def mkdir_root(path: Path, mode: int = 0o700) -> None:
    os.mkdir(path, mode)
    os.chown(path, 0, 0)
    os.chmod(path, mode)
    no_symlink_dir(path, 0, mode)
    require_no_acl(path)


def require_no_acl(path: Path) -> None:
    for attr in ("system.posix_acl_access", "system.posix_acl_default"):
        try:
            value = os.getxattr(path, attr, follow_symlinks=False)
        except OSError as exc:
            if exc.errno in {errno.ENODATA, errno.ENOTSUP, errno.EOPNOTSUPP}:
                continue
            raise SliceFailure("acl_check_failed", "Could not verify ACL state on a privileged path") from exc
        require(not value, "acl_present", "Unexpected POSIX ACL on a privileged install path")


def tap_inventory(output: bytes) -> dict | None:
    try:
        text = output.decode("utf-8", "strict")
    except UnicodeError:
        return None
    lines = [line.rstrip("\r") for line in text.splitlines()]
    expected_counts = {"tests": "1", "suites": "0", "pass": "1", "fail": "0",
                       "cancelled": "0", "skipped": "0", "todo": "0"}
    if not lines or lines[0] != "TAP version 13" or lines.count("1..1") != 1:
        return None
    subtests = [line[len("# Subtest: "):] for line in lines if line.startswith("# Subtest: ")]
    successes = [line for line in lines if re.match(r"^ok [0-9]+ - ", line)]
    failures = [line for line in lines if line.startswith("not ok ")]
    if subtests != [EXPECTED_TEST_NAME] or successes != [f"ok 1 - {EXPECTED_TEST_NAME}"] or failures:
        return None
    counts = {}
    for key, expected in expected_counts.items():
        rows = [line for line in lines if line.startswith(f"# {key} ")]
        if rows != [f"# {key} {expected}"]:
            return None
        counts[key] = int(expected)
    durations = [line for line in lines if line.startswith("# duration_ms ")]
    if len(durations) != 1 or re.fullmatch(r"# duration_ms [0-9]+(?:\.[0-9]+)?", durations[0]) is None:
        return None
    # Node's TAP reporter emits a YAML diagnostic block after each test.
    # Validate its known fields while still rejecting extra tests or errors.
    allowed = {"TAP version 13", "# Subtest: " + EXPECTED_TEST_NAME, "ok 1 - " + EXPECTED_TEST_NAME,
               "1..1", *(f"# {key} {value}" for key, value in expected_counts.items()), durations[0],
               "  ---", "  type: 'test'", "  ..."}
    yaml_durations = [line for line in lines if line.startswith("  duration_ms: ")]
    if len(yaml_durations) > 1 or any(re.fullmatch(r"  duration_ms: [0-9]+(?:\.[0-9]+)?", line) is None
                                      for line in yaml_durations):
        return None
    allowed.update(yaml_durations)
    if any(line not in allowed for line in lines):
        return None
    if lines.count("  ---") != 1 or lines.count("  type: 'test'") != 1 or lines.count("  ...") != 1:
        return None
    return {"node_version": NODE_VERSION, "expected_names": [EXPECTED_TEST_NAME], "tests": counts["tests"],
            "pass": counts["pass"], "fail": counts["fail"], "skipped": counts["skipped"],
            "cancelled": counts["cancelled"], "todo": counts["todo"]}


def component_acceptance(return_code: int, value: dict, observer_acknowledged: bool,
                         child_reaped: bool, tap: dict | None) -> bool:
    wait_statuses = ("init_wait_status", "keeper_wait_status", "worker_wait_status", "authority_wait_status", "importer_wait_status")
    return (type(return_code) is int and return_code == 0 and value.get("status") == "WORK_CLOSED" and
            type(value.get("fault_mode")) is int and value["fault_mode"] == 0 and value.get("fault_reached") is False and
            value.get("observer_ack_required") is True and observer_acknowledged is True and child_reaped is True and
            all(value.get(name) is True for name in (
                "cleanup_confirmed", "importer_namespace_drained", "importer_detached_writer_ready",
                "source_readonly", "authority_readback", "cgroup_empty", "output_eof")) and
            value.get("phase") == 4 and value.get("stop_reason") == 4 and
            type(value.get("work_ms")) is int and 0 <= value["work_ms"] < WORK_BUDGET_MS and
            type(value.get("cleanup_ms")) is int and 0 <= value["cleanup_ms"] <= CLEANUP_BUDGET_MS and
            type(value.get("proof_emitted_ms")) is int and
            value["work_ms"] + value["cleanup_ms"] <= value["proof_emitted_ms"] <= WORK_BUDGET_MS + CLEANUP_BUDGET_MS + 2000 and
            all(value.get(name) == 0 and type(value.get(name)) is int for name in wait_statuses) and
            tap is not None and tap.get("tests") == 1 and tap.get("pass") == 1 and
            tap.get("fail") == 0 and tap.get("skipped") == 0)


def fault_acceptance(return_code: int, value: dict, mode: int, observer_acknowledged: bool,
                     child_reaped: bool, tap: dict | None) -> bool:
    """A successful fault experiment requires a failed work result plus exact closure."""
    if not (type(mode) is int and mode in {1, 2, 3, 4} and type(return_code) is int and return_code == 1 and
            type(value.get("fault_mode")) is int and value["fault_mode"] == mode and value.get("fault_reached") is True and
            value.get("status") == "FAIL" and value.get("production_admission") is False and
            value.get("release_gate_qualified") is False and value.get("observer_ack_required") is True and
            observer_acknowledged is False and child_reaped is True and value.get("stop_reason") == 3 and
            all(value.get(name) is True for name in ("cleanup_confirmed", "cgroup_empty", "output_eof")) and
            type(value.get("work_ms")) is int and WORK_BUDGET_MS <= value["work_ms"] <= WORK_BUDGET_MS + 2000 and
            type(value.get("cleanup_ms")) is int and 0 <= value["cleanup_ms"] <= CLEANUP_BUDGET_MS and
            type(value.get("proof_emitted_ms")) is int and
            value["work_ms"] + value["cleanup_ms"] <= value["proof_emitted_ms"] <= WORK_BUDGET_MS + CLEANUP_BUDGET_MS + 2000 and
            all(type(value.get(name)) is int for name in ("phase", "init_wait_status", "keeper_wait_status", "importer_wait_status", "worker_wait_status", "authority_wait_status")) and
            value["init_wait_status"] == signal.SIGKILL and value["keeper_wait_status"] == (signal.SIGKILL if mode == 3 else 0) and
            value["importer_wait_status"] == 0 and value["authority_wait_status"] == -1):
        return False
    if mode == 1:
        return (value["phase"] == 2 and value["worker_wait_status"] == -1 and value.get("output_bytes") == 0 and
                value.get("input_manifest_sha256") == "" and value.get("directories_sha256") == "" and
                value.get("importer_report_hex") == "" and
                all(value.get(name) is False for name in ("importer_namespace_drained", "importer_detached_writer_ready", "source_readonly", "authority_readback")) and tap is None)
    if mode in {3, 4} and not drain_acceptance(value, mode):
        return False
    return (value["phase"] == 3 and value["worker_wait_status"] == 0 and
            all(value.get(name) is True for name in ("importer_namespace_drained", "importer_detached_writer_ready", "source_readonly", "authority_readback")) and
            tap is not None and tap.get("tests") == 1 and tap.get("pass") == 1 and tap.get("fail") == 0 and tap.get("skipped") == 0)


def drain_acceptance(value: dict, mode: int) -> bool:
    """Native stop/reap transaction evidence, never an observer fallback proof."""
    required_true = DRAIN_BOOLS - {"drain_observer_emergency_cleanup", "drain_init_exit_before_fault"}
    pids = [value.get(key) for key in ("drain_target_pid", "drain_survivor_pid", "drain_init_pid")]
    return (mode in {3, 4} and all(value.get(key) is True for key in required_true) and
            value.get("drain_observer_emergency_cleanup") is False and
            type(value.get("drain_init_exit_before_fault")) is bool and
            all(type(pid) is int and 0 < pid < 2**31 for pid in pids) and len(set(pids)) == 3 and
            type(value.get("drain_broker_wait_status")) is int and
            value["drain_broker_wait_status"] == (1 << 8 if mode == 3 else signal.SIGKILL))


def bounded_native_failure(body: bytes | None) -> bool:
    """Diagnostic classification only: this can never admit a successful run."""
    if not isinstance(body, bytes) or not body.endswith(b"\n") or body.count(b"\n") != 1 or len(body) > MAX_NATIVE_JSON:
        return False
    try:
        value = strict_json(body)
    except (UnicodeError, ValueError):
        return False
    return isinstance(value, dict) and value.get("status") == "FAIL"


def decode_mount_field(value: str) -> str:
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), value)


def mounts_below(root: Path) -> list[str]:
    root_text = str(root)
    mounts = []
    for line in Path("/proc/self/mountinfo").read_text(encoding="ascii", errors="strict").splitlines():
        fields = line.split()
        if len(fields) < 6:
            raise SliceFailure("mountinfo_invalid", "Mount table has an invalid row")
        mount = decode_mount_field(fields[4])
        if mount == root_text or mount.startswith(root_text + "/"):
            mounts.append(mount)
    return mounts


def remove_owned_tree(root: Path, root_identity: tuple[int, int], allowed_uids: set[int]) -> None:
    current = root.lstat()
    require((current.st_dev, current.st_ino) == root_identity and stat.S_ISDIR(current.st_mode) and
            current.st_uid == 0 and current.st_gid == 0, "cleanup_root_identity", "Install root inode changed; preserving it")
    require(not mounts_below(root), "cleanup_mount_present", "A mount remains below the owned install root")
    root_dev = current.st_dev
    seen = 0
    byte_count = 0

    def walk(path: Path, depth: int) -> None:
        nonlocal seen, byte_count
        require(depth <= MAX_TREE_DEPTH, "cleanup_depth_limit", "Owned tree cleanup depth exceeded")
        dfd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        try:
            parent_stat = os.fstat(dfd)
            require(parent_stat.st_dev == root_dev and parent_stat.st_uid in allowed_uids and
                    stat.S_ISDIR(parent_stat.st_mode), "cleanup_directory_identity", "Owned tree contains an unexpected directory")
            require_no_acl(path)
            names = os.listdir(dfd)
            os.fchmod(dfd, 0o700)
            for name in names:
                require(name not in {".", ".."} and "/" not in name and "\\" not in name,
                        "cleanup_name_invalid", "Owned tree contains a nonportable entry name")
                seen += 1
                require(seen <= MAX_TREE_ENTRIES, "cleanup_entry_limit", "Owned tree entry limit exceeded")
                item = os.stat(name, dir_fd=dfd, follow_symlinks=False)
                require(item.st_dev == root_dev and item.st_uid in allowed_uids and not stat.S_ISLNK(item.st_mode),
                        "cleanup_entry_identity", "Owned tree entry is a link, foreign file, or different device")
                if stat.S_ISDIR(item.st_mode):
                    walk(path / name, depth + 1)
                    os.rmdir(name, dir_fd=dfd)
                elif stat.S_ISREG(item.st_mode):
                    require(item.st_nlink == 1 and item.st_size >= 0, "cleanup_file_identity", "Owned tree file is hardlinked or invalid")
                    require_no_acl(path / name)
                    byte_count += item.st_size
                    require(byte_count <= MAX_TREE_BYTES, "cleanup_byte_limit", "Owned tree cleanup byte limit exceeded")
                    os.unlink(name, dir_fd=dfd)
                else:
                    raise SliceFailure("cleanup_special_file", "Owned install tree contains a special file")
        finally:
            os.close(dfd)

    walk(root, 0)
    os.rmdir(root)
    require(not root.exists() and not root.is_symlink(), "cleanup_root_remaining", "Install root remained after bounded cleanup")


class RootRun:
    def __init__(self, run_id: str):
        require(os.geteuid() == 0 and os.environ.get("SUDO_UID") == str(RUNNER_UID),
                "root_identity", "Root phase requires the fixed sudo caller UID 1001")
        architecture_profile()
        self.helpers = load_old_helpers()
        self.scratch = exact_scratch(run_id)
        self.plan, self.blob, self.scratch = load_plan(self.scratch, self.helpers)
        self.run_id = run_id
        self.unit = self.plan["unit"]
        self.install_root = Path(self.plan["slice_root"])
        self.service_cgroup = Path(self.plan["service_cgroup"])
        self.work_cgroup = Path(self.plan["work_cgroup"])
        self.private = Path("/tmp") / f"knowledge-slice-private-{run_id}"
        self.public_dir = self.scratch / "public"
        self.result = {"schema_version": "knowledge-linux-service-component-result.v1", "status": "FAIL",
                       "run_id": self.run_id, "production_admission": False, "release_gate_qualified": False,
                       "scope": "closed component experiment only; not production, KVE, release, or public RPC qualification",
                       "platform": f"linux-{HOST_ARCH}", "node_version": NODE_VERSION,
                       "fault_mode": self.plan["fault_mode"],
                       "node_sha256": self.plan["node"]["sha256"], "native_sha256": self.plan["native_binary"]["sha256"],
                       "importer_sha256": self.plan["component_sources"]["importer.js"]["sha256"],
                       "authority_sha256": self.plan["component_sources"]["authority.js"]["sha256"],
                       "input_sha256": self.plan["blob"]["sha256"],
                       "input_manifest_sha256": self.plan["blob"]["manifest_sha256"],
                       "directories_sha256": self.plan["blob"]["directories_sha256"],
                       "reasons": [], "native": {}, "host_cleanup_confirmed": False}
        self.claim_identity: tuple[int, int, str] | None = None
        self.root_identity: tuple[int, int] | None = None
        self.claim_created = False
        self.install_created = False
        self.unit_intent = False
        self.unit_confirmed = False
        self.native_result: dict | None = None
        self.native_json_body: bytes | None = None
        self.native_stdout_body: bytes | None = None
        self.native_child_reaped = False
        self.observer_acknowledged = False
        self.observed_unit: dict[str, str] | None = None
        self.systemd_run_elapsed_seconds: float | None = None

    def record_failure(self, code: str) -> None:
        if code not in self.result["reasons"]:
            self.result["reasons"].append(code)

    def reserve_uids(self) -> None:
        for parent in (Path("/"), Path("/run"), Path("/var"), Path("/var/lib")):
            st = parent.lstat()
            require(stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode) and st.st_uid == 0 and
                    (st.st_mode & 0o022) == 0, "host_path_unsafe", "Root install ancestor is not protected")
            require_no_acl(parent)
        for source, column in ((Path("/etc/passwd"), 2), (Path("/etc/group"), 2)):
            st, raw = physical_read(source, 4 * 1024 * 1024, 0)
            for line in raw.decode("utf-8", "strict").splitlines():
                if not line or line.startswith("#"):
                    continue
                fields = line.split(":")
                require(len(fields) > column and fields[column].isdigit(), "account_file_invalid", "Local account file is malformed")
                value = int(fields[column])
                require(value not in {AUTHORITY_UID, WORKER_UID}, "uid_conflict", "Reserved component UID is assigned locally")
        for source in (Path("/etc/subuid"), Path("/etc/subgid")):
            if not source.exists():
                continue
            _, raw = physical_read(source, 4 * 1024 * 1024, 0)
            for line in raw.decode("utf-8", "strict").splitlines():
                if not line or line.startswith("#"):
                    continue
                fields = line.split(":")
                require(len(fields) == 3 and fields[1].isdigit() and fields[2].isdigit(),
                        "subid_file_invalid", "Local sub-ID file is malformed")
                start, count = int(fields[1]), int(fields[2])
                if count:
                    require(start > WORKER_UID or start + count - 1 < AUTHORITY_UID,
                            "subid_conflict", "Reserved component UID overlaps a local sub-ID range")
        deadline = time.monotonic() + 10
        checked = 0
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit():
                continue
            require(checked < 8192 and time.monotonic() <= deadline,
                    "process_scan_incomplete", "Bounded live UID occupancy scan did not complete")
            try:
                raw = self.helpers.read_bounded(entry / "status", 65536, require_size_match=False)
            except (FileNotFoundError, ProcessLookupError):
                continue
            checked += 1
            for line in raw.decode("ascii", "strict").splitlines():
                if line.startswith(("Uid:", "Gid:")):
                    values = [int(value) for value in line.split()[1:]]
                    require(not any(value in {AUTHORITY_UID, WORKER_UID} for value in values),
                            "uid_live_process_conflict", "Reserved component UID/GID has a live process")
        body = json.dumps({"schema_version": "knowledge-slice-uid-reservation.v1", "run_id": self.run_id,
                           "uids": [AUTHORITY_UID, WORKER_UID]}, sort_keys=True, separators=(",", ":")).encode()
        fd = os.open(CLAIM_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        self.claim_created = True
        try:
            st = os.fstat(fd)
            require(st.st_uid == 0 and st.st_gid == 0 and (st.st_mode & 0o7777) == 0o600,
                    "uid_claim_identity", "Exclusive UID reservation claim is not root-owned mode 0600")
            self.claim_identity = (st.st_dev, st.st_ino, sha256(body))
            view = memoryview(body)
            while view:
                count = os.write(fd, view)
                require(count > 0, "uid_claim_short_write", "UID reservation claim write was incomplete")
                view = view[count:]
            os.fsync(fd)
        finally:
            os.close(fd)

    def install_files(self) -> None:
        require(not self.install_root.exists() and not self.install_root.is_symlink(),
                "install_root_exists", "Generated install root already exists")
        os.mkdir(self.install_root, 0o755)
        self.install_created = True
        initial = self.install_root.lstat()
        require(stat.S_ISDIR(initial.st_mode) and not stat.S_ISLNK(initial.st_mode),
                "install_root_identity", "Fresh install root is not a physical directory")
        self.root_identity = (initial.st_dev, initial.st_ino)
        os.chown(self.install_root, 0, 0)
        os.chmod(self.install_root, 0o755)
        st = no_symlink_dir(self.install_root, 0, 0o755)
        require_no_acl(self.install_root)
        runtime = self.install_root / "runtime"
        mkdir_root(runtime, 0o700)
        libdir = runtime / "lib"
        mkdir_root(libdir, 0o700)

        node_st, node_body = physical_read(NODE_PATH, 256 * 1024 * 1024)
        require(len(node_body) == self.plan["node"]["bytes"] and sha256(node_body) == self.plan["node"]["sha256"],
                "node_source_changed", "Setup-node binary no longer matches its prepared pin")
        write_root_file(runtime / "node", node_body, 0o555, self.plan["node"]["sha256"], 256 * 1024 * 1024)

        inputs_dir = self.scratch / "inputs"
        no_symlink_dir(inputs_dir, RUNNER_UID, 0o700)
        for name in ("importer.js", "authority.js"):
            record = self.plan["component_sources"][name]
            st, body = physical_read(inputs_dir / name, 512 * 1024, RUNNER_UID)
            require(len(body) == record["bytes"] and sha256(body) == record["sha256"],
                    "component_source_changed", f"Staged {name} changed before install")
            write_root_file(runtime / name, body, 0o444, record["sha256"], 512 * 1024)

        for dep in self.plan["dependencies"]:
            src = Path(dep["source_path"])
            st, body = physical_read(src, 64 * 1024 * 1024)
            require(len(body) == dep["bytes"] and sha256(body) == dep["sha256"],
                    "dependency_changed", "Resolved Node dependency changed after prepare")
            write_root_file(libdir / dep["name"], body, 0o444, dep["sha256"], 64 * 1024 * 1024)

        loader = self.plan["loader"]
        loader_stat, loader_body = physical_read(Path(loader["path"]), 16 * 1024 * 1024)
        require(len(loader_body) == loader["bytes"] and sha256(loader_body) == loader["sha256"],
                "loader_changed", "ARM64 ELF loader changed after prepare")
        write_root_file(runtime / "loader", loader_body, 0o555, loader["sha256"], 16 * 1024 * 1024)
        os.chmod(libdir, 0o555)
        os.chmod(runtime, 0o555)

        native_st, native_body = physical_read(self.scratch / "native-slice", 16 * 1024 * 1024, RUNNER_UID)
        native_record = self.plan["native_binary"]
        require(len(native_body) == native_record["bytes"] and sha256(native_body) == native_record["sha256"],
                "native_changed", "Static native input changed after prepare")
        write_root_file(self.install_root / "native-slice", native_body, 0o555, native_record["sha256"], 16 * 1024 * 1024)
        write_root_file(self.install_root / "input.json", self.blob, 0o400, self.plan["blob"]["sha256"], MAX_INPUT_BYTES)
        self.result["runtime_files"] = {"node": self.plan["node"]["sha256"],
            "loader": self.plan["loader"]["sha256"], "dependencies": {x["name"]: x["sha256"] for x in self.plan["dependencies"]},
            "importer": self.plan["component_sources"]["importer.js"]["sha256"],
            "authority": self.plan["component_sources"]["authority.js"]["sha256"],
            "native": native_record["sha256"]}

    def admin(self, name: str, argv: list[str], timeout: int, expected: set[int] = {0}) -> subprocess.CompletedProcess:
        return self.helpers.bounded_command(name, argv, timeout, self.private, self.result, expected=expected)

    def inspect_unit(self) -> dict[str, str]:
        output = self.admin("systemctl-show-component", ["systemctl", "show", "--no-pager", self.unit,
            "--property=LoadState", "--property=ActiveState", "--property=MainPID", "--property=ControlGroup",
            "--property=Type", "--property=Delegate", "--property=KillMode", "--property=RuntimeMaxUSec", "--property=TimeoutStopUSec"],
            10).stdout
        values = self.helpers.parse_systemd_show(output)
        return values

    def observe_native_and_ack(self, body: bytes) -> None:
        deadline = min(getattr(self, "native_observation_deadline", time.monotonic() + 30), time.monotonic() + 30)
        def timely():
            require(time.monotonic() < deadline, "observer_deadline_expired", "Late observer work cannot acknowledge a stopped attempt")
        timely()
        require(body.endswith(b"\n") and body.count(b"\n") == 1 and len(body) <= MAX_NATIVE_JSON,
                "observer_native_shape", "Pre-ACK native proof is not one complete bounded JSON line")
        try:
            value = strict_json(body)
        except (UnicodeError, ValueError) as exc:
            raise SliceFailure("observer_native_invalid", "Pre-ACK native proof is not valid JSON") from exc
        require(not bounded_native_failure(body), "native_reported_failure", "Native reported failure before observer ACK")
        require(isinstance(value, dict) and value.get("status") == "WORK_CLOSED" and
                value.get("observer_ack_required") is True and value.get("cgroup_empty") is True,
                "observer_native_not_ready", "Native has not reported closed work and a required observer ACK")
        unit = self.inspect_unit()
        timely()
        expected = "/system.slice/" + self.unit + ".service"
        require(unit.get("ControlGroup") == expected and unit.get("Delegate") == "yes" and
                unit.get("KillMode") == "control-group" and unit.get("Type") == "exec" and
                unit.get("RuntimeMaxUSec") not in {None, "0", "infinity"} and
                unit.get("TimeoutStopUSec") not in {None, "0", "infinity"},
                "systemd_unit_contract", "Systemd unit did not retain the fixed delegation and lifetime properties")
        # The work group must still be observed while native init is held for
        # the external ACK. Its post-exit removal is not this evidence.
        self.verify_cgroup_contract(unit)
        timely()
        self.observed_unit = dict(unit)
        self.result["systemd_unit_observed_before_ack"] = True
        fifo = self.install_root / "observer.fifo"
        before = fifo.lstat()
        require(stat.S_ISFIFO(before.st_mode) and before.st_uid == 0 and before.st_gid == 0 and
                (before.st_mode & 0o7777) == 0o600 and before.st_nlink == 1,
                "observer_fifo_identity", "Native observer FIFO is not root-owned mode 0600")
        identity = (before.st_dev, before.st_ino, before.st_mode, before.st_nlink, before.st_uid, before.st_gid)
        fd = os.open(fifo, os.O_WRONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC)
        try:
            opened = os.fstat(fd)
            after = fifo.lstat()
            require(stat.S_ISFIFO(opened.st_mode) and
                    (opened.st_dev, opened.st_ino, opened.st_mode, opened.st_nlink, opened.st_uid, opened.st_gid) == identity and
                    (after.st_dev, after.st_ino, after.st_mode, after.st_nlink, after.st_uid, after.st_gid) == identity,
                    "observer_fifo_raced", "Observer FIFO identity changed during no-follow open")
            timely()
            require(os.write(fd, b"A") == 1, "observer_ack_write", "Could not write the exact one-byte observer ACK")
            timely()
        finally:
            os.close(fd)
        self.observer_acknowledged = True
        self.result["observer_acknowledged"] = True

    def run_native(self) -> tuple[int, bytes, bytes]:
        fault_mode = getattr(self, "plan", {}).get("fault_mode", 0)
        private_root = self.private / "native"
        private_root.mkdir(mode=0o700, parents=True, exist_ok=False)
        stdout_path, stderr_path = private_root / "stdout.bin", private_root / "stderr.bin"
        stdout_fd = os.open(stdout_path, os.O_RDWR | os.O_CREAT | os.O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        stderr_fd = os.open(stderr_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        native_command = ["systemd-run", "--system", "--pipe", "--wait", "--quiet", f"--unit={self.unit}",
            "--service-type=exec", "--property=Delegate=yes", "--property=KillMode=control-group",
            "--property=RuntimeMaxSec=120", "--property=TimeoutStopSec=15", "--",
            str(self.install_root / "native-slice")]
        require(native_command[0] == "systemd-run", "systemd_command_invalid", "Only fixed systemd-run may launch the native component")
        self.result["native_argv_profile"] = ["systemd-run", "--system", "--pipe", "--wait", "--quiet",
            "--unit=<generated-unit>", "--service-type=exec", "--property=Delegate=yes",
            "--property=KillMode=control-group", "--property=RuntimeMaxSec=120",
            "--property=TimeoutStopSec=15", "--", "<fresh-root-owned-native-slice>"]
        self.result["native_argv_sha256"] = sha256(json.dumps(native_command, separators=(",", ":")).encode())
        self.unit_intent = True
        process = None
        pidfd = None
        start = time.monotonic()
        self.native_observation_deadline = start + ROOT_STAGE_TIMEOUT
        timed_out = False
        output_limited = False
        next_unit_observation = start + 0.1
        try:
            process = subprocess.Popen(native_command, cwd="/", stdin=subprocess.DEVNULL, stdout=stdout_fd, stderr=stderr_fd,
                close_fds=True, shell=False, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"})
            try:
                pidfd = os.pidfd_open(process.pid, 0)
            except Exception:
                process.kill()
                try:
                    process.wait(timeout=2)
                    self.native_child_reaped = process.returncode is not None
                except subprocess.TimeoutExpired:
                    self.result["systemd_run_child_reap_confirmed"] = False
                raise SliceFailure("systemd_pidfd_unavailable", "Cannot retain exact child custody for systemd-run")
            info = Path(f"/proc/self/fdinfo/{pidfd}").read_text(encoding="ascii")
            require(f"Pid:\t{process.pid}" in info, "systemd_pidfd_invalid", "systemd-run pidfd did not bind to its direct child")
            while process.poll() is None:
                if time.monotonic() - start >= ROOT_STAGE_TIMEOUT:
                    timed_out = True
                    break
                if os.fstat(stdout_fd).st_size > MAX_NATIVE_JSON or os.fstat(stderr_fd).st_size > MAX_COMMAND_OUTPUT:
                    output_limited = True
                    break
                size = os.fstat(stdout_fd).st_size
                if fault_mode and self.observed_unit is None and time.monotonic() >= next_unit_observation:
                    unit = self.inspect_unit()
                    expected = "/system.slice/" + self.unit + ".service"
                    active = unit.get("ActiveState") == "active"
                    pending = (unit.get("LoadState") == "not-found" or
                               (unit.get("LoadState") == "loaded" and unit.get("ActiveState") in {"activating", "inactive"}))
                    require(active or (pending and time.monotonic() < start + 5),
                            "fault_unit_startup", "Fault service did not become active within its fixed startup interval")
                    next_unit_observation = time.monotonic() + 0.2
                    require(not active or (unit.get("ControlGroup") == expected and unit.get("Delegate") == "yes" and
                            unit.get("KillMode") == "control-group" and unit.get("Type") == "exec" and
                            unit.get("RuntimeMaxUSec") not in {None, "0", "infinity"} and
                            unit.get("TimeoutStopUSec") not in {None, "0", "infinity"}),
                            "fault_unit_contract", "Fault experiment did not bind its live fixed systemd envelope")
                    require(time.monotonic() < self.native_observation_deadline,
                            "observer_deadline_expired", "Fault observation arrived after its original deadline")
                    if active:
                        self.observed_unit = dict(unit)
                        self.result["systemd_unit_observed_before_fault"] = True
                if size and not self.observer_acknowledged:
                    live = os.pread(stdout_fd, min(size, MAX_NATIVE_JSON + 1), 0)
                    if live.endswith(b"\n") and fault_mode == 0:
                        self.observe_native_and_ack(live)
                time.sleep(0.025)
            if timed_out or output_limited:
                try:
                    self.helpers.signal_pidfd(pidfd, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            try:
                return_code = process.wait(timeout=3 if (timed_out or output_limited) else 5)
                self.native_child_reaped = process.returncode is not None
            except subprocess.TimeoutExpired:
                if pidfd is not None:
                    try:
                        self.helpers.signal_pidfd(pidfd, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    try:
                        process.wait(timeout=2)
                        self.native_child_reaped = process.returncode is not None
                    except subprocess.TimeoutExpired:
                        pass
                raise SliceFailure("systemd_run_reap_unconfirmed", "Could not reap the exact systemd-run child")
        finally:
            if process is not None and process.poll() is None:
                try:
                    if pidfd is not None:
                        self.helpers.signal_pidfd(pidfd, signal.SIGKILL)
                    else:
                        process.kill()
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=2)
                    self.native_child_reaped = process.returncode is not None
                except subprocess.TimeoutExpired:
                    self.native_child_reaped = False
            if process is not None and process.returncode is None:
                self.native_child_reaped = False
            self.result["systemd_run_child_reap_confirmed"] = self.native_child_reaped
            self.systemd_run_elapsed_seconds = round(time.monotonic() - start, 3)
            self.result["systemd_run_elapsed_seconds"] = self.systemd_run_elapsed_seconds
            os.close(stdout_fd); os.close(stderr_fd)
            if pidfd is not None:
                os.close(pidfd)
            try:
                out_st, raw = physical_read(stdout_path, MAX_NATIVE_JSON, 0)
                require(out_st.st_uid == 0, "native_stdout_owner", "Private native stdout is not root-owned")
                self.native_stdout_body = raw
                self.result["native_stdout_sha256"] = sha256(raw)
                self.result["native_stdout_bytes"] = len(raw)
                self.result["native_stdout_capture"] = "private_bounded_copy"
                write_new_file(self.private / "native-stdout.raw.json", raw, 0o600)
                if raw.endswith(b"\n") and raw.count(b"\n") == 1:
                    try:
                        strict_json(raw)
                    except (UnicodeError, ValueError):
                        pass
                    else:
                        self.native_json_body = raw
                        self.result["native_proof_sha256"] = sha256(raw)
            except Exception:
                self.result["native_stdout_capture"] = "unavailable_or_over_limit_private_original_retained"
        require(self.native_child_reaped, "systemd_run_reap_unconfirmed", "Exact systemd-run child exit remains unconfirmed")
        if fault_mode == 0 and not self.observer_acknowledged and bounded_native_failure(self.native_json_body):
            raise SliceFailure("native_reported_failure", "Native reported failure without an observer ACK")
        require(self.observer_acknowledged or fault_mode in {1, 2, 3, 4},
                "observer_ack_missing", "Native observer did not complete its root ACK exchange")
        require(not timed_out, "systemd_run_timeout", "Component service exceeded bounded outer wait")
        require(not output_limited, "systemd_run_output_limit", "Native or systemd output exceeded bounded storage")
        out_st, out = physical_read(stdout_path, MAX_NATIVE_JSON)
        err_st, err = physical_read(stderr_path, MAX_COMMAND_OUTPUT)
        require(out_st.st_uid == 0 and err_st.st_uid == 0, "private_output_owner", "Native output artifact is not root-owned")
        return return_code, out, err

    def parse_native(self, return_code: int, stdout: bytes) -> dict:
        require(stdout.endswith(b"\n") and stdout.count(b"\n") == 1 and len(stdout) <= MAX_NATIVE_JSON,
                "native_output_shape", "Native must emit exactly one bounded JSON line")
        try:
            value = strict_json(stdout)
        except (UnicodeError, ValueError) as exc:
            raise SliceFailure("native_output_invalid", "Native JSON output is invalid") from exc
        self.native_json_body = stdout
        self.result["native_proof_sha256"] = sha256(stdout)
        fields = {"status", "production_admission", "release_gate_qualified", "observer_ack_required", "component", "cleanup_confirmed", "fault_mode", "fault_reached",
                  "importer_namespace_drained", "importer_detached_writer_ready", "source_readonly", "authority_readback", "phase", "work_ms",
                  "cleanup_ms", "proof_emitted_ms", "stop_reason", "init_wait_status", "keeper_wait_status",
                  "worker_wait_status", "authority_wait_status", "importer_wait_status", "importer_report_hex", "cgroup_empty", "output_eof", "output_bytes",
                  "input_manifest_sha256", "directories_sha256", "output_hex"}
        if self.plan.get("fault_mode") in {3, 4}:
            fields |= DRAIN_FIELDS
        require(isinstance(value, dict) and set(value) == fields and value["status"] in {"WORK_CLOSED", "FAIL"} and
                value["production_admission"] is False and value["release_gate_qualified"] is False and
                value["observer_ack_required"] is True and value["component"] == "readonly_node_namespace",
                "native_output_contract", "Native output violated component-only contract")
        require(type(value["fault_mode"]) is int and value["fault_mode"] == self.plan.get("fault_mode", 0) and
                type(value["fault_reached"]) is bool, "native_fault_profile", "Native result does not bind the prepared fault profile")
        bools = ("cleanup_confirmed", "importer_namespace_drained", "importer_detached_writer_ready",
                 "source_readonly", "authority_readback", "cgroup_empty", "output_eof")
        require(all(type(value[name]) is bool for name in bools), "native_output_types", "Native output boolean fields are invalid")
        if value["fault_mode"] in {3, 4}:
            require(all(type(value[key]) is bool for key in DRAIN_BOOLS) and
                    all(type(value[key]) is int for key in DRAIN_INTS),
                    "native_drain_types", "Native drain observer fields have invalid types")
        nonnegative_ints = ("phase", "work_ms", "cleanup_ms", "proof_emitted_ms", "stop_reason", "output_bytes")
        wait_statuses = ("init_wait_status", "keeper_wait_status", "worker_wait_status", "authority_wait_status", "importer_wait_status")
        require(all(type(value[name]) is int and value[name] >= 0 for name in nonnegative_ints) and
                all(type(value[name]) is int and value[name] >= -1 for name in wait_statuses),
                "native_output_types", "Native output integer fields are invalid")
        require(isinstance(value["importer_report_hex"], str) and
                re.fullmatch(r"(?:[0-9a-f]{2}){0,257}", value["importer_report_hex"]) is not None,
                "native_importer_report_invalid", "Native importer receipt is not bounded hexadecimal bytes")
        if value["status"] == "WORK_CLOSED" or value["fault_mode"] in {2, 3, 4}:
            expected_import = ("KSM1 chroot_root_not_mountpoint EINVAL\n"
                f"KSI1 {self.plan['blob']['manifest_sha256']} {self.plan['blob']['directories_sha256']} "
                f"{self.plan['blob']['files']} {self.plan['blob']['total_bytes']}\n"
                "KSD1 writable_alias_ready\n").encode("ascii")
            require(bytes.fromhex(value["importer_report_hex"]) == expected_import,
                    "native_importer_report_mismatch", "Importer regression/readback receipt did not match the exact prepared input")
        no_import_receipt = value["fault_mode"] == 1 and value["status"] == "FAIL"
        require(value["output_bytes"] <= MAX_WORKER_OUTPUT and
                ((no_import_receipt and value["input_manifest_sha256"] == "" and value["directories_sha256"] == "") or
                 (value["input_manifest_sha256"] == self.plan["blob"]["manifest_sha256"] and
                  value["directories_sha256"] == self.plan["blob"]["directories_sha256"])),
                "native_output_digest", "Native result digests or output length are invalid")
        require(isinstance(value["output_hex"], str) and len(value["output_hex"]) == value["output_bytes"] * 2 and
                re.fullmatch(r"(?:[0-9a-f]{2})*", value["output_hex"]) is not None,
                "native_output_hex", "Native returned malformed bounded worker output")
        decoded = bytes.fromhex(value["output_hex"])
        write_new_file(self.private / "worker-output.bin", decoded, 0o600)
        value["worker_output_sha256"] = sha256(decoded)
        tap = tap_inventory(decoded)
        if tap is None and not no_import_receipt:
            self.record_failure("tap_inventory_mismatch")
            self.result["tap_inventory"] = {"node_version": NODE_VERSION, "expected_names": [EXPECTED_TEST_NAME],
                                             "status": "FAIL", "tests": None, "pass": None, "fail": None, "skipped": None}
        elif tap is not None:
            self.result["tap_inventory"] = {**tap, "status": "PASS"}
        else:
            self.result["tap_inventory"] = {"status": "NOT_RUN_EXPECTED_IMPORT_STALL", "tests": 0, "pass": 0}
        passed = (fault_acceptance(return_code, value, self.plan["fault_mode"], self.observer_acknowledged, self.native_child_reaped, tap)
                  if self.plan.get("fault_mode", 0) else
                  component_acceptance(return_code, value, self.observer_acknowledged, self.native_child_reaped, tap))
        if not passed:
            self.record_failure("native_component_contract_failed")
        return value

    def verify_cgroup_contract(self, values: dict[str, str]) -> None:
        root = Path("/sys/fs/cgroup")
        root_stat = root.lstat()
        require(stat.S_ISDIR(root_stat.st_mode) and not stat.S_ISLNK(root_stat.st_mode) and root_stat.st_uid == 0 and
                (root / "cgroup.controllers").is_file(), "cgroup_root_invalid", "Unified cgroup root is not physical and root-owned")
        mounts = Path("/proc/mounts").read_text(encoding="ascii", errors="strict").splitlines()
        require(any(len(row.split()) >= 3 and row.split()[1] == "/sys/fs/cgroup" and row.split()[2] == "cgroup2"
                    for row in mounts), "cgroup_v2_missing", "Expected unified cgroup v2 mount is unavailable")
        actual = values.get("ControlGroup", "")
        expected_rel = "/system.slice/" + self.unit + ".service"
        require(actual == expected_rel and self.plan["work_cgroup"] == str(root / actual.lstrip("/") / "work"),
                "cgroup_path_mismatch", "Compiled work cgroup is not the exact systemd unit child")
        service = root / actual.lstrip("/")
        work = self.work_cgroup
        for path in (service, work):
            st = path.lstat()
            require(stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode) and st.st_uid == 0 and
                    st.st_dev == root_stat.st_dev, "cgroup_directory_invalid", "Systemd cgroup directory is not root-owned physical v2")
        require_no_acl(service)
        require_no_acl(work)
        events = self.helpers.read_cgroup_events(work)
        procs = self.helpers.read_bounded(work / "cgroup.procs", 65536, require_size_match=False)
        require(events.get("populated") == 0 and not procs.strip(),
                "work_cgroup_not_empty", "Native work cgroup still contains a process after component completion")
        self.result["cgroup_contract"] = {"status": "PASS", "work_cgroup_empty": True,
                                          "cgroup_v2": True, "systemd_control_group_match": True}

    def stop_confirmed(self) -> bool:
        if not self.unit_intent:
            return True
        try:
            self.admin("systemctl-stop-owned-component", ["systemctl", "stop", self.unit], UNIT_STOP_TIMEOUT, {0, 5})
            values = self.inspect_unit()
            expected = "/system.slice/" + self.unit + ".service"
            # Bounded facts only; do not expose foreign cgroup paths/live PIDs.
            self.result["final_unit_state"] = {
                "LoadState": values.get("LoadState") if values.get("LoadState") in {"loaded", "not-found"} else "unexpected",
                "ActiveState": values.get("ActiveState") if values.get("ActiveState") in {"inactive", "failed", ""} else "unexpected",
                "MainPID": values.get("MainPID") if values.get("MainPID") in {"0", ""} else "nonzero_or_invalid",
                "ControlGroup": values.get("ControlGroup") if values.get("ControlGroup") in {expected, ""} else "foreign_or_invalid",
            }
            if values.get("ControlGroup") not in {expected, ""}:
                return False
            if values.get("LoadState") == "loaded":
                if values.get("ActiveState") not in {"inactive", "failed"} or values.get("MainPID") != "0":
                    return False
            elif values.get("LoadState") == "not-found":
                if values.get("ActiveState") not in {"inactive", "failed", ""} or values.get("MainPID") not in {"0", ""}:
                    return False
            else:
                return False
            observations = self.result["final_expected_cgroups"] = {}
            for label, group in (("service", self.service_cgroup), ("work", self.work_cgroup)):
                try:
                    identity = group.lstat()
                except FileNotFoundError:
                    observations[label] = "absent"
                    continue
                if not stat.S_ISDIR(identity.st_mode) or stat.S_ISLNK(identity.st_mode) or identity.st_uid != 0:
                    observations[label] = "unsafe"
                    return False
                try:
                    events = self.helpers.read_cgroup_events(group)
                except FileNotFoundError:
                    # GC is accepted only when the expected directory itself
                    # is independently gone, not merely its events file.
                    try:
                        group.lstat()
                    except FileNotFoundError:
                        observations[label] = "absent_after_gc"
                        continue
                    observations[label] = "unconfirmed"
                    return False
                if type(events.get("populated")) is not int or events["populated"] != 0:
                    observations[label] = "populated_or_invalid"
                    return False
                observations[label] = "empty"
            self.unit_confirmed = True
            return True
        except Exception:
            return False

    def release_claim(self) -> bool:
        if not self.claim_created:
            return True
        if not self.claim_identity:
            return False
        if not self.unit_confirmed or self.install_created:
            return False
        try:
            st, body = physical_read(CLAIM_PATH, 4096, 0)
            if (st.st_dev, st.st_ino, sha256(body)) != self.claim_identity:
                return False
            CLAIM_PATH.unlink()
            self.claim_created = False
            return True
        except Exception:
            return False

    def cleanup_install(self) -> bool:
        if not self.install_created:
            return True
        if self.root_identity is None:
            return False
        if not self.unit_confirmed or not self.native_child_reaped or self.helpers.OWNED_HELPERS or self.helpers.HELPER_UNCONFIRMED:
            return False
        try:
            remove_owned_tree(self.install_root, self.root_identity, {0, RUNNER_UID, AUTHORITY_UID, WORKER_UID})
            self.install_created = False
            return True
        except Exception:
            return False

    def write_public(self) -> None:
        named = no_symlink_dir(self.public_dir, RUNNER_UID, 0o755)
        dirfd = os.open(self.public_dir, os.O_RDONLY | os.O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        public_result = dict(self.result)
        if public_result.get("status") == "PASS_COMPONENT_QA":
            public_result["status"] = "CANDIDATE_COMPONENT_QA"
            public_result["verification_requires"] = "controller_exit_zero_and_separate_acceptance_record"
        elif public_result.get("status") == "PASS_FAULT_QA":
            public_result["status"] = "CANDIDATE_FAULT_QA"
            public_result["verification_requires"] = "controller_exit_zero_and_separate_acceptance_record"
        body = json.dumps(public_result, sort_keys=True, ensure_ascii=False, indent=2).encode("utf-8") + b"\n"
        try:
            require(len(body) <= 64 * 1024, "public_result_limit", "Sanitized public result exceeded its output bound")
            files = {}
            if self.native_json_body is not None:
                require(len(self.native_json_body) <= MAX_NATIVE_JSON and
                        self.result.get("native_proof_sha256") == sha256(self.native_json_body),
                        "public_native_proof_invalid", "Native proof bytes failed their bounded digest")
                files["NATIVE.json"] = self.native_json_body
            files["RESULT.json"] = body
            parent = os.fstat(dirfd)
            current = self.public_dir.lstat()
            require(parent.st_uid == RUNNER_UID and stat.S_ISDIR(parent.st_mode) and
                    (parent.st_mode & 0o7777) == 0o755 and
                    (parent.st_dev, parent.st_ino, parent.st_mode, parent.st_uid, parent.st_gid) ==
                    (named.st_dev, named.st_ino, named.st_mode, named.st_uid, named.st_gid) ==
                    (current.st_dev, current.st_ino, current.st_mode, current.st_uid, current.st_gid),
                    "public_directory_identity", "Public result directory identity changed")
            require_no_acl(self.public_dir)
            for dst_name in files:
                try:
                    os.stat(dst_name, dir_fd=dirfd, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                raise SliceFailure("public_result_exists", "A public result file already exists; refusing overwrite")
        except BaseException:
            os.close(dirfd)
            raise
        status_r, status_w = os.pipe2(O_CLOEXEC | O_NONBLOCK)
        try:
            pid = self.helpers.fork_owned_helper()
        except BaseException:
            # fork_owned_helper registers the child before pidfd_open. If that
            # open fails, the helper may raise with an owned child still in its
            # registry; drain it before releasing the directory/status handles.
            try:
                self.result["public_export_child_cleanup_confirmed"] = bool(
                    self.helpers.cleanup_owned_helpers())
            except BaseException:
                self.result["public_export_child_cleanup_confirmed"] = False
            os.close(status_r); os.close(status_w); os.close(dirfd)
            raise
        if pid == 0:
            os.close(status_r)
            def child_exit(code: int) -> None:
                try:
                    os.write(status_w, bytes([code]))
                except OSError:
                    pass
                os._exit(code)
            try:
                self.helpers.close_unlisted_fds({dirfd, status_w})
                self.helpers.drop_ids(RUNNER_UID, RUNNER_UID)
                for dst_name, file_body in files.items():
                    temp_name = "." + dst_name + "." + secrets.token_hex(8) + ".tmp"
                    fd = os.open(temp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                                 0o600, dir_fd=dirfd)
                    try:
                        view = memoryview(file_body)
                        while view:
                            count = os.write(fd, view)
                            if count <= 0:
                                child_exit(21)
                            view = view[count:]
                        os.fchmod(fd, 0o644)
                        os.fsync(fd)
                        file_st = os.fstat(fd)
                        if not (stat.S_ISREG(file_st.st_mode) and file_st.st_uid == RUNNER_UID and
                                file_st.st_nlink == 1 and file_st.st_size == len(file_body) and
                                (file_st.st_mode & 0o7777) == 0o644):
                            child_exit(22)
                    finally:
                        os.close(fd)
                    os.link(temp_name, dst_name, src_dir_fd=dirfd, dst_dir_fd=dirfd, follow_symlinks=False)
                    os.unlink(temp_name, dir_fd=dirfd)
                os.fsync(dirfd)
                child_exit(0)
            except BaseException:
                child_exit(23)
        os.close(status_w)
        try:
            owned = self.helpers.OWNED_HELPERS.get(pid)
            if owned is None:
                self.helpers.cleanup_owned_helpers()
                raise SliceFailure("public_child_pidfd", "Could not retain exact public export child custody")
            reaped = self.helpers.reap_exact_child(pid, owned, 5.0)
            if not reaped:
                self.helpers.cleanup_owned_helpers()
                reaped = pid not in self.helpers.OWNED_HELPERS
            require(reaped, "public_child_reap", "Public export child did not exit under bounded pidfd custody")
            os.close(owned)
            require(pid not in self.helpers.OWNED_HELPERS, "public_child_custody", "Public export child custody was not released")
            child_status = os.read(status_r, 2)
            require(child_status == b"\x00", "public_child_exit_status", "Runner-owned public export child reported failure")
        finally:
            if pid in self.helpers.OWNED_HELPERS:
                try:
                    self.result["public_export_child_cleanup_confirmed"] = bool(
                        self.helpers.cleanup_owned_helpers())
                except BaseException:
                    self.result["public_export_child_cleanup_confirmed"] = False
            os.close(status_r); os.close(dirfd)
        for dst_name, file_body in files.items():
            output_st, output = physical_read(self.public_dir / dst_name, max(64 * 1024, MAX_NATIVE_JSON), RUNNER_UID)
            require(output == file_body and output_st.st_uid == RUNNER_UID and output_st.st_nlink == 1 and
                    (output_st.st_mode & 0o7777) == 0o644,
                    "public_output_verification", "Runner-owned result failed readback")

    def run(self) -> int:
        self.private.mkdir(mode=0o700)
        os.chown(self.private, 0, 0)
        os.chmod(self.private, 0o700)
        try:
            self.reserve_uids()
            self.install_files()
            expected_unit_control = "/system.slice/" + self.unit + ".service"
            try:
                return_code, stdout, stderr = self.run_native()
                self.result["native_return_code"] = return_code
                self.result["observer_acknowledged"] = self.observer_acknowledged
                write_new_file(self.private / "systemd-run.stderr.bin", stderr, 0o600)
                native = self.parse_native(return_code, stdout)
                self.native_result = native
                self.result["native"] = {key: value for key, value in native.items() if key != "output_hex"}
                unit = self.observed_unit
                require(unit is not None and (self.observer_acknowledged if not self.plan["fault_mode"] else
                        self.result.get("systemd_unit_observed_before_fault") is True) and self.native_child_reaped,
                        "observer_or_child_unconfirmed", "Required pre-exit observer and exact child custody were not confirmed")
                require(unit.get("ControlGroup") == expected_unit_control and unit.get("Delegate") == "yes" and
                        unit.get("KillMode") == "control-group" and unit.get("Type") == "exec" and
                        unit.get("RuntimeMaxUSec") not in {None, "0", "infinity"} and
                        unit.get("TimeoutStopUSec") not in {None, "0", "infinity"},
                        "systemd_unit_contract", "Systemd unit did not retain the fixed delegation and lifetime properties")
                fault = self.plan["fault_mode"] != 0
                if return_code != (1 if fault else 0) or native["status"] != ("FAIL" if fault else "WORK_CLOSED") or self.result["reasons"]:
                    self.record_failure("component_result_not_pass")
                else:
                    self.result["status"] = "PASS_FAULT_QA" if fault else "PASS_COMPONENT_QA"
            except Exception as exc:
                self.record_failure(exc.code if isinstance(exc, SliceFailure) else "component_controller_error")
                self.result["status"] = "FAIL"
        finally:
            self.unit_confirmed = self.stop_confirmed()
            if not self.unit_confirmed:
                self.record_failure("systemd_cleanup_unconfirmed")
            cleaned = self.cleanup_install()
            if not cleaned:
                self.record_failure("install_cleanup_unconfirmed")
            self.result["host_cleanup_confirmed"] = self.unit_confirmed and cleaned
            released = self.release_claim()
            if not released:
                self.record_failure("uid_reservation_preserved")
            if self.result["status"] in {"PASS_COMPONENT_QA", "PASS_FAULT_QA"} and (
                    not self.result["host_cleanup_confirmed"] or not released):
                self.result["status"] = "FAIL"
            try:
                private_record = {"schema_version": "knowledge-linux-service-private-run.v1", "result": self.result,
                                  "plan_sha256": sha256(json.dumps(self.plan, sort_keys=True, separators=(",", ":")).encode()),
                                  "source_paths_and_toolchain": {"node": str(NODE_PATH),
                                      "component_dir": str(component_sources()), "install_root": str(self.install_root),
                                      "claim_path": str(CLAIM_PATH)}}
                write_new_file(self.private / "private-result.json",
                               json.dumps(private_record, sort_keys=True, indent=2).encode() + b"\n", 0o600)
            except Exception:
                self.record_failure("private_result_write_failed")
                self.result["status"] = "FAIL"
            self.write_public()
        return 0 if self.result["status"] in {"PASS_COMPONENT_QA", "PASS_FAULT_QA"} else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="phase", required=True)
    prepare = sub.add_parser("prepare", help="compile and pin fixed component inputs as ordinary UID 1001")
    prepare.add_argument("--fault", choices=tuple(FAULT_PROFILES), default="none")
    run = sub.add_parser("run", help="install and run one fixed component experiment as the root controller")
    run.add_argument("--run-id", required=True)
    args = parser.parse_args(argv)
    if args.phase == "prepare":
        return run_prepare(args.fault)
    try:
        return RootRun(args.run_id).run()
    except SliceFailure as exc:
        print(json.dumps({"status": "FAIL", "reason": exc.code}, sort_keys=True), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
