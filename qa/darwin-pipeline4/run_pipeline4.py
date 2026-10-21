#!/usr/bin/env python3
"""Pinned, private-evidence Darwin pipeline4 diagnostic runner.

This only reports scoped diagnostics. Its separate QA binary contains a
compile-time persistence boundary gate; neither binary is qualified here.
"""
from pathlib import Path
import argparse
import hashlib
import json
import math
import os
import platform
import plistlib
import re
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid

from persistence_gate import persistence_gate_as_root

SCHEMA = "knowledge-darwin-pipeline4-pins.v1"
SUMMARY_SCHEMA = "knowledge-darwin-pipeline4-public-summary.v1"
UID_SCAN_SHA256 = "cf8245dc0e1c564c50ecbb9b8114ab50c74e1c89daf8a9bcc9bc239456bb2ebc"
HEX64 = re.compile(r"^[a-f0-9]{64}$")
COPY_LIMITS = {"max_files": 20000, "max_bytes": 1073741824,
               "max_file_bytes": 67108864}


class QAError(RuntimeError):
    def __init__(self, stage):
        self.stage = stage
        super().__init__(stage)


def sha_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha_file(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def private_file(path, data):
    path = Path(path)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) & 0o077:
            raise QAError("private_evidence_permissions")
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)


def public_file(path, data):
    path = Path(path)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 getattr(os, "O_NOFOLLOW", 0), 0o644)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_uid != os.getuid():
            raise QAError("public_artifact_permissions")
        os.fchmod(fd, 0o644)
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)


class Runner:
    def __init__(self, pins_path, evidence_root, expected_arch, public_evidence_dir, only_d2=False):
        self.pins_path = Path(pins_path).absolute()
        self.workspace = Path.cwd().resolve(strict=True)
        self.evidence = Path(evidence_root)
        self.public_evidence_dir = Path(public_evidence_dir)
        self.expected_arch = expected_arch
        self.only_d2 = bool(only_d2)
        self.d2_attempted = {"active_runtime": False, "startup_replay": False}
        self.records = []
        self.fixture = None
        self.fixture_initialized = False
        self.fixture_service_registered = False
        self.label = None
        self.bootstrapped = False
        self.broker_pid = None
        self.uid_scan = None
        self.descriptor = None
        self.pins = None
        self.source = None
        self.account_policy = None
        self.project_roots = []
        self.project_app_pins = {}
        self.fixture_source_layout = []
        self.boolean_wire_record = None
        self.task_uids = set()
        self.binaries = {}
        self.binary_history = []
        self.compile_counter = 0
        self.fixture_counter = 0
        self.compiler_diagnostics = []
        self.diagnostic_attempts = []
        self.runtime_pins = []
        self.installed_bindings = []
        self.diagnostic_proofs = []
        self.native_allocations = []
        self.expected_allocation_ids = set()
        self.diagnostic_summary = None
        self.status = "FAIL"
        self.failed_stage = None
        self.primary_failed_stage = None
        self.cleanup_failed_stage = None
        self.command_pid = None
        self.role_birth_unconfirmed = False
        self.host_security = {"sip_status": "unknown", "csrutil_stdout_sha256": None,
                              "csrutil_exit_code": None}

    def run(self, name, argv, timeout=120, data=None, root=False):
        safe_name = "%03d-%s" % (len(self.records), re.sub(r"[^a-zA-Z0-9_.-]", "_", name))
        out = self.evidence / (safe_name + ".stdout.raw")
        err = self.evidence / (safe_name + ".stderr.raw")
        started = time.monotonic()
        timed_out = False
        try:
            p = subprocess.run(argv, input=data, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, timeout=timeout,
                               shell=False, check=False)
        except subprocess.TimeoutExpired as error:
            timed_out = True
            stdout = error.stdout or b""
            stderr = error.stderr or b""
            if isinstance(stdout, str): stdout = stdout.encode()
            if isinstance(stderr, str): stderr = stderr.encode()
            p = subprocess.CompletedProcess(argv, None, stdout, stderr)
        private_file(out, p.stdout)
        private_file(err, p.stderr)
        self.records.append({"name": safe_name, "exit_code": p.returncode,
            "timed_out": timed_out, "elapsed_ms": round((time.monotonic() - started) * 1000, 3),
            "stdout_sha256": sha_bytes(p.stdout), "stderr_sha256": sha_bytes(p.stderr),
            "root_command": bool(root)})
        if name.startswith("compile-"):
            self.compiler_diagnostics.append({"stage": name, "exit_code": p.returncode,
                "timed_out": timed_out, "elapsed_ms": round((time.monotonic() - started) * 1000, 3),
                "stdout_sha256": sha_bytes(p.stdout), "stderr_sha256": sha_bytes(p.stderr),
                "stdout_excerpt": self.compiler_excerpt(p.stdout),
                "stderr_excerpt": self.compiler_excerpt(p.stderr)})
        return p

    def compiler_excerpt(self, data):
        text = data.decode("utf-8", errors="replace")
        for path, replacement in ((str(self.source or ""), "<pinned-source>"),
                                  (str(self.evidence), "<private-evidence>"),
                                  (str(self.fixture or ""), "<fixture>")):
            if path:
                text = text.replace(path, replacement)
        return "\n".join(line[:300] for line in text.splitlines()[:8])[:1600]

    def safe_cli_text(self, value):
        text = str(value)
        for path, replacement in ((str(self.source or ""), "<pinned-source>"),
                                  (str(self.evidence), "<private-evidence>"),
                                  (str(self.fixture or ""), "<fixture>")):
            if path:
                text = text.replace(path, replacement)
        text = re.sub(r"\b[a-fA-F0-9]{24,64}\b", "<opaque-hex>", text)
        text = re.sub(r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b",
                      "<redacted-token>", text)
        return text[:500]

    def safe_cli_stderr(self, data):
        text = data.decode("utf-8", errors="replace")
        for path, replacement in ((str(self.source or ""), "<pinned-source>"),
                                  (str(self.evidence), "<private-evidence>"),
                                  (str(self.fixture or ""), "<fixture>")):
            if path:
                text = text.replace(path, replacement)
        text = re.sub(r"\b[a-fA-F0-9]{24,64}\b", "<opaque-hex>", text)
        text = re.sub(r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b",
                      "<redacted-token>", text)
        return "\n".join(line[:300] for line in text.splitlines()[:8])[:1600]

    def sudo(self, *argv, **kwargs):
        return self.run(kwargs.pop("name", "root-command"),
                        ["/usr/bin/sudo", "-n", *map(str, argv)], root=True, **kwargs)

    def check(self, condition, stage):
        if not condition:
            raise QAError(stage)

    def load_pins(self):
        expected_pins = self.workspace / "qa/darwin-pipeline4/PINS.json"
        self.check(self.pins_path == expected_pins, "pins_path_unexpected")
        pin_stat = self.pins_path.lstat()
        self.check(stat.S_ISREG(pin_stat.st_mode) and not stat.S_ISLNK(pin_stat.st_mode),
                   "pins_path_unsafe")
        try:
            pins = json.loads(self.pins_path.read_bytes())
        except Exception:
            raise QAError("pins_json_invalid")
        self.check(isinstance(pins, dict) and pins.get("schema") == SCHEMA and
                   pins.get("status") == "ready", "pins_not_ready")
        self.check(pins.get("source_root") == "input/source", "source_root_unexpected")
        source_lexical = self.workspace / "qa/darwin-pipeline4/input/source"
        source_stat = source_lexical.lstat()
        source = source_lexical.resolve(strict=True)
        self.check(stat.S_ISDIR(source_stat.st_mode) and not stat.S_ISLNK(source_stat.st_mode) and
                   source.parent == (self.workspace / "qa/darwin-pipeline4/input").resolve(strict=True),
                   "source_root_unsafe")
        files = pins.get("files")
        self.check(isinstance(files, list) and bool(files), "source_file_pins_missing")
        seen = set()
        for row in files:
            self.check(isinstance(row, dict) and set(row) == {"path", "sha256", "bytes"} and
                       isinstance(row["path"], str) and isinstance(row["sha256"], str) and
                       HEX64.fullmatch(row["sha256"]) and type(row["bytes"]) is int and row["bytes"] >= 0,
                       "source_file_pin_invalid")
            rel = Path(row["path"])
            self.check(not rel.is_absolute() and ".." not in rel.parts and "\\" not in row["path"] and
                       row["path"] not in seen, "source_file_path_invalid")
            seen.add(row["path"])
            path = source / rel
            resolved = path.resolve(strict=True)
            self.check(resolved.is_relative_to(source) and path.is_file() and not path.is_symlink() and
                       path.stat().st_size == row["bytes"] and sha_file(path) == row["sha256"],
                       "source_file_pin_mismatch")
        native = pins.get("native")
        self.check(isinstance(native, dict) and set(native) == {
            "broker", "stub", "history_header", "history_source", "transport_header"},
            "native_paths_invalid")
        for name, rel in native.items():
            self.check(isinstance(rel, str) and rel in seen, "native_path_not_pinned")
        qa = pins.get("qa")
        self.check(isinstance(qa, dict) and set(qa) == {"build_id", "socket_relative"} and
                   HEX64.fullmatch(qa.get("build_id", "")) and
                   qa.get("socket_relative") == "qa/gate.sock", "qa_pin_invalid")
        diagnostic = pins.get("diagnostic_cli")
        self.check(isinstance(diagnostic, str) and diagnostic in seen, "diagnostic_cli_not_pinned")
        self.pins, self.source = pins, source
        broker_text = (source / native["broker"]).read_text(encoding="utf-8")
        policy = re.search(r'^#define K_ACCOUNT_POLICY @"([A-Za-z0-9_.-]{1,128})"$',
                           broker_text, re.MULTILINE)
        self.check(policy is not None, "native_account_policy_pin_missing")
        self.account_policy = policy.group(1)

    def make_private_evidence(self):
        root = self.evidence
        if root.exists() or root.is_symlink():
            raise QAError("evidence_root_exists")
        root.mkdir(mode=0o700, parents=True)
        st = root.lstat()
        self.check(stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode) and
                   st.st_uid == os.getuid() and stat.S_IMODE(st.st_mode) == 0o700,
                   "evidence_root_permissions")

    def compile_pair(self, qa_enabled):
        n, root = self.pins["native"], self.source
        paths = {key: root / n[key] for key in n}
        digests = {key: sha_file(path) for key, path in paths.items()}
        for row in self.pins["files"]:
            if row["path"] in n.values():
                self.check(digests[next(key for key, value in n.items() if value == row["path"])] == row["sha256"],
                           "native_pin_drift")
        kind = "qa" if qa_enabled else "shipping"
        self.compile_counter += 1
        instance = "%s-%02d" % (kind, self.compile_counter)
        binary = self.evidence / ("broker-" + instance)
        stub = self.evidence / ("stub-" + instance)
        defs = ["-DKNOWLEDGE_BROKER_SOURCE_SHA=\"" + digests["broker"] + "\"",
                "-DKNOWLEDGE_DARWIN_STUB_SOURCE_SHA=\"" + digests["stub"] + "\"",
                "-DKNOWLEDGE_DARWIN_UID_HISTORY_HEADER_SHA=\"" + digests["history_header"] + "\"",
                "-DKNOWLEDGE_DARWIN_UID_HISTORY_SOURCE_SHA=\"" + digests["history_source"] + "\"",
                "-DKNOWLEDGE_DARWIN_TRANSPORT_HEADER_SHA=\"" + digests["transport_header"] + "\""]
        if qa_enabled:
            socket_path = self.fixture / self.pins["qa"]["socket_relative"]
            defs += ["-DKNOWLEDGE_DARWIN_QA_IO=1",
                     "-DKNOWLEDGE_DARWIN_QA_SOCKET_PATH=\"" + str(socket_path) + "\"",
                     "-DKNOWLEDGE_DARWIN_QA_BUILD_ID=\"" + self.pins["qa"]["build_id"] + "\""]
        argv = ["/usr/bin/clang", "-fobjc-arc", "-Wall", "-Wextra",
                "-Wno-deprecated-declarations", "-framework", "Foundation",
                *defs, "-I", str(paths["broker"].parent), str(paths["broker"]),
                str(paths["history_source"]), "-o", str(binary)]
        result = self.run("compile-" + instance + "-broker", argv, timeout=180)
        self.check(result.returncode == 0, "compile_" + kind + "_broker_failed")
        broker_hash = sha_file(binary)
        stub_argv = ["/usr/bin/clang", "-std=c11", "-D_DARWIN_C_SOURCE", "-O2",
            "-Wall", "-Wextra", "-Wno-deprecated-declarations",
            "-DKNOWLEDGE_BROKER_BINARY_SHA=\"" + broker_hash + "\"",
            "-DKNOWLEDGE_BROKER_SOURCE_SHA=\"" + digests["broker"] + "\"",
            "-DKNOWLEDGE_DARWIN_STUB_SOURCE_SHA=\"" + digests["stub"] + "\"",
            str(paths["stub"]), "-o", str(stub)]
        result = self.run("compile-" + instance + "-stub", stub_argv, timeout=180)
        self.check(result.returncode == 0, "compile_" + kind + "_stub_failed")
        stub_hash = sha_file(stub)
        describe = self.run("describe-" + instance + "-stub", [str(stub), "--describe"], timeout=15)
        try: pair = json.loads(describe.stdout)
        except Exception: pair = None
        self.check(describe.returncode == 0 and pair == {
            "schema": "knowledge-darwin-stub.v1", "broker_binary_sha256": broker_hash,
            "broker_source_sha256": digests["broker"], "stub_source_sha256": digests["stub"],
            "capability_qualified": False}, "stub_pair_mismatch_" + kind)
        self.binaries[kind] = {"broker": binary, "stub": stub, "instance": instance,
            "broker_sha256": broker_hash, "stub_sha256": stub_hash,
            "source_sha256": digests["broker"], "stub_source_sha256": digests["stub"],
            "history_header_sha256": digests["history_header"],
            "history_source_sha256": digests["history_source"],
            "transport_header_sha256": digests["transport_header"],
            "qa_io_enabled": bool(qa_enabled), "qa_build_id": self.pins["qa"]["build_id"] if qa_enabled else None}
        self.binary_history.append({"kind": kind, "instance": instance, "broker_sha256": broker_hash,
            "stub_sha256": stub_hash, "source_sha256": digests["broker"],
            "stub_source_sha256": digests["stub"], "qa_io_enabled": bool(qa_enabled),
            "qa_build_id": self.pins["qa"]["build_id"] if qa_enabled else None,
            "qa_socket_path_sha256": sha_bytes(str(self.fixture / self.pins["qa"]["socket_relative"]).encode())
                if qa_enabled else None})

    def fixture_path(self):
        self.bootstrapped = False
        self.fixture_initialized = False
        self.fixture_service_registered = False
        self.broker_pid = None
        self.descriptor = None
        path = Path(tempfile.mkdtemp(prefix="knowledge-pipeline4.", dir="/private/tmp"))
        if path.parent.resolve(strict=True) != Path("/private/tmp").resolve(strict=True) or path.is_symlink():
            raise QAError("fixture_path_unsafe")
        self.fixture = path
        self.fixture_counter += 1
        self.label = "org.knowledgekit.rc5.pipeline4." + uuid.uuid4().hex[:16]
        self.root("protect-fixture", "/usr/sbin/chown", "0:0", str(path))
        self.root("mode-fixture", "/bin/chmod", "0711", str(path))

    def root(self, name, *argv, timeout=30, data=None):
        p = self.sudo(*argv, name=name, timeout=timeout, data=data)
        self.check(p.returncode == 0, name + "_failed")
        return p

    def root_dir(self, name, mode):
        p = self.fixture / name
        self.root("mkdir-" + name.replace("/", "-"), "/bin/mkdir", str(p))
        self.root("chown-" + name.replace("/", "-"), "/usr/sbin/chown", "0:0", str(p))
        self.root("chmod-" + name.replace("/", "-"), "/bin/chmod", mode, str(p))
        return p

    def setup_fixture(self, kind, run_at_load=True):
        for name, mode in (("bin", "0711"), ("runtime", "0711"), ("control", "0711"),
            ("registry", "0700"), ("workspaces", "0711"), ("logs", "0700"),
            ("launchd", "0700"), ("allocator", "0700"), ("anchors", "0755")):
            self.root_dir(name, mode)
        if kind == "qa":
            self.root_dir("qa", "0700")
        binary = self.fixture / "bin/broker"
        stub = self.fixture / "bin/knowledge-native-stub"
        node = self.fixture / "runtime/node"
        actual_node = self.node_path()
        for name, source, target in (("broker", self.binaries[kind]["broker"], binary),
                                     ("stub", self.binaries[kind]["stub"], stub),
                                     ("node", actual_node, node)):
            self.root("install-" + kind + "-" + name, "/usr/bin/install", "-o", "0", "-g", "0", "-m", "0555", str(source), str(target))
            source_digest, installed_digest = sha_file(source), sha_file(target)
            self.check(installed_digest == source_digest, "installed_" + name + "_hash_mismatch")
            self.installed_bindings.append({"fixture_index": self.fixture_counter, "service_kind": kind,
                "role": name, "source_sha256": source_digest, "installed_sha256": installed_digest})
        self.runtime_pins.append({"fixture_index": self.fixture_counter,
            "source_node_sha256": sha_file(actual_node), "installed_node_sha256": sha_file(node)})
        sock = self.fixture / "control/broker.sock"
        if kind == "qa":
            qa_sock = self.fixture / self.pins["qa"]["socket_relative"]
            self.check(qa_sock.parent == self.fixture / "qa", "qa_socket_path_invalid")
        else:
            qa_sock = None
        stdout, stderr = self.fixture / "logs/daemon.stdout.log", self.fixture / "logs/daemon.stderr.log"
        for name, p in (("stdout", stdout), ("stderr", stderr)):
            self.root("touch-log-" + kind + "-" + name, "/usr/bin/touch", str(p))
            self.root("mode-log-" + kind + "-" + name, "/bin/chmod", "0600", str(p))
        roots = {"registry": self.fixture / "registry", "allocator": self.fixture / "allocator",
                 "anchors": self.fixture / "anchors", "workspaces": self.fixture / "workspaces",
                 "socket": sock, "runtime": node}
        root_options = ["--" + k + "=" + str(v) for k, v in roots.items()]
        init = [str(binary), "--init-install", "--qualification-mode",
            "--confirm-reserved-uid-range=1000000000:1900000000",
                "--account-policy=" + self.account_policy, "--allow-owner=" + str(os.getuid()), *root_options]
        initialized = self.sudo(*init, name="init-" + kind, timeout=90)
        try: init_reply = json.loads(initialized.stdout)
        except Exception: init_reply = None
        self.check(initialized.returncode == 0 and isinstance(init_reply, dict) and init_reply.get("ok") is True,
                   "init_" + kind + "_failed")
        self.fixture_initialized = True
        argv = [str(binary), "--serve", "--qualification-mode", *root_options]
        plist = {"Label": self.label, "ProgramArguments": argv, "RunAtLoad": run_at_load,
                 "KeepAlive": False, "StandardOutPath": str(stdout), "StandardErrorPath": str(stderr)}
        if qa_sock:
            plist["Sockets"] = {"KnowledgeQAPersistenceGate": {
                "SockPathName": str(qa_sock), "SockPathMode": 0o600}}
        stage = self.evidence / ("launchd-%s-%02d.plist" % (kind, self.fixture_counter))
        private_file(stage, plistlib.dumps(plist, fmt=plistlib.FMT_XML, sort_keys=True))
        plist_path = self.fixture / "launchd/job.plist"
        self.root("install-plist-" + kind, "/usr/bin/install", "-o", "0", "-g", "0", "-m", "0444", str(stage), str(plist_path))
        self.bootstrapped = True
        boot = self.sudo("/bin/launchctl", "bootstrap", "system", str(plist_path), name="bootstrap-" + kind, timeout=45)
        if boot.returncode:
            self.bootstrapped = not self.label_absent()
            self.check(False, "bootstrap_" + kind + "_failed")
        self.fixture_service_registered = True
        if run_at_load:
            self.check(self.label_exists(timeout=20), "launchd_label_not_active_" + kind)
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline and not sock.exists():
                time.sleep(.1)
            self.check(sock.exists() and stat.S_ISSOCK(sock.lstat().st_mode),
                       "public_service_socket_not_ready_" + kind)
            probe = self.native_request({"binary": binary, "socket": sock},
                {"op": "probe"}, "probe-" + kind + "-pair")
            self.check(probe.get("source_sha256") == self.binaries[kind]["source_sha256"] and
                       probe.get("qa_persistence_gate") is (kind == "qa") and
                       probe.get("qa_build_id") == (self.pins["qa"]["build_id"] if kind == "qa" else None),
                       "service_pair_mode_mismatch_" + kind)
            self.records.append({"name": "service_pair_probe_verified", "service_kind": kind,
                "source_pin_verified": True, "qualification_mode": True, "backend_qualified": False})
        else:
            self.check(not self.label_exists(timeout=2), "demand_service_started_before_socket_connect")
        return {"binary": binary, "stub": stub, "node": node, "socket": sock,
                "qa_socket": qa_sock, "roots": roots}

    def node_path(self):
        located = shutil.which("node")
        self.check(bool(located), "node_not_found")
        result = self.run("node-exec-path", [located, "-p", "process.execPath"], timeout=10)
        self.check(result.returncode == 0, "node_exec_path_failed")
        path = Path(result.stdout.decode().strip()).resolve(strict=True)
        libs = self.run("node-system-dylibs", ["/usr/bin/otool", "-L", str(path)], timeout=15)
        self.check(libs.returncode == 0, "node_dylib_scan_failed")
        deps = [line.strip().split(" ", 1)[0] for line in libs.stdout.decode(errors="replace").splitlines()[1:] if line.strip()]
        self.check(all(dep.startswith(("/System/Library/", "/usr/lib/")) for dep in deps),
                   "node_has_non_system_dynamic_dependency")
        return path

    def label_exists(self, timeout=10):
        p = self.run("launchctl-print-own-label", ["/usr/bin/sudo", "-n", "/bin/launchctl", "print", "system/" + self.label], timeout=timeout)
        match = re.search(rb"\bpid\s*=\s*([0-9]+)", p.stdout)
        if match:
            self.broker_pid = int(match.group(1))
        return p.returncode == 0 and match is not None

    def label_absent(self):
        p = self.run("launchctl-verify-own-label-absent", ["/usr/bin/sudo", "-n", "/bin/launchctl",
            "print", "system/" + self.label], timeout=10)
        expected = ('Could not find service "' + self.label + '" in domain for system').encode()
        return p.returncode == 113 and p.stderr.splitlines() == [b"Bad request.", expected]

    def native_request(self, fixture_info, request, name, timeout=15):
        data = canonical(request)
        p = self.run(name, [str(fixture_info["binary"]), "--request",
                      "--socket=" + str(fixture_info["socket"])],
                      timeout=timeout, data=data)
        try: value = json.loads(p.stdout)
        except Exception: value = None
        self.check(p.returncode == 0 and isinstance(value, dict) and value.get("ok") is True,
                   name + "_typed_result_invalid")
        return value

    def copy_source_tree(self, project, full_runtime=True):
        target = project / ".knowledge"
        target.mkdir(mode=0o700)
        copied_count = 0
        if full_runtime:
            for row in self.pins["files"]:
                rel = Path(row["path"])
                if not rel.parts or rel.parts[0] != ".knowledge":
                    continue
                src = self.source / rel
                st = src.lstat()
                resolved = src.resolve(strict=True)
                if not resolved.is_relative_to(self.source) or not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode) or st.st_size != row["bytes"] or sha_file(src) != row["sha256"]:
                    raise QAError("project_source_changed_during_copy")
                dst = target.joinpath(*rel.parts[1:])
                dst.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                fd = os.open(str(src), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
                try:
                    pieces = []
                    remaining = st.st_size + 1
                    while remaining:
                        chunk = os.read(fd, min(1024 * 1024, remaining))
                        if not chunk: break
                        pieces.append(chunk)
                        remaining -= len(chunk)
                    copied = b"".join(pieces)
                finally:
                    os.close(fd)
                self.check(len(copied) == st.st_size == row["bytes"] and sha_bytes(copied) == row["sha256"],
                           "project_source_readback_mismatch")
                private_file(dst, copied)
                copied_count += 1
            self.check(copied_count == len(self.pins["files"]), "full_source_copy_count_mismatch")
            # Diagnostics are read-only except for their own private state roots.
            (project / "fixtures").mkdir(mode=0o700)
            self.project_roots.append(project)
        self.fixture_source_layout.append({"project_id": project.name,
            "kind": "full_source_copy" if full_runtime else "state_only",
            "source_files": copied_count})
        return target

    def verify_pins_unchanged(self):
        for row in self.pins["files"]:
            path = self.source / row["path"]
            self.check(path.is_file() and not path.is_symlink() and path.stat().st_size == row["bytes"] and sha_file(path) == row["sha256"],
                       "source_mutated_during_run")
            rel = Path(row["path"])
            if rel.parts and rel.parts[0] == ".knowledge":
                copied_rel = Path(*rel.parts[1:])
                for project in self.project_roots:
                    copied = project / ".knowledge" / copied_rel
                    self.check(copied.is_file() and not copied.is_symlink() and copied.stat().st_size == row["bytes"] and sha_file(copied) == row["sha256"],
                               "copied_source_mutated_during_run")
        for path, expected in self.project_app_pins.items():
            self.check(path.is_file() and not path.is_symlink() and sha_file(path) == expected,
                       "original_project_source_mutated_during_run")

    @staticmethod
    def measured_timings_ms(value):
        names = ("work_elapsed_ms", "cleanup_elapsed_ms", "elapsed_ms", "monitor_elapsed_ms")
        measured = {}
        for name in names:
            number = value.get(name) if isinstance(value, dict) else None
            valid_integer = type(number) is int and number >= 0
            valid_float = type(number) is float and math.isfinite(number) and number >= 0
            measured[name] = number if valid_integer or valid_float else None
        return measured

    def run_diagnostic(self, info, project, argv, sources, name, timeout=480,
                   expected_status="diagnostic_completed"):
        for source_name, script_bytes in sources.items():
            script = project / source_name
            script.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            script.write_bytes(script_bytes)
            self.project_app_pins[script] = sha_bytes(script_bytes)
        state = project / ".knowledge"
        request = {"report_only": True, "repoRoot": str(project), "stateRoot": str(state),
            "test": {"argv": argv, "cwd": ".", "timeout_ms": 30000},
            "sourceFiles": list(sources),
            "nativeExecution": {"darwin": {"enabled": True, "mode": "isolated_copy",
                "broker_path": str(info["binary"]), "broker_socket": str(info["socket"]),
                "copy": COPY_LIMITS}},
            "verificationPolicy": {"work_budget_ms": 300000, "cleanup_budget_ms": 60000,
                "no_progress_ms": 0}}
        request_path = self.evidence / (name + ".request.private.json")
        private_file(request_path, canonical(request))
        node = info["node"]
        cli = self.source / self.pins["diagnostic_cli"]
        p = self.run(name + "-diagnostic-cli", [str(node), str(cli), str(request_path)],
                     timeout=timeout)
        outer_record = self.records[-1] if self.records else {}
        runner_process_elapsed = self.measured_timings_ms({"elapsed_ms": outer_record.get("elapsed_ms")})["elapsed_ms"]
        try: result = json.loads(p.stdout)
        except Exception: result = None
        try: stderr_json = json.loads(p.stderr)
        except Exception: stderr_json = None
        diagnostic_attempt = {"name": name, "attempted": True, "status": "FAIL",
            "expected_status": expected_status,
            "cli_exit_code": p.returncode, "timed_out": p.returncode is None,
            "stdout_bytes": len(p.stdout), "stdout_sha256": sha_bytes(p.stdout),
            "stdout_typed_json": isinstance(result, dict),
            "stderr_bytes": len(p.stderr), "stderr_sha256": sha_bytes(p.stderr),
            "stderr_json_parsed": isinstance(stderr_json, dict),
            "stderr_json_code": None, "stderr_json_reason": None,
            "stderr_excerpt": None if isinstance(stderr_json, dict) else self.safe_cli_stderr(p.stderr),
            "timings_ms": self.measured_timings_ms(result),
            "runner_observed_process_elapsed_ms": runner_process_elapsed,
            "typed_result": None}
        if isinstance(stderr_json, dict):
            nested_error = stderr_json.get("error")
            diagnostic_attempt["stderr_json_code"] = self.safe_cli_text(
                stderr_json.get("code", nested_error.get("code") if isinstance(nested_error, dict) else "") or "")
            diagnostic_attempt["stderr_json_reason"] = self.safe_cli_text(
                stderr_json.get("reason", nested_error.get("reason", nested_error.get("message", ""))
                    if isinstance(nested_error, dict) else "") or "")
        if isinstance(result, dict):
            command = result.get("command") if isinstance(result.get("command"), dict) else {}
            authority_exit = result.get("authority_exit") if isinstance(result.get("authority_exit"), dict) else {}
            diagnostic_attempt["typed_result"] = {
                "status": self.safe_cli_text(result.get("status", "")),
                "reason": self.safe_cli_text(result.get("reason", "")),
                "code": self.safe_cli_text(result.get("code", "")),
                "timings_ms": self.measured_timings_ms(result),
                "role_exit": {"command_exit_code": command.get("exit_code"),
                    "command_signal": self.safe_cli_text(command.get("signal", "")),
                    "authority_exit_code": authority_exit.get("exit_code"),
                    "authority_signal": self.safe_cli_text(authority_exit.get("signal", "")),
                    "authority_method": self.safe_cli_text(result.get("authority_exit_method", ""))}}
        self.check(not self.has_secret_key(diagnostic_attempt), name + "_diagnostic_attempt_public_unsafe")
        self.diagnostic_attempts.append(diagnostic_attempt)
        early_failure_proof_exported = False
        if isinstance(result, dict) and result.get("status") == "failed":
            terminal_observation = result.get("native_terminal_observation")
            if isinstance(terminal_observation, dict):
                observation_fields = ("state", "stop_reason", "admission_closed",
                    "allocation_tuple_verified_current", "registry_healthy",
                    "cleanup_budget_exceeded", "proof_sha256", "command_drain_sha256",
                    "proof_current")
                safe_observation = {key: terminal_observation[key]
                    for key in observation_fields if key in terminal_observation}
                observed_proof = terminal_observation.get("proof")
                if observed_proof is not None:
                    safe_observation["proof"] = observed_proof
                authority_exit = result.get("authority_exit")
                safe_authority_exit = ({key: authority_exit.get(key) for key in ("exit_code", "signal")
                    if key in authority_exit} if isinstance(authority_exit, dict) else None)
                failure_proof = {"name": name + "-unexpected-failure-observation",
                    "status": "failed", "reason": self.safe_cli_text(result.get("reason", "")),
                    "native_terminal_observation": safe_observation,
                    "authority_exit": safe_authority_exit,
                    "timings_ms": self.measured_timings_ms(result)}
                self.check(not self.has_secret_key(failure_proof),
                    name + "_unexpected_failure_proof_public_unsafe")
                self.diagnostic_proofs.append(failure_proof)
                early_failure_proof_exported = True
        expect_cli_exit = 0 if expected_status == "diagnostic_completed" else 1
        self.check(p.returncode == expect_cli_exit and isinstance(result, dict) and
                   result.get("status") == expected_status and
                   result.get("report_only") in (True, None) and
                   result.get("production_acceptance") is False and
                   result.get("capability_qualified") in (False, None) and
                   result.get("kve_created") is False and result.get("kvf_created") is False and
                   result.get("ack_created") is False, name + "_diagnostic_failed")
        two_phase = False
        if expected_status in ("diagnostic_completed", "command_failed"):
            drain = result.get("command_drain_proof")
            terminal = result.get("native_terminal_proof")
            authority_exit = result.get("authority_exit")
            two_phase = (isinstance(drain, dict) and isinstance(terminal, dict) and
                drain.get("schema") == "knowledge-darwin-command-drain-proof.v1" and
                drain.get("native_command_drain_facts_confirmed") is True and
                drain.get("command_drain_confirmed") is False and
                drain.get("admission_closed") is True and drain.get("capability_qualified") is False and
                terminal.get("schema") == "knowledge-darwin-private-ruid-proof.v1" and
                terminal.get("native_cleanup_facts_confirmed") is True and
                terminal.get("cleanup_confirmed") is False and terminal.get("terminal_cleanup") is True and
                terminal.get("capability_qualified") is False and isinstance(authority_exit, dict) and
                authority_exit.get("exit_code") is None and authority_exit.get("signal") == "SIGKILL" and
                result.get("authority_exit_method") == "native_exact_terminal_stop_then_child_handle_exit")
            self.check(two_phase, name + "_two_phase_drain_close_proof_invalid")
            descriptor = result.get("reservation", {}).get("descriptor", {})
            uid = descriptor.get("task_ruid") if isinstance(descriptor, dict) else None
            if isinstance(uid, int) and 1000000000 <= uid < 1900000000:
                self.task_uids.add(uid)
            reservation = result.get("reservation")
            if isinstance(reservation, dict) and isinstance(reservation.get("descriptor"), dict):
                self.descriptor = reservation
                self.expected_allocation_ids.add(reservation.get("attempt_id"))
            proof_record = {"name": name, "status": result["status"],
                "attempt_id": reservation.get("attempt_id") if isinstance(reservation, dict) else None,
                "descriptor_sha256": reservation.get("descriptor_sha256") if isinstance(reservation, dict) else None,
                "readbacks": result.get("readbacks"), "command_drain_proof": drain,
                "native_terminal_proof": terminal,
                "authority_exit": authority_exit,
                "authority_exit_method": result.get("authority_exit_method"),
                "command_result": {key: result.get("command", {}).get(key)
                    for key in ("ok", "exit_code", "signal", "timed_out", "stop_latched", "admission_closed")},
                "timings_ms": self.measured_timings_ms(result)}
            self.check(not self.has_secret_key(proof_record), name + "_public_proof_contains_secret_key")
            self.diagnostic_proofs.append(proof_record)
        elif expected_status == "failed":
            terminal_observation = result.get("native_terminal_observation")
            failure_reservation = result.get("reservation")
            if isinstance(failure_reservation, dict) and isinstance(failure_reservation.get("descriptor"), dict):
                self.expected_allocation_ids.add(failure_reservation.get("attempt_id"))
                self.descriptor = failure_reservation
            if isinstance(terminal_observation, dict):
                observed_proof = terminal_observation.get("proof")
                failure_proof = {"name": name, "status": result["status"],
                    "reason": result.get("reason"),
                    "attempt_id": failure_reservation.get("attempt_id") if isinstance(failure_reservation, dict) else terminal_observation.get("attempt_id"),
                    "descriptor_sha256": failure_reservation.get("descriptor_sha256") if isinstance(failure_reservation, dict) else terminal_observation.get("descriptor_sha256"),
                    "terminal_state": terminal_observation.get("state"),
                    "admission_closed": terminal_observation.get("admission_closed"),
                    "proof": observed_proof,
                    "authority_exit": result.get("authority_exit"),
                    "timings_ms": self.measured_timings_ms(result)}
                if not early_failure_proof_exported:
                    self.check(not self.has_secret_key(failure_proof), name + "_failure_proof_public_unsafe")
                    self.diagnostic_proofs.append(failure_proof)
        # The complete result (which may contain private bindings) remains in the
        # private raw output file. Only this typed subset escapes into summary.
        self.diagnostic_summary = {"name": name, "status": result["status"],
            "report_only": True, "production_acceptance": False,
            "capability_qualified": False, "command_exit_code": result.get("command", {}).get("exit_code"),
            "command_signal": result.get("command", {}).get("signal"),
            "timings_ms": self.measured_timings_ms(result),
            "cleanup_status": result.get("cleanup_status", "native_terminal_confirmed"),
            "kve_created": False, "kvf_created": False, "ack_created": False}
        self.records.append({"name": name, "diagnostic_status": result["status"],
            "command_exit_code": result.get("command", {}).get("exit_code"),
            "command_signal": result.get("command", {}).get("signal"),
            "expected_status": expected_status,
            "report_only_contract": expected_status in ("diagnostic_completed", "command_failed", "failed"),
            "two_phase_drain_close_proofs": two_phase,
            "producer_writeback_absent": result.get("kve_created") is False and
                result.get("kvf_created") is False and result.get("ack_created") is False})
        diagnostic_attempt["status"] = "PASS"
        return result

    def reservation_binding(self, project):
        root = project / ".knowledge/maintenance/darwin-diagnostics"
        candidates = sorted(root.glob("*/reservation.json"), key=lambda p: p.stat().st_mtime_ns, reverse=True)
        self.check(bool(candidates), "reservation_not_observed")
        path = candidates[0]
        st = path.lstat()
        self.check(stat.S_ISREG(st.st_mode) and not stat.S_ISLNK(st.st_mode) and
                   st.st_nlink == 1 and st.st_uid == os.getuid() and st.st_size <= 65536,
                   "reservation_file_unsafe")
        value = json.loads(path.read_bytes())
        self.check(isinstance(value, dict) and isinstance(value.get("attempt_id"), str) and
                   HEX64.fullmatch(value["attempt_id"]) and
                   isinstance(value.get("descriptor_sha256"), str) and HEX64.fullmatch(value["descriptor_sha256"]) and
                   isinstance(value.get("descriptor"), dict) and
                   sha_bytes(canonical(value["descriptor"])) == value["descriptor_sha256"] and
                   value["descriptor"].get("attempt_id") == value["attempt_id"] and
                   not self.has_secret_key(value), "reservation_binding_invalid")
        self.descriptor = value
        self.expected_allocation_ids.add(value["attempt_id"])
        return value

    @staticmethod
    def has_secret_key(value):
        if isinstance(value, dict):
            return any(k.lower() in {"token", "secret", "password", "credential"} or Runner.has_secret_key(v)
                       for k, v in value.items())
        if isinstance(value, list):
            return any(Runner.has_secret_key(v) for v in value)
        return False

    def arm_active_gate(self, info, project, binding_ready, marker_ready):
        # This runtime-only point is armed only after the command marker and
        # exact durable reservation binding are both present.
        for _ in range(600):
            if binding_ready.is_set() and marker_ready.is_set():
                break
            time.sleep(.1)
        self.check(binding_ready.is_set() and marker_ready.is_set(), "active_gate_precondition_timeout")
        binding = self.reservation_binding(project)
        descriptor = binding["descriptor"]
        workspace = descriptor.get("workspace_path")
        expected_parent = (self.fixture / "workspaces").resolve(strict=True)
        self.check(isinstance(workspace, str) and Path(workspace).parent.resolve(strict=True) == expected_parent,
                   "workspace_path_outside_fixture")
        marker = Path(workspace) / "ready.marker"
        marker_probe = self.sudo("/bin/test", "-f", str(marker), name="confirm-active-private-marker")
        self.check(marker_probe.returncode == 0, "active_marker_missing")
        observe = {"op": "observe", "source_sha256": self.binaries["qa"]["source_sha256"],
                   "attempt_id": binding["attempt_id"], "descriptor_sha256": binding["descriptor_sha256"]}
        def pending(_entered):
            self.role_birth_unconfirmed = True
            self.check(self.label_exists(timeout=5) and self.broker_pid == _entered.get("broker_pid"),
                       "active_gate_broker_identity_mismatch")
            before = self.native_request(info, observe, "observe-active-before-stop")
            self.check(before.get("attempt_id") == binding["attempt_id"] and
                       before.get("descriptor_sha256") == binding["descriptor_sha256"] and
                       before.get("capability_qualified") is False,
                       "active_role_observation_mismatch")
            state = self.fixture_registry_snapshot()
            entry = state.get("attempts", {}).get(binding["attempt_id"]) if isinstance(state, dict) else None
            self.check(isinstance(entry, dict) and entry.get("descriptor_sha256") == binding["descriptor_sha256"],
                       "active_registry_birth_record_missing")
            descriptor = entry.get("descriptor", {})
            command_identity = entry.get("command_identity")
            authority_identity = entry.get("authority")
            self.check(isinstance(command_identity, dict) and isinstance(authority_identity, dict) and
                       command_identity.get("pid") == self.command_pid,
                       "active_exact_births_missing")
            self.active_birth_observations = {
                "command": self.capture_birth(command_identity, descriptor["task_ruid"], str(info["node"])),
                "authority": self.capture_birth(authority_identity, descriptor["owner_uid"], str(info["node"]))}
            self.active_birth_identities = (command_identity, authority_identity)
            # Signal only the direct monitor Popen handle. Its own IPC sends
            # cancellation to the exact controller, which performs authorized
            # native stop. Never PID-kill an authority/command cached in state.
            stop_signal_at = time.monotonic()
            self.active_monitor.send_signal(signal.SIGINT)
            deadline = time.monotonic() + 30
            after = None
            while time.monotonic() < deadline:
                after = self.native_request(info, observe, "observe-after-stop")
                if after.get("stop_latched") is True:
                    break
                time.sleep(.1)
            self.check(after.get("stop_latched") is True and after.get("proof_current") is False and
                       after.get("resources_free") is False and after.get("observation_cached") is True,
                       "stop_fence_not_observed")
            def wait_exact_birth_stopped(identity, label):
                deadline_birth = time.monotonic() + 30
                zombie_seen = False
                while time.monotonic() < deadline_birth:
                    observation = self.compare_birth(identity)
                    state_name = observation.get("state")
                    if state_name in ("absent", "replaced"):
                        return {"state_before_stop": "same_running", "state_after_stop": state_name,
                            "execution_stopped": True, "birth_absent": True, "waitpid_observed": False,
                            "resources_free": False,
                            "same_zombie_seen": zombie_seen,
                            "latency_ms": round((time.monotonic() - stop_signal_at) * 1000, 3)}
                    if state_name == "same_zombie":
                        return {"state_before_stop": "same_running", "state_after_stop": state_name,
                            "execution_stopped": True, "birth_absent": False, "waitpid_observed": False,
                            "resources_free": False, "same_zombie_seen": True,
                            "latency_ms": round((time.monotonic() - stop_signal_at) * 1000, 3)}
                    elif state_name != "same_running":
                        raise QAError(label + "_birth_unavailable")
                    time.sleep(.1)
                raise QAError(label + ("_zombie_not_reaped" if zombie_seen else "_still_running"))
            self.command_birth_terminal = wait_exact_birth_stopped(command_identity, "command")
            self.authority_birth_terminal = wait_exact_birth_stopped(authority_identity, "authority")
        gate = persistence_gate_as_root(str(info["qa_socket"]), uuid.uuid4().hex + "00000000000000000000000000000000",
            "history_journal_read", self.pins["qa"]["build_id"], pending,
            str(Path(__file__).with_name("persistence_gate.py")))
        self.check(gate["completed"] is True, "active_gate_not_completed")
        self.check(gate["persistence_result_ok"] is True, "active_real_history_read_failed")
        def wait_birth_reaped(identity, label):
            deadline_reaped = time.monotonic() + 30
            while time.monotonic() < deadline_reaped:
                observation = self.compare_birth(identity)
                state_name = observation.get("state")
                if state_name in ("absent", "replaced"):
                    return {"state_after_release": state_name, "birth_absent": True, "waitpid_observed": False}
                if state_name not in ("same_running", "same_zombie"):
                    raise QAError(label + "_post_release_birth_unavailable")
                time.sleep(.1)
            raise QAError(label + "_post_release_reap_unconfirmed")
        if hasattr(self, "active_birth_identities"):
            command_reaped = wait_birth_reaped(self.active_birth_identities[0], "command")
            authority_reaped = wait_birth_reaped(self.active_birth_identities[1], "authority")
            self.command_birth_terminal["post_release"] = command_reaped
            self.authority_birth_terminal["post_release"] = authority_reaped
            self.role_birth_unconfirmed = False
        final_status = self.native_request(info, {"op": "status",
            "source_sha256": self.binaries["qa"]["source_sha256"],
            "attempt_id": binding["attempt_id"], "descriptor_sha256": binding["descriptor_sha256"]},
            "status-after-late-release")
        terminal_proof = final_status.get("proof")
        self.check(final_status.get("state") == "closed" and
                   final_status.get("admission_closed") is True and
                   final_status.get("spawn_intent") is False and
                   final_status.get("authority_spawn_intent") is False and
                   final_status.get("capability_qualified") is False and
                   isinstance(terminal_proof, dict) and terminal_proof.get("terminal_cleanup") is True and
                   terminal_proof.get("native_cleanup_facts_confirmed") is True and
                   terminal_proof.get("cleanup_confirmed") is False and
                   terminal_proof.get("admission_closed") is True and
                   terminal_proof.get("capability_qualified") is False,
                   "late_release_terminal_status_invalid")
        if isinstance(terminal_proof, dict):
            public_proof = {"name": "d2-active-terminal", "attempt_id": binding["attempt_id"],
                "descriptor_sha256": binding["descriptor_sha256"], "proof": terminal_proof}
            self.check(not self.has_secret_key(public_proof), "d2_terminal_proof_public_unsafe")
            self.diagnostic_proofs.append(public_proof)
        self.records.append({"name": "active_runtime_history_gate", "entered": True,
            "completed": True, "persistence_result_ok": gate["persistence_result_ok"],
            "gate_kind": gate["gate_kind"], "late_release_stop_fence_observed": True,
            "attempt_binding_verified": True, "terminal_state": final_status.get("state"),
            "command_birth_initial_state": self.active_birth_observations["command"].get("state"),
            "authority_birth_initial_state": self.active_birth_observations["authority"].get("state"),
            "command_birth_terminal": self.command_birth_terminal,
            "authority_birth_terminal": self.authority_birth_terminal,
            "resource_free_claimed": False})

    def startup_gate(self, info):
        self.require_test_utility()
        self.d2_attempted["startup_replay"] = True
        def pending(_entered):
            self.check(self.label_exists(timeout=5) and self.broker_pid == _entered.get("broker_pid"),
                       "startup_gate_broker_identity_mismatch")
            observed = self.native_request(info, {"op": "observe",
                "source_sha256": self.binaries["qa"]["source_sha256"]}, "observe-startup-pending")
            self.check(observed.get("state") == "initializing_or_idle" and
                       observed.get("durability_pending") is True and
                       observed.get("allocation_tuple_verified_current") is False,
                       "startup_pending_observation_invalid")
        gate = persistence_gate_as_root(str(info["qa_socket"]), uuid.uuid4().hex + "00000000000000000000000000000000",
            "history_journal_read", self.pins["qa"]["build_id"], pending,
            str(Path(__file__).with_name("persistence_gate.py")))
        self.check(gate["completed"] is True, "startup_gate_not_completed")
        self.check(gate["persistence_result_ok"] is True, "startup_real_history_read_failed")
        self.records.append({"name": "startup_history_gate", "entered": True,
            "completed": True, "startup_pending_observed": True,
            "persistence_result_ok": gate["persistence_result_ok"], "gate_kind": gate["gate_kind"]})
        self.check(self.label_exists(timeout=15), "startup_service_not_resumed_after_release")
        probe = self.native_request(info, {"op": "probe"}, "probe-startup-qa-pair")
        self.check(probe.get("qa_persistence_gate") is True and
                   probe.get("qa_build_id") == self.pins["qa"]["build_id"],
                   "startup_service_qa_pair_mismatch")
        self.verify_pins_unchanged()

    def compile_uid_scan(self):
        source = self.workspace / "qa/darwin-broker/uid-scan.c"
        digest = sha_file(source)
        self.check(digest == UID_SCAN_SHA256, "uid_scan_source_pin_mismatch")
        output = self.evidence / "uid-scan"
        result = self.run("compile-uid-scan", ["/usr/bin/clang", "-std=c11", "-O2", "-Wall", "-Wextra",
            str(source), "-o", str(output)], timeout=60)
        self.check(result.returncode == 0, "uid_scan_compile_failed")
        self.uid_scan = output

    def require_test_utility(self):
        utility = Path("/bin/test")
        self.check(utility.is_file() and os.access(utility, os.X_OK),
                   "darwin_test_utility_missing")

    def compile_boolean_wire(self):
        source = self.workspace / "qa/darwin-pipeline4/boolean-wire.m"
        digest = sha_file(source)
        output = self.evidence / "boolean-wire"
        compile_result = self.run("compile-boolean-wire", ["/usr/bin/clang", "-x", "objective-c",
            "-fobjc-arc", "-Wall", "-Wextra", "-Werror", "-framework", "Foundation",
            "-framework", "CoreFoundation", str(source), "-o", str(output)], timeout=60)
        self.check(compile_result.returncode == 0, "boolean_wire_compile_failed")
        execution = self.run("run-boolean-wire", [str(output)], timeout=15)
        self.check(execution.returncode == 0, "boolean_wire_json_type_regression_failed")
        self.boolean_wire_record = {"status": "PASS", "source_sha256": digest,
            "compile_exit_code": compile_result.returncode, "run_exit_code": execution.returncode,
            "boolean_fields_verified": 5, "truth_values_checked": 2, "numeric_control_verified": True,
            "stdout_bytes": len(execution.stdout), "stdout_sha256": sha_bytes(execution.stdout)}

    def fixture_registry_snapshot(self):
        registry = self.fixture / "registry/registry.json"
        reader = ("import os,stat,sys; p=sys.argv[1]; "
            "\ntry: fd=os.open(p,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)) "
            "\nexcept FileNotFoundError: raise SystemExit(44) "
            "\nst=os.fstat(fd); "
            "\nif not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_nlink!=1 or stat.S_IMODE(st.st_mode)&0o077 or st.st_size>1048576: raise SystemExit(45) "
            "\ndata=b'' "
            "\nwhile True:\n chunk=os.read(fd,65536)\n if not chunk: break\n data+=chunk\n if len(data)>1048576: raise SystemExit(45) "
            "\nos.close(fd); sys.stdout.buffer.write(data)")
        read = self.run("read-own-protected-registry", ["/usr/bin/sudo", "-n", sys.executable,
            "-c", reader, str(registry)], timeout=15, root=True)
        if read.returncode == 44 and not self.fixture_initialized:
            return None
        self.check(read.returncode == 0, "native_registry_unreadable_or_unsafe")
        try:
            state = json.loads(read.stdout)
        except Exception:
            raise QAError("native_registry_json_invalid")
        return state

    def collect_fixture_allocations(self):
        state = self.fixture_registry_snapshot()
        if state is None:
            return
        attempts = state.get("attempts") if isinstance(state, dict) else None
        active = state.get("active_attempt") if isinstance(state, dict) else None
        self.check(isinstance(state, dict) and state.get("schema") == "knowledge-darwin-broker.v1" and
                   isinstance(attempts, dict) and isinstance(active, str) and
                   (active == "" or active in attempts), "native_registry_shape_invalid")
        self.check(active == "" and all(isinstance(entry, dict) and entry.get("state") == "closed"
                   for entry in attempts.values()), "native_registry_terminal_state_unconfirmed")
        observed_ids = set()
        for attempt_id, entry in attempts.items():
            self.check(isinstance(attempt_id, str) and HEX64.fullmatch(attempt_id) and
                       isinstance(entry, dict) and isinstance(entry.get("descriptor"), dict),
                       "native_registry_attempt_invalid")
            descriptor = entry["descriptor"]
            digest = entry.get("descriptor_sha256")
            uid = descriptor.get("task_ruid")
            self.check(descriptor.get("attempt_id") == attempt_id and
                       isinstance(digest, str) and HEX64.fullmatch(digest) and
                       sha_bytes(canonical(descriptor)) == digest and
                       type(uid) is int and 1000000000 <= uid < 1900000000,
                       "native_registry_descriptor_invalid")
            observed_ids.add(attempt_id)
            self.task_uids.add(uid)
            public = {"fixture_index": self.fixture_counter, "attempt_id": attempt_id,
                "descriptor_sha256": digest, "task_ruid": uid, "state": entry.get("state"),
                "allocation_seq": descriptor.get("allocation_seq"),
                "allocation_sha256": descriptor.get("allocation_sha256"),
                "source_sha256": descriptor.get("source_sha256"),
                "broker_binary_sha256": descriptor.get("broker_binary_sha256"),
                "stub_source_sha256": descriptor.get("stub_source_sha256"),
                "stub_binary_sha256": descriptor.get("stub_binary_sha256"),
                "capability_qualified": descriptor.get("capability_qualified"),
                "qualification_mode": descriptor.get("qualification_mode")}
            self.check(not self.has_secret_key(public), "native_allocation_public_record_unsafe")
            self.native_allocations.append(public)
        expected = getattr(self, "expected_allocation_ids", set())
        self.check(expected.issubset(observed_ids), "reported_allocation_missing_from_registry")
        self.expected_allocation_ids = set()
        self.records.append({"name": "native_registry_allocation_inventory",
            "fixture_index": self.fixture_counter, "allocations": len(attempts),
            "allocation_bindings_verified": True})

    def capture_birth(self, identity, expected_ruid, expected_image):
        self.check(isinstance(identity, dict) and type(identity.get("pid")) is int and
                   isinstance(identity.get("unique_id"), str) and
                   isinstance(identity.get("start_sec"), (int, str)) and
                   isinstance(identity.get("start_usec"), (int, str)), "native_birth_identity_invalid")
        result = self.sudo(str(self.birth_observer), str(identity["pid"]),
                           name="capture-native-process-birth", timeout=5)
        try: value = json.loads(result.stdout)
        except Exception: value = None
        self.check(result.returncode == 0 and isinstance(value, dict) and
                   value.get("state") == "same_running" and value.get("pid") == identity["pid"] and
                   value.get("ruid") == expected_ruid and value.get("image") == expected_image and
                   str(value.get("unique_id")) == str(identity["unique_id"]) and
                   str(value.get("start_sec")) == str(identity["start_sec"]) and
                   str(value.get("start_usec")) == str(identity["start_usec"]),
                   "native_birth_capture_mismatch")
        return value

    def compile_birth_observer(self):
        source = self.workspace / "qa/darwin-pipeline4/birth-observer.c"
        self.check(source.is_file() and not source.is_symlink(), "birth_observer_source_missing")
        digest = sha_file(source)
        output = self.evidence / "birth-observer"
        result = self.run("compile-birth-observer", ["/usr/bin/clang", "-std=c11", "-O2",
            "-D_DARWIN_C_SOURCE", "-Wall", "-Wextra", "-Werror", str(source), "-o", str(output)], timeout=60)
        self.check(result.returncode == 0, "birth_observer_compile_failed")
        self.birth_observer = output
        self.birth_observer_pin = {"source_sha256": digest, "binary_sha256": sha_file(output)}

    def compare_birth(self, identity, expected_ruid=None, expected_image=None):
        result = self.sudo(str(self.birth_observer), str(identity["pid"]), identity["unique_id"],
            str(identity["start_sec"]), str(identity["start_usec"]),
            name="compare-native-process-birth", timeout=5)
        try: value = json.loads(result.stdout)
        except Exception: value = None
        self.check(result.returncode == 0 and isinstance(value, dict) and
                   value.get("schema") == "knowledge-darwin-qa-birth.v1" and
                   value.get("pid") == identity["pid"] and
                   value.get("state") in ("absent", "replaced", "same_running", "same_zombie", "unavailable"),
                   "native_birth_comparison_invalid")
        if value.get("state") in ("same_running", "same_zombie"):
            self.check(str(value.get("unique_id")) == str(identity["unique_id"]) and
                       str(value.get("start_sec")) == str(identity["start_sec"]) and
                       str(value.get("start_usec")) == str(identity["start_usec"]),
                       "native_birth_identity_changed")
        return value

    def cleanup(self):
        if getattr(self, "active_monitor", None) is not None and self.active_monitor.poll() is None:
            self.active_monitor.send_signal(signal.SIGINT)
            try:
                self.active_monitor.wait(timeout=75)
            except subprocess.TimeoutExpired:
                self.active_monitor.kill()
                try: self.active_monitor.wait(timeout=10)
                except subprocess.TimeoutExpired: self.check(False, "direct_monitor_exit_unconfirmed")
        if not self.fixture:
            return
        if self.label and self.bootstrapped:
            if self.broker_pid is None:
                self.label_exists(timeout=5)
            stop = self.sudo("/bin/launchctl", "bootout", "system/" + self.label,
                             name="bootout-own-launchd-label", timeout=60)
            deadline = time.monotonic() + 20
            absent = False
            while time.monotonic() < deadline:
                absent = self.label_absent()
                if absent: break
                time.sleep(.25)
            self.bootstrapped = not absent
            self.check(stop.returncode == 0 and absent, "launchd_bootout_unconfirmed")
        if self.bootstrapped:
            return
        if self.broker_pid is not None:
            process_exit_confirmed = False
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                ps = self.sudo("/bin/ps", "-p", str(self.broker_pid), "-o", "command=",
                               name="confirm-own-broker-exit", timeout=5)
                if ps.returncode == 1 and not ps.stdout.strip():
                    process_exit_confirmed = True
                    break
                if ps.returncode != 0:
                    break
                cmd = ps.stdout.decode("utf-8", errors="replace").strip()
                if str(self.fixture / "bin/broker") not in cmd:
                    # PID may have been reused; do not treat that as a reap.
                    break
                time.sleep(.25)
            self.check(process_exit_confirmed, "root_broker_exit_unconfirmed")
        self.collect_fixture_allocations()
        uid_clear = True
        for uid in sorted(self.task_uids):
            scan = self.run("post-stop-private-uid-scan", [str(self.uid_scan), str(uid)], timeout=20)
            uid_clear = uid_clear and scan.returncode == 0
            if not uid_clear: break
        self.check(uid_clear, "private_uid_membership_unconfirmed")
        self.check(not self.role_birth_unconfirmed, "exact_role_birth_unconfirmed_preserve_fixture")
        inspect = ("import json,os,stat,sys; p=sys.argv[1]; s=os.lstat(p); "
            "print(json.dumps({'directory':stat.S_ISDIR(s.st_mode),'symlink':stat.S_ISLNK(s.st_mode),"
            "'uid':s.st_uid,'mode':stat.S_IMODE(s.st_mode),'parent_ok':os.path.realpath(os.path.dirname(p))==os.path.realpath('/private/tmp'),"
            "'name_ok':os.path.basename(p).startswith('knowledge-pipeline4.')},separators=(',',':')))")
        root_check = self.sudo(sys.executable, "-c", inspect, str(self.fixture),
                               name="lstat-own-fixture-before-remove", timeout=10)
        try: fixture_check = json.loads(root_check.stdout)
        except Exception: fixture_check = None
        self.check(root_check.returncode == 0 and isinstance(fixture_check, dict) and
                   fixture_check.get("directory") is True and fixture_check.get("symlink") is False and
                   fixture_check.get("uid") == 0 and fixture_check.get("mode") == 0o711 and
                   fixture_check.get("parent_ok") is True and fixture_check.get("name_ok") is True,
                   "fixture_cleanup_path_invalid")
        removed = self.sudo("/bin/rm", "-rf", "--", str(self.fixture), name="remove-own-fixture", timeout=60)
        self.check(removed.returncode == 0, "fixture_cleanup_failed")
        self.records.append({"name": "fixture_cleanup", "launchd_absent": True,
            "root_broker_exit_confirmed": True, "private_uid_scan_clear": uid_clear,
            "fixture_removed": True})
        self.fixture = None

    def execute(self):
        self.check(platform.system() == "Darwin", "requires_darwin")
        arch = platform.machine()
        self.check(arch == self.expected_arch, "runner_architecture_mismatch")
        self.make_private_evidence()
        sip = self.run("observe-csrutil-status", ["/usr/bin/csrutil", "status"], timeout=10)
        sip_text = sip.stdout.decode("utf-8", errors="replace").lower()
        sip_state = "enabled" if "status: enabled" in sip_text else (
            "disabled" if "status: disabled" in sip_text else "unknown")
        self.host_security = {"sip_status": sip_state,
            "csrutil_stdout_sha256": sha_bytes(sip.stdout), "csrutil_exit_code": sip.returncode}
        self.load_pins()
        self.compile_uid_scan()
        self.compile_boolean_wire()
        self.compile_birth_observer()
        if not self.only_d2:
            self.compile_pair(False)
            self.fixture_path()
            normal = self.setup_fixture("shipping")
            project = self.evidence / "project-d1"
            project.mkdir(mode=0o700)
            self.copy_source_tree(project)
            script = b"'use strict';\nconsole.log('pipeline4-diagnostic-script-ok');\n"
            self.run_diagnostic(normal, project, ["node", "fixtures/main.js"],
                            {"fixtures/main.js": script}, "d1-script")
            project_test = self.evidence / "project-d1-node-test"
            project_test.mkdir(mode=0o700)
            self.copy_source_tree(project_test, full_runtime=False)
            test = b"'use strict';\nconst test=require('node:test');\nconst assert=require('node:assert/strict');\ntest('pipeline4 diagnostic test',()=>assert.equal(2+2,4));\n"
            self.run_diagnostic(normal, project_test, ["node", "--test", "fixtures/main.test.js"],
                            {"fixtures/main.test.js": test}, "d1-node-test")
            project_failing = self.evidence / "project-d1-failing-command"
            project_failing.mkdir(mode=0o700)
            self.copy_source_tree(project_failing, full_runtime=False)
            failing = b"'use strict';\nprocess.exitCode=7;\n"
            result = self.run_diagnostic(normal, project_failing, ["node", "fixtures/failing.js"],
                            {"fixtures/failing.js": failing}, "d1-failing-command",
                            expected_status="command_failed")
            self.check(result.get("command", {}).get("exit_code") == 7,
                       "failing_command_exit_not_preserved")
            project_mutation = self.evidence / "project-d1-copy-mutation"
            project_mutation.mkdir(mode=0o700)
            self.copy_source_tree(project_mutation, full_runtime=False)
            original = b"'use strict';\nmodule.exports='pinned-copy';\n"
            mutation = ("'use strict';\nconst fs=require('node:fs');\n"+
                        "fs.writeFileSync('fixtures/source.js','mutated');\n").encode()
            result = self.run_diagnostic(normal, project_mutation, ["node", "fixtures/mutate.js"],
                            {"fixtures/source.js": original, "fixtures/mutate.js": mutation},
                            "d1-copy-mutation", expected_status="failed")
            self.check(result.get("reason") == "COPY_READBACK_UNCONFIRMED", "copy_mutation_not_refused")
            self.verify_pins_unchanged()
        # A separate QA service fixture ensures the gate binary path macro and
        # its protected socket are rooted in this own disposable service.
        self.cleanup()
        self.fixture_path()
        self.compile_pair(True)
        qa = self.setup_fixture("qa", run_at_load=True)
        project2 = self.evidence / "project-d2"
        project2.mkdir(mode=0o700)
        self.copy_source_tree(project2, full_runtime=False)
        script2 = ("'use strict';\nconst fs=require('node:fs');\n"+
                   "fs.writeFileSync('ready.marker',JSON.stringify({pid:process.pid})+'\\n',{flag:'wx',mode:0o600});\n"+
                   "setInterval(()=>{},1000);\n").encode()
        # Start one long-running diagnostic in the controller process; the
        # command only creates a private marker then remains silent.
        self.start_active_diagnostic(qa, project2, script2)
        self.cleanup()
        self.fixture_path()
        self.compile_pair(True)
        startup = self.setup_fixture("qa", run_at_load=False)
        self.startup_gate(startup)
        self.cleanup()
        self.status = "PASS_DIAGNOSTIC_ONLY"

    def start_active_diagnostic(self, info, project, script_bytes):
        # Start the diagnostic directly while retaining its stdout/stderr in
        # the private evidence directory. The reservation and copied marker are
        # observed before the QA persistence point is armed.
        self.require_test_utility()
        script = project / "fixtures/long.js"
        script.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        script.write_bytes(script_bytes)
        self.project_app_pins[script] = sha_bytes(script_bytes)
        request = {"report_only": True, "repoRoot": str(project), "stateRoot": str(project / ".knowledge"),
            "test": {"argv": ["node", "fixtures/long.js"], "cwd": ".", "timeout_ms": 30000},
            "sourceFiles": ["fixtures/long.js"],
            "nativeExecution": {"darwin": {"enabled": True, "mode": "isolated_copy",
                "broker_path": str(info["binary"]), "broker_socket": str(info["socket"]), "copy": COPY_LIMITS}},
            "verificationPolicy": {"work_budget_ms": 300000, "cleanup_budget_ms": 60000, "no_progress_ms": 0}}
        request_path = self.evidence / "d2-active.request.private.json"
        private_file(request_path, canonical(request))
        cli = self.source / self.pins["diagnostic_cli"]
        stdout = (self.evidence / "d2-active.stdout.raw").open("xb")
        stderr = (self.evidence / "d2-active.stderr.raw").open("xb")
        os.chmod(stdout.name, 0o600); os.chmod(stderr.name, 0o600)
        proc = subprocess.Popen([str(info["node"]), str(cli), str(request_path)], stdin=subprocess.DEVNULL,
            stdout=stdout, stderr=stderr, shell=False)
        self.active_monitor = proc
        self.d2_attempted["active_runtime"] = True
        monitor_started = time.monotonic()
        binding_ready = threading.Event()
        marker_ready = threading.Event()
        failures = []
        def watch_binding():
            try:
                deadline = time.monotonic() + 180
                while time.monotonic() < deadline and proc.poll() is None:
                    try:
                        binding = self.reservation_binding(project)
                        self.descriptor = binding
                        self.active_binding = binding
                        binding_ready.set()
                        descriptor = binding["descriptor"]
                        workspace = Path(descriptor["workspace_path"])
                        if workspace.parent.resolve(strict=True) != (self.fixture / "workspaces").resolve(strict=True):
                            raise QAError("workspace_path_outside_fixture")
                        marker = self.sudo("/bin/test", "-f", str(workspace / "ready.marker"),
                                           name="poll-private-command-marker", timeout=5)
                        if marker.returncode == 0:
                            marker_data = self.sudo("/bin/cat", str(workspace / "ready.marker"),
                                name="read-private-command-marker", timeout=5)
                            try: marker_value = json.loads(marker_data.stdout)
                            except Exception: marker_value = None
                            if (marker_data.returncode == 0 and isinstance(marker_value, dict) and
                                    type(marker_value.get("pid")) is int and marker_value["pid"] > 0):
                                self.command_pid = marker_value["pid"]
                                marker_ready.set(); return
                    except (FileNotFoundError, QAError, KeyError, ValueError):
                        pass
                    time.sleep(.1)
                raise QAError("active_private_marker_timeout")
            except BaseException as error:
                failures.append(error)
        watcher = threading.Thread(target=watch_binding, daemon=True)
        watcher.start()
        watcher.join(180)
        if proc.poll() is not None:
            early_result = None
            try: early_result = json.loads((self.evidence / "d2-active.stdout.raw").read_bytes())
            except Exception: pass
            if isinstance(early_result, dict) and early_result.get("status") == "failed":
                early_projection = {"name": "d2-active-early-cli-failure",
                    "status": "failed", "reason": self.safe_cli_text(early_result.get("reason", "")),
                    "exit_code": proc.returncode if proc.returncode >= 0 else None,
                    "signal": -proc.returncode if proc.returncode < 0 else None,
                    "timings_ms": self.measured_timings_ms(early_result),
                    "runner_elapsed_ms": round((time.monotonic() - monitor_started) * 1000, 3)}
                self.check(not self.has_secret_key(early_projection), "d2_early_failure_public_unsafe")
                self.diagnostic_proofs.append(early_projection)
        self.check(not watcher.is_alive() and not failures and binding_ready.is_set() and marker_ready.is_set(),
                   "active_reservation_marker_not_observed")
        binding = self.active_binding
        try:
            self.arm_active_gate(info, project, binding_ready, marker_ready)
        except BaseException:
            if proc.poll() is None:
                proc.send_signal(signal.SIGINT)
                try: proc.wait(timeout=75)
                except subprocess.TimeoutExpired: proc.kill(); proc.wait(timeout=10)
            stdout.close(); stderr.close()
            raise
        try:
            proc.wait(timeout=90)
        except subprocess.TimeoutExpired:
            self.check(False, "active_diagnostic_did_not_finish_after_late_release")
        finally:
            stdout.close(); stderr.close()
        self.check(proc.returncode != 0, "active_diagnostic_unexpected_success_after_stop")
        try: result = json.loads((self.evidence / "d2-active.stdout.raw").read_bytes())
        except Exception: result = None
        self.check(isinstance(result, dict) and result.get("status") == "failed" and
                   result.get("production_acceptance") is False and result.get("kve_created") is False and
                   result.get("kvf_created") is False and result.get("ack_created") is False,
                   "active_diagnostic_terminal_result_invalid")
        observed_terminal = result.get("native_terminal_observation")
        failed_proof = {"name": "d2-active-cancel-report", "status": result.get("status"),
            "reason": result.get("reason"), "attempt_id": binding["attempt_id"],
            "descriptor_sha256": binding["descriptor_sha256"],
            "readbacks": result.get("readbacks"),
            "native_terminal_proof": observed_terminal.get("proof") if isinstance(observed_terminal, dict) else None,
            "terminal_state": observed_terminal.get("state") if isinstance(observed_terminal, dict) else None,
            "authority_exit": result.get("authority_exit"),
            "timings_ms": self.measured_timings_ms(result)}
        self.check(not self.has_secret_key(failed_proof), "d2_failure_proof_public_unsafe")
        self.diagnostic_proofs.append(failed_proof)
        self.diagnostic_summary = {"name": "d2-active-cancel", "status": "failed_as_expected",
            "reason": result.get("reason"),
            "production_acceptance": False, "capability_qualified": False,
            "kve_created": False, "kvf_created": False, "ack_created": False,
            "direct_monitor_sigint": True, "process_exit_code": proc.returncode if proc.returncode >= 0 else None,
            "process_signal": -proc.returncode if proc.returncode < 0 else None,
            "timings_ms": self.measured_timings_ms(result),
            "runner_observed_monitor_process_elapsed_ms": round((time.monotonic() - monitor_started) * 1000, 3)}
        self.records.append({"name": "active_command_late_release_fence", "cli_exit_code": proc.returncode,
            "runner_observed_monitor_process_elapsed_ms": round((time.monotonic() - monitor_started) * 1000, 3),
            "stop_latched_before_release": True, "positive_completion_after_stop": False})

    def public_summary(self):
        record_names = {row.get("name") for row in self.records}
        compile_names = {row.get("kind") for row in self.binary_history}
        diagnostic_names = {row.get("name"): row.get("status", "FAIL")
                            for row in self.diagnostic_attempts}
        active_d2_status = ("PASS" if "active_runtime_history_gate" in record_names else
            ("FAIL" if self.d2_attempted["active_runtime"] else "NOT_RUN"))
        startup_d2_status = ("PASS" if "startup_history_gate" in record_names else
            ("FAIL" if self.d2_attempted["startup_replay"] else "NOT_RUN"))
        scenarios = [
            {"scenario": "shipping_complete_source_compile", "status": "PASS" if "shipping" in compile_names else "NOT_RUN"},
            {"scenario": "qa_complete_source_compile", "status": "PASS" if "qa" in compile_names else "NOT_RUN"},
            {"scenario": "foundation_boolean_json_type_regression",
                "status": self.boolean_wire_record.get("status", "NOT_RUN") if isinstance(self.boolean_wire_record, dict) else "NOT_RUN"},
            {"scenario": "normal_root_launchd_baseline", "status": "PASS" if any(row.get("name") == "service_pair_probe_verified" and row.get("service_kind") == "shipping" for row in self.records) else "NOT_RUN"},
            {"scenario": "d1_single_node_script", "status": diagnostic_names.get("d1-script", "NOT_RUN")},
            {"scenario": "d1_single_quiet_node_test", "status": diagnostic_names.get("d1-node-test", "NOT_RUN")},
            {"scenario": "d1_failing_command", "status": diagnostic_names.get("d1-failing-command", "NOT_RUN")},
            {"scenario": "d1_isolated_copy_mutation_refused", "status": diagnostic_names.get("d1-copy-mutation", "NOT_RUN")},
            {"scenario": "d2_runtime_history_read_cancel_exact_births_late_release", "status": active_d2_status},
            {"scenario": "d2_startup_history_replay_pending", "status": startup_d2_status},
            {"scenario": "command_deadline_while_persistence_gate_held", "status": "NOT_RUN"},
            {"scenario": "short_cleanup_budget_during_long_stall", "status": "NOT_RUN"},
            {"scenario": "registry_file_fsync_gate", "status": "NOT_RUN"},
            {"scenario": "registry_fullfsync_gate", "status": "NOT_RUN"},
            {"scenario": "valid_64MiB_journal_and_12MiB_registry_bounds", "status": "NOT_RUN"},
            {"scenario": "controller_keeper_crash_and_owner_death", "status": "NOT_RUN"},
            {"scenario": "native_capability_or_os_origin_qualification", "status": "NOT_RUN"}]
        return {"schema": SUMMARY_SCHEMA, "status": self.status,
            "failed_stage": self.failed_stage,
            "primary_failed_stage": self.primary_failed_stage,
            "cleanup_failed_stage": self.cleanup_failed_stage,
            "platform": platform.platform(), "architecture": platform.machine(),
            "expected_architecture": self.expected_arch,
            "source_pin_count": len(self.pins.get("files", [])) if self.pins else 0,
            "source_pins": ([{"path": row["path"], "sha256": row["sha256"], "bytes": row["bytes"]}
                for row in self.pins["files"]] if self.pins else []),
            "source_sha256": ({k: v["source_sha256"] for k, v in self.binaries.items()}),
            "binary_sha256": ({k: {"broker": v["broker_sha256"], "stub": v["stub_sha256"],
                "qa_io_enabled": v["qa_io_enabled"], "qa_build_id": v["qa_build_id"]}
                for k, v in self.binaries.items()}),
            "compiled_pairs": self.binary_history,
            "compiler_diagnostics": self.compiler_diagnostics,
            "boolean_wire_regression": self.boolean_wire_record,
            "runtime_pins": self.runtime_pins,
            "installed_bindings": self.installed_bindings,
            "birth_observer_pin": getattr(self, "birth_observer_pin", None),
            "native_allocations": self.native_allocations,
            "native_diagnostic_proofs": self.diagnostic_proofs,
            "diagnostic_attempts": self.diagnostic_attempts,
            "fixture_source_layout": self.fixture_source_layout,
            "scenario_matrix": scenarios,
            "stages": [{k: v for k, v in row.items() if k != "root_command"}
                       for row in self.records],
            "workflow_commit": os.environ.get("GITHUB_SHA"),
            "github_actions_runner": os.environ.get("GITHUB_ACTIONS") == "true",
            "host_security_observation": self.host_security,
            "physical_hardware_qualification": False,
            "run_selection": "d2_only" if self.only_d2 else "all",
            "d2_attempted": dict(self.d2_attempted),
            "diagnostic": self.diagnostic_summary,
            "backend_qualified": False, "native_os_origin_qualified": False,
            "artifact_scope": "public allowlisted summary; raw evidence remains private"}

    def publish_public_evidence(self, summary):
        root = self.public_evidence_dir
        if root.exists() or root.is_symlink():
            raise QAError("public_evidence_directory_exists")
        root.mkdir(mode=0o755, parents=True)
        os.chmod(root, 0o755)
        st = root.lstat()
        self.check(stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode) and
                   st.st_uid == os.getuid() and stat.S_IMODE(st.st_mode) == 0o755,
                   "public_evidence_directory_unsafe")
        pins_bytes = self.pins_path.read_bytes()
        artifacts = {
            "PINS.json": pins_bytes,
            "summary.json": (json.dumps(summary, sort_keys=True, indent=2) + "\n").encode(),
            "native-proofs.json": (json.dumps({"schema": "knowledge-darwin-pipeline4-native-proofs.v1",
                "allocations": self.native_allocations, "diagnostics": self.diagnostic_proofs},
                sort_keys=True, indent=2) + "\n").encode(),
            "compiler-diagnostics.json": (json.dumps({"schema": "knowledge-darwin-pipeline4-compiler.v1",
                "compiles": self.compiler_diagnostics}, sort_keys=True, indent=2) + "\n").encode(),
            "runtime-binaries.json": (json.dumps({"schema": "knowledge-darwin-pipeline4-build-pins.v1",
                "native_pairs": self.binary_history, "runtimes": self.runtime_pins,
                "installed_bindings": self.installed_bindings,
                "birth_observer": getattr(self, "birth_observer_pin", None)},
                sort_keys=True, indent=2) + "\n").encode()}
        for filename, payload in artifacts.items():
            if filename.endswith(".json") and filename != "PINS.json":
                value = json.loads(payload)
                self.check(not self.has_secret_key(value), "public_artifact_secret_key_detected")
            public_file(root / filename, payload)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pins", required=True)
    parser.add_argument("--evidence-root", required=True)
    parser.add_argument("--public-evidence-dir", required=True)
    parser.add_argument("--summary", required=True)
    parser.add_argument("--only-d2", action="store_true",
                        help="run D2 persistence-gate scenarios without repeating D1")
    args = parser.parse_args()
    expected_arch = os.environ.get("EXPECTED_ARCH", "")
    runner = Runner(args.pins, args.evidence_root, expected_arch, args.public_evidence_dir,
                    only_d2=args.only_d2)
    try:
        runner.execute()
    except BaseException as error:
        runner.status = "FAIL"
        runner.primary_failed_stage = error.stage if isinstance(error, QAError) else "unexpected_runner_error"
        runner.failed_stage = runner.primary_failed_stage
    finally:
        try:
            runner.cleanup()
        except BaseException as error:
            runner.status = "CLEANUP_UNCONFIRMED"
            runner.cleanup_failed_stage = error.stage if isinstance(error, QAError) else "cleanup_unconfirmed"
            runner.failed_stage = runner.primary_failed_stage or runner.cleanup_failed_stage
        summary_path = Path(args.summary)
        try:
            runner.publish_public_evidence(runner.public_summary())
        except BaseException as error:
            runner.status = "FAIL"
            if runner.primary_failed_stage is None:
                runner.primary_failed_stage = error.stage if isinstance(error, QAError) else "public_evidence_failed"
            runner.failed_stage = runner.primary_failed_stage
        payload = (json.dumps(runner.public_summary(), sort_keys=True, indent=2) + "\n").encode("utf-8")
        private_file(summary_path, payload)
        os.chmod(summary_path, 0o644)
    print(json.dumps(runner.public_summary(), sort_keys=True, separators=(",", ":")))
    return 0 if runner.status == "PASS_DIAGNOSTIC_ONLY" else 1


if __name__ == "__main__":
    raise SystemExit(main())
