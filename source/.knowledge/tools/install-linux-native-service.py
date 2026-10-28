#!/usr/bin/env python3
"""Prepare the installed Linux native service as the ordinary application UID.

Compilation, Node/ELF inspection and source traversal happen before privilege.
The generated reviewed install script only invokes fixed OS administration
utilities and the pinned native broker's history initializer. It never runs
Node, source fixtures, npm, Python or the compiler as host root.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import stat
import subprocess
import sys


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def physical(path: Path, limit: int = 256 * 1024 * 1024) -> bytes:
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > limit:
        raise RuntimeError(f"not a bounded single-link physical file: {path}")
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise RuntimeError("file identity changed")
        chunks, size = [], 0
        while True:
            chunk = os.read(fd, min(65536, limit + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > limit:
                raise RuntimeError("file size limit")
        after = os.fstat(fd)
        if (after.st_size, after.st_mtime_ns, after.st_ctime_ns) != (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns):
            raise RuntimeError("file changed during prepare")
        return b"".join(chunks)
    finally:
        os.close(fd)


def command(argv: list[str], timeout: int = 45) -> bytes:
    result = subprocess.run(argv, check=False, timeout=timeout, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"})
    if result.returncode:
        raise RuntimeError(f"command failed {argv[0]}: {result.stderr.decode(errors='replace')[-16000:]}")
    if len(result.stdout) > 8 * 1024 * 1024 or len(result.stderr) > 8 * 1024 * 1024:
        raise RuntimeError("bounded prepare output exceeded")
    return result.stdout


def range_preflight(first: int, last: int) -> dict:
    """Check existing administrator identities without allocating/reusing any."""
    counts = {"accounts": 0, "groups": 0, "subordinate_ranges": 0, "native_claims": 0}
    for table, count in (("passwd", "accounts"), ("group", "groups")):
        for row in command(["/usr/bin/getent", table], 20).decode("utf-8", "strict").splitlines():
            fields = row.split(":")
            if len(fields) < 3 or not fields[2].isdigit():
                raise RuntimeError("unrecognized system identity record")
            counts[count] += 1
            if first <= int(fields[2]) <= last:
                raise RuntimeError("dedicated native UID/GID range overlaps a system identity")
    for file in (Path("/etc/subuid"), Path("/etc/subgid")):
        if not file.exists():
            continue
        for row in physical(file, 4 * 1024 * 1024).decode("utf-8", "strict").splitlines():
            if not row.strip() or row.lstrip().startswith("#"):
                continue
            fields = row.split(":")
            if len(fields) != 3 or not fields[1].isdigit() or not fields[2].isdigit() or int(fields[2]) <= 0:
                raise RuntimeError("unrecognized subordinate identity record")
            start, size = int(fields[1]), int(fields[2]);counts["subordinate_ranges"] += 1
            if start <= last and first < start + size:
                raise RuntimeError("dedicated native UID/GID range overlaps a subordinate allocation")
    claims = Path("/var/lib/knowledge-linux-native-reservations")
    if claims.exists():
        info = claims.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise RuntimeError("native identity reservation directory is not protected")
        for claim in claims.iterdir():
            match = re.fullmatch(r"uid-(\d+)-(\d+)", claim.name)
            if not match:
                raise RuntimeError("unrecognized permanent native identity reservation")
            start, end = map(int, match.groups());counts["native_claims"] += 1
            if start <= last and first <= end:
                raise RuntimeError("dedicated native UID/GID range is already permanently reserved")
    return {"status": "no_conflicts", **counts}


def unit_bytes(install_root: str) -> bytes:
    return ("[Unit]\nDescription=Knowledge native Linux verification service\nAfter=local-fs.target\n\n"
            "[Service]\nType=notify\nNotifyAccess=main\nUser=root\nGroup=root\n"
            f"ExecStart={install_root}/broker --serve\n"
            "TimeoutStartSec=20s\nTimeoutStopSec=10s\nDelegate=yes\nKillMode=control-group\n"
            "Restart=no\nUMask=0077\nNoNewPrivileges=no\nProtectControlGroups=no\n\n"
            "[Install]\nWantedBy=multi-user.target\n").encode("ascii")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--node", type=Path, default=Path(shutil.which("node") or "/usr/bin/node"))
    parser.add_argument("--uid-first", type=int, default=1590000000)
    parser.add_argument("--uid-last", type=int, default=1590009999)
    parser.add_argument("--service-lifetime-seconds", type=int, default=0,
                        help="0 emits a persistent unit; 1..14400 creates a bounded transient qualification service")
    args = parser.parse_args()
    if sys.platform != "linux":
        raise RuntimeError("this installer supports Linux x64 and ARM64 only")
    if os.getuid() == 0 or os.geteuid() == 0:
        raise RuntimeError("prepare must run as the ordinary installation caller, never root")
    source, out, node = args.source.resolve(strict=True), args.out.absolute(), args.node.resolve(strict=True)
    if source.name != ".knowledge" or not source.is_dir() or out.exists():
        raise RuntimeError("expected an existing .knowledge source and a fresh output directory")
    if not 1_000_000_000 <= args.uid_first < args.uid_last < 1_900_000_000 or args.uid_first <= os.getuid() <= args.uid_last:
        raise RuntimeError("invalid dedicated UID range")
    if not 0 <= args.service_lifetime_seconds <= 14400:
        raise RuntimeError("service lifetime must be 0 or a bounded 1..14400 seconds")
    if any(ord(character) < 32 or ord(character) == 127 for value in (source, out, node) for character in str(value)):
        raise RuntimeError("installation preparation paths must not contain control characters")
    identity_preflight = range_preflight(args.uid_first, args.uid_last)
    install_root = "/var/lib/knowledge-linux-native-v1"
    unit = "knowledge-linux-native-v1"
    installation = secrets.token_hex(16)
    machine = physical(Path("/etc/machine-id"), 128).strip()
    if not re.fullmatch(rb"[0-9a-f]{32}", machine):
        raise RuntimeError("unavailable fixed machine identity")
    host = digest(b"knowledge-linux-native-host.v1\0" + machine)[:32]
    out.mkdir(mode=0o700)
    staged = out / "stage"
    runtime = staged / "runtime"
    (runtime / "knowledge").mkdir(parents=True, mode=0o700)
    (runtime / "lib").mkdir(mode=0o700)
    records: dict[str, str] = {}
    source_policy = json.loads(command([str(node), "-e",
        "process.stdout.write(JSON.stringify(require(process.argv[1]).sourcePolicy))",
        str(source / "tools/lib/verification-linux-service-importer.js")], 10))
    source_dirs, source_files = set(source_policy["directories"]), set(source_policy["files"])

    def save(name: str, data: bytes, mode: int = 0o444) -> None:
        if not name or name.startswith("/") or any(x in {"", ".", ".."} for x in name.split("/")) or any(ord(x) < 32 or ord(x) == 127 for x in name):
            raise RuntimeError("unsupported runtime path")
        target = runtime / name
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with target.open("xb") as stream:
            stream.write(data)
        target.chmod(mode)
        records[name] = digest(data)

    rg = shutil.which("rg", path="/usr/bin:/bin")
    if rg:
        paths = command([rg, "--files", "--hidden", "--no-ignore", str(source)]).decode().splitlines()
    else:
        # Some stock Actions images omit ripgrep. Inventory stays ordinary-UID
        # and every selected leaf is still opened NOFOLLOW and read back.
        paths = []
        for current, directories, files in os.walk(source, followlinks=False):
            for name in directories:
                if (Path(current) / name).is_symlink():
                    raise RuntimeError("trusted source contains a directory symlink")
            paths.extend(str(Path(current) / name) for name in files)
    if not 1 <= len(paths) <= 20000:
        raise RuntimeError("trusted runtime inventory outside bounds")
    for file in sorted(map(Path, paths), key=lambda x: os.fsencode(str(x.relative_to(source)))):
        relative = file.relative_to(source).as_posix()
        if any(part in {".git", "node_modules", "__pycache__"} for part in file.relative_to(source).parts):
            continue
        parts = file.relative_to(source).parts
        if not (parts[0] in source_dirs if len(parts) > 1 else parts[0] in source_files):
            continue
        save("knowledge/" + relative, physical(file, 32 * 1024 * 1024), 0o555 if file.lstat().st_mode & 0o111 else 0o444)
    for required in ("verification-linux-service-importer.js", "verification-linux-service-authority.js"):
        if "knowledge/tools/lib/" + required not in records:
            raise RuntimeError(f"trusted runtime entry missing: {required}")
    node_body = physical(node)
    save("node", node_body, 0o555)
    version = command([str(node), "--version"], 10).decode().strip()
    if not re.fullmatch(r"v22\.17\.1", version):
        raise RuntimeError(f"this native runtime supports pinned Node v22.17.1, received {version}")
    headers = command(["/usr/bin/readelf", "-lW", str(node)])
    match = re.search(rb"Requesting program interpreter:\s*(/[^\s\]]+)", headers)
    if not match:
        raise RuntimeError("Node interpreter unavailable")
    requested_loader = os.fsdecode(match.group(1))
    if requested_loader not in {"/lib64/ld-linux-x86-64.so.2", "/lib/ld-linux-aarch64.so.1"}:
        raise RuntimeError("unsupported Node architecture loader")
    save("loader", physical(Path(requested_loader).resolve(strict=True), 16 * 1024 * 1024), 0o555)
    dependencies = command(["/usr/bin/ldd", str(node)]).decode()
    if "not found" in dependencies:
        raise RuntimeError("unresolved Node ELF dependencies")
    for line in dependencies.splitlines():
        match = re.match(r"^\s*([A-Za-z0-9._+\-]+)\s+=>\s+(/\S+)\s+\(", line)
        if match:
            library = Path(match.group(2)).resolve(strict=True)
            if not str(library).startswith(("/lib/", "/usr/lib/")):
                raise RuntimeError("library is outside protected OS roots")
            save("lib/" + match.group(1), physical(library, 64 * 1024 * 1024))
        elif "linux-vdso" not in line and requested_loader not in line and line.strip():
            raise RuntimeError("unrecognized ldd record")
    manifest = b"".join((records[name] + " " + name + "\n").encode() for name in sorted(records, key=os.fsencode))
    (staged / "runtime.manifest").write_bytes(manifest)
    source_manifest = b"".join((records[name] + " " + name + "\n").encode() for name in sorted(records, key=os.fsencode) if name.startswith("knowledge/"))
    native_names = ["verification-linux-service.c", "verification-linux-service.h", "verification-linux-uid-history.c", "verification-linux-uid-history.h"]
    native = [{"name": name, "sha256": digest(physical(runtime / "knowledge/tools/lib" / name, 2 * 1024 * 1024))} for name in native_names]
    native_digest = digest(json.dumps(native, separators=(",", ":")).encode())
    definitions = {
        "KLS_ROOT": install_root, "KLS_INSTALLATION_ID": installation, "KLS_HOST_ID": host,
        "KLS_NATIVE_SOURCE_SHA": native_digest, "KLS_NODE_SHA": digest(node_body),
        "KLS_RUNTIME_MANIFEST_SHA": digest(manifest), "KLS_TRUSTED_SOURCE_MANIFEST_SHA": digest(source_manifest),
    }
    compile_argv = ["/usr/bin/gcc", "-std=c11", "-O2", "-static", "-no-pie", "-fstack-protector-strong", "-D_FORTIFY_SOURCE=2",
                    "-Wall", "-Wextra", "-Werror", "-Wno-misleading-indentation", "-Wno-parentheses"]
    compile_argv += [f'-D{name}="{value}"' for name, value in definitions.items()]
    compile_argv += [f"-DKLS_CALLER_UID={os.getuid()}", f"-DKLS_UID_FIRST={args.uid_first}", f"-DKLS_UID_LAST={args.uid_last}",
                     str(runtime / "knowledge/tools/lib/verification-linux-service.c"), str(runtime / "knowledge/tools/lib/verification-linux-uid-history.c"),
                     "-lcrypto", "-ldl", "-pthread", "-o", str(staged / "broker")]
    command(compile_argv, 90)
    binary = physical(staged / "broker", 16 * 1024 * 1024)
    executable_headers = command(["/usr/bin/readelf", "-lW", str(staged / "broker")])
    if b" INTERP " in executable_headers or b"Requesting program interpreter" in executable_headers:
        raise RuntimeError("root native broker must be a fixed static executable")
    config = {
        "schema_version": "knowledge-linux-native-installation.v1", "broker": install_root + "/broker",
        "installation_id": installation, "host_id": host, "caller_uid": os.getuid(),
        "uid_first": args.uid_first, "uid_last": args.uid_last, "unit": unit + ".service",
        "source_sha256": native_digest, "native_source_sha256": native_digest,
        "runtime_sha256": digest(manifest), "trusted_runtime_manifest_sha256": digest(manifest),
        "trusted_source_manifest_sha256": digest(source_manifest),
        "node_sha256": digest(node_body), "node_version": version, "broker_binary_sha256": digest(binary),
        "trusted_sources": native,
        "source_policy": source_policy,
        "identity_preflight": identity_preflight,
        "service_lifetime_seconds": args.service_lifetime_seconds,
    }
    (staged / "installation.json").write_text(json.dumps(config, indent=2) + "\n")
    service_unit = unit_bytes(install_root)
    if args.service_lifetime_seconds == 0:
        (staged / (unit + ".service")).write_bytes(service_unit)
    entries = sorted((p for p in staged.rglob("*") if p.is_file()), key=lambda x: os.fsencode(str(x.relative_to(staged))))
    checks = b"".join((digest(physical(p)) + "  " + str(p) + "\n").encode() for p in entries)
    (out / "SHA256SUMS").write_bytes(checks)
    q = shlex.quote
    script = ["#!/bin/sh", "set -eu", "test \"$(id -u)\" = 0", f"test ! -e {q(install_root)}", f"cd {q(str(out))}",
              f"/usr/bin/sha256sum --strict -c {q(str(out / 'SHA256SUMS'))} >/dev/null",
              f"/usr/bin/mkdir -m 0755 {q(install_root)}",
              "/usr/bin/install -d -o root -g root -m 0755 /var/lib/knowledge-linux-native-reservations",
              f"/usr/bin/mkdir -m 0700 /var/lib/knowledge-linux-native-reservations/uid-{args.uid_first}-{args.uid_last}"]
    directories = sorted((p for p in runtime.rglob("*") if p.is_dir()), key=lambda x: (len(x.parts), str(x)))
    for directory in [runtime, *directories]:
        script.append(f"/usr/bin/install -d -o root -g root -m 0555 {q(install_root + '/' + directory.relative_to(staged).as_posix())}")
    for entry in entries:
        relative = entry.relative_to(staged).as_posix()
        mode = "0555" if relative in {"broker", "runtime/node", "runtime/loader"} or entry.lstat().st_mode & 0o111 else "0444"
        script.append(f"/usr/bin/install -o root -g root -m {mode} {q(str(entry))} {q(install_root + '/' + relative)}")
    script.append(f"test \"$(/usr/bin/sha256sum {q(install_root + '/broker')} | /usr/bin/cut -d ' ' -f 1)\" = {q(digest(binary))}")
    script += [f"/usr/bin/install -d -o root -g root -m 0700 {q(install_root + '/anchor')} {q(install_root + '/journal')}",
               f"{q(install_root + '/broker')} --initialize-history"]
    if args.service_lifetime_seconds:
        script.append(f"/usr/bin/systemd-run --system --unit={q(unit)} --service-type=notify --property=NotifyAccess=main --property=TimeoutStartSec=20s --property=Delegate=yes --property=KillMode=control-group --property=TimeoutStopSec=10s --property=RuntimeMaxSec={args.service_lifetime_seconds}s --property=Restart=no --property=NoNewPrivileges=no --property=ProtectControlGroups=no {q(install_root + '/broker')} --serve")
    else:
        protected_unit = install_root + "/" + unit + ".service"
        system_unit = "/etc/systemd/system/" + unit + ".service"
        script += [f"test ! -e {q(system_unit)}",
                   f"test \"$(/usr/bin/sha256sum {q(protected_unit)} | /usr/bin/cut -d ' ' -f 1)\" = {q(digest(service_unit))}",
                   f"/usr/bin/install -o root -g root -m 0644 {q(protected_unit)} {q(system_unit)}",
                   "/usr/bin/systemctl daemon-reload",
                   f"/usr/bin/systemctl enable --now {q(unit + '.service')}"]
    script.append(f"/usr/bin/printf '%s\\n' {q(install_root + '/installation.json')}")
    (out / "install-native.sh").write_text("\n".join(script) + "\n")
    (out / "install-native.sh").chmod(0o700)
    (out / "prepare.json").write_text(json.dumps({"status": "PREPARED_NATIVE_INSTALLATION", "install_root": install_root,
         "unit": unit, "config": install_root + "/installation.json", "install_script": str(out / "install-native.sh"),
         "runtime_files": len(records), "pins": config}, indent=2) + "\n")
    print(json.dumps({"status": "PREPARED_NATIVE_INSTALLATION", "prepare": str(out / "prepare.json"), "config": install_root + "/installation.json", "unit": unit}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
