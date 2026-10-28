#!/usr/bin/env python3
"""Verify audit7 handoff integrity without executing or extracting its contents.

Manifest self-hashes are consistency checks, not independent authenticity or
runtime qualification. Authenticate the outer ZIP digest through a separate
trusted channel. The parent Git baseline archive and diagnostic ZIP have fixed digests.
"""
from __future__ import annotations
import argparse
import hashlib
import io
import json
import math
import os
from pathlib import Path
import re
import stat
import tempfile
import unicodedata
import zipfile

PARENT_SHA256 = "1447c64ea1f59f60ec52d7040ceac0036a294ab0629e0eb27b187b83dd75583f"
PARENT_HANDOFF_SHA256 = "325b2e4d38fda187d89ecf8ded140f23073819a990e70194230336a83004b021"
FIXED_DIAGNOSTIC_SHA256 = "3bf5913522b6f8aad368936976202c499b90439d9219f155d315c74fcf209936"
SOURCE_COUNT = 690
REVISION = "independent-audit.20261028.reliability.7"
MAX_FILE = 256 * 1024 * 1024
MAX_TOTAL = 1024 * 1024 * 1024
MAX_ENTRIES = 50000
HEX = re.compile(r"[a-f0-9]{64}\Z")


class Invalid(ValueError):
    pass


def need(ok, message):
    if not ok:
        raise Invalid(message)


def digest(body):
    return hashlib.sha256(body).hexdigest()


def json_value(body):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result, "duplicate JSON member")
            result[key] = value
        return result
    def nonfinite(_value):
        raise Invalid("nonfinite JSON number")
    def finite_float(value):
        number = float(value)
        need(math.isfinite(number), "nonfinite JSON number")
        return number
    return json.loads(body.decode("utf-8", "strict"), object_pairs_hook=unique,
                      parse_constant=nonfinite, parse_float=finite_float)


def safe_name(name):
    need(isinstance(name, str) and 0 < len(name.encode("utf-8", "strict")) <= 4096 and
         name == unicodedata.normalize("NFC", name) and not name.startswith("/") and
         not any(ord(c) < 32 or ord(c) == 127 or c in '\\:<>"|?*' for c in name), "unsafe member path")
    for part in name.split("/"):
        need(part not in {"", ".", ".."} and not part.endswith((" ", ".")) and
             len(part.encode("utf-8")) <= 255 and
             re.fullmatch(r"(?:CON|PRN|AUX|NUL|COM[1-9¹²³]|LPT[1-9¹²³]|CONIN\$|CONOUT\$)(?:\..*)?", part, re.I) is None,
             "unsafe member component")
    return name


def inventory_names(files, directories=()):
    need(len(files) <= MAX_ENTRIES, "too many files")
    aliases = set()
    file_set = set(files)
    parents = set()
    for name in files:
        safe_name(name)
        key = unicodedata.normalize("NFD", name).casefold()
        need(key not in aliases, "duplicate or portable path alias")
        aliases.add(key)
        parts = name.split("/")
        for count in range(1, len(parts)):
            parent = "/".join(parts[:count])
            need(parent not in file_set, "file/directory path conflict")
            parents.add(parent)
    directory_aliases = {}
    for name in parents:
        key = unicodedata.normalize("NFD", name).casefold()
        need(key not in aliases, "file/directory portable alias")
        need(key not in directory_aliases or directory_aliases[key] == name, "directory portable alias")
        directory_aliases[key] = name
    for name in directories:
        safe_name(name)
        need(name in parents, "unmanifested empty or foreign directory")


class Store:
    def __init__(self, source):
        self.archive = None
        self.root_fd = None
        try:
            self._initialize(source)
        except BaseException:
            self.close()
            raise

    def _initialize(self, source):
        self.archive = None
        self.root_fd = None
        self.files = {}
        self.directories = set()
        if isinstance(source, bytes):
            need(len(source) <= MAX_FILE, "nested archive compressed size limit")
            self.archive = zipfile.ZipFile(io.BytesIO(source))
        else:
            source = Path(source)
            identity = source.lstat()
            need(not stat.S_ISLNK(identity.st_mode), "input is a symlink")
            if stat.S_ISDIR(identity.st_mode):
                self.root = source
                if os.open in os.supports_dir_fd and hasattr(os, "O_NOFOLLOW"):
                    self.root_fd = os.open(source, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                for parent, dirs, names in os.walk(source, followlinks=False):
                    for leaf in dirs + names:
                        path = Path(parent) / leaf
                        st = path.lstat()
                        need(not stat.S_ISLNK(st.st_mode), "symlink in directory input")
                        name = path.relative_to(source).as_posix()
                        if stat.S_ISDIR(st.st_mode):
                            self.directories.add(name)
                        else:
                            need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1, "nonregular or multiply linked input")
                            need(st.st_mode & 0o7022 == 0, "unsafe directory file mode")
                            self.files[name] = st
                        need(len(self.files) + len(self.directories) <= MAX_ENTRIES, "directory inventory limit")
            else:
                need(stat.S_ISREG(identity.st_mode) and identity.st_size <= MAX_TOTAL, "outer archive type/size limit")
                self.archive = zipfile.ZipFile(source)
        if self.archive:
            infos = self.archive.infolist()
            need(len(infos) <= MAX_ENTRIES, "archive inventory limit")
            seen = set()
            for info in infos:
                need(info.orig_filename == info.filename, "archive member name was truncated")
                name = info.filename[:-1] if info.is_dir() else info.filename
                safe_name(name)
                need(name not in seen, "duplicate archive member")
                seen.add(name)
                mode = info.external_attr >> 16
                kind = stat.S_IFMT(mode)
                need(not info.flag_bits & 1, "encrypted archive member")
                need(kind in {0, stat.S_IFDIR if info.is_dir() else stat.S_IFREG}, "archive symlink or special member")
                need(mode & 0o7022 == 0, "unsafe archive permission bits")
                if info.is_dir():
                    need(info.file_size == 0, "directory contains data")
                    self.directories.add(name)
                else:
                    self.files[name] = info
        inventory_names(self.files, self.directories)
        sizes = [value.file_size if self.archive else value.st_size for value in self.files.values()]
        need(all(0 <= size <= MAX_FILE for size in sizes) and sum(sizes) <= MAX_TOTAL, "uncompressed size limit")

    def close(self):
        if self.archive:
            self.archive.close()
        if self.root_fd is not None:
            os.close(self.root_fd)
            self.root_fd = None

    def read(self, name, maximum=MAX_FILE):
        need(name in self.files, "required member missing: " + name)
        item = self.files[name]
        size = item.file_size if self.archive else item.st_size
        need(size <= maximum, "member exceeds read limit: " + name)
        if self.archive:
            handle = self.archive.open(item)
        else:
            parent_fd = os.dup(self.root_fd) if self.root_fd is not None else None
            try:
                parts = name.split("/")
                if parent_fd is not None:
                    for part in parts[:-1]:
                        next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
                        os.close(parent_fd)
                        parent_fd = next_fd
                    fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd)
                else:
                    # Windows: inspect every ancestor and the opened file. ZIP
                    # input is preferred for a concurrently mutable directory.
                    path = self.root
                    for part in parts:
                        path = path / part
                        need(not path.is_symlink(), "directory path changed to symlink")
                    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
                opened = os.fstat(fd)
                if not (stat.S_ISREG(opened.st_mode) and opened.st_nlink == 1 and
                        (opened.st_dev, opened.st_ino, opened.st_mode, opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) ==
                        (item.st_dev, item.st_ino, item.st_mode, item.st_size, item.st_mtime_ns, item.st_ctime_ns)):
                    os.close(fd)
                    raise Invalid("directory member changed")
                handle = os.fdopen(fd, "rb")
            finally:
                if parent_fd is not None:
                    os.close(parent_fd)
        with handle:
            chunks, total = [], 0
            while True:
                block = handle.read(min(65536, maximum + 1 - total))
                if not block:
                    break
                chunks.append(block)
                total += len(block)
                need(total <= maximum, "stream exceeds read limit")
            need(total == size, "stream size mismatch")
            if not self.archive:
                after = os.fstat(handle.fileno())
                need((after.st_size, after.st_mtime_ns, after.st_ctime_ns) ==
                     (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns), "file changed while reading")
            return b"".join(chunks)


def immutable_input(source):
    """Read one stable, bounded outer file; expected digest and parsing share bytes."""
    if isinstance(source, bytes):
        need(len(source) <= MAX_FILE, "outer ZIP compressed size limit")
        return source
    path = Path(source)
    before = path.lstat()
    need(not stat.S_ISLNK(before.st_mode), "input is a symlink")
    if stat.S_ISDIR(before.st_mode):
        return path
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
         before.st_mode & 0o7022 == 0 and 0 <= before.st_size <= MAX_FILE,
         "outer ZIP type/mode/size limit")
    identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as handle:
        opened = os.fstat(handle.fileno())
        need(identity(opened) == identity(before), "outer ZIP changed before open")
        body = handle.read(MAX_FILE + 1)
        need(len(body) == before.st_size and identity(os.fstat(handle.fileno())) == identity(before) and
             identity(path.lstat()) == identity(before), "outer ZIP changed while reading")
    return body


def verify(source, *, expected_sha256=None, _parent_digest=PARENT_SHA256,
           _diagnostic_digest=FIXED_DIAGNOSTIC_SHA256, _handoff_digest=PARENT_HANDOFF_SHA256):
    source = immutable_input(source)
    outer_digest = digest(source) if isinstance(source, bytes) else None
    if expected_sha256 is not None:
        need(isinstance(expected_sha256, str) and HEX.fullmatch(expected_sha256), "expected SHA-256 must be lowercase hexadecimal")
        need(outer_digest is not None, "expected outer ZIP SHA-256 cannot authenticate a directory")
        need(outer_digest == expected_sha256, "trusted outer ZIP digest mismatch")
    store = Store(source)
    try:
        manifest_raw = store.read("MANIFEST.json", 16 * 1024 * 1024)
        manifest = json_value(manifest_raw)
        need(isinstance(manifest, dict) and set(manifest) == {"schema_version", "files"} and
             manifest["schema_version"] == "audit7.manifest.v1" and isinstance(manifest["files"], dict), "manifest schema")
        entries = manifest["files"]
        inventory_names(entries)
        need("MANIFEST.json" not in entries and set(entries) == set(store.files) - {"MANIFEST.json"}, "manifest inventory mismatch")
        for name, record in entries.items():
            need(isinstance(record, dict) and set(record) == {"sha256", "size"} and
                 isinstance(record["sha256"], str) and HEX.fullmatch(record["sha256"]) and
                 type(record["size"]) is int and 0 <= record["size"] <= MAX_FILE, "manifest entry schema")
            body = store.read(name)
            need(len(body) == record["size"] and digest(body) == record["sha256"], "member hash/size mismatch: " + name)
        need(digest(store.read("original/GIT_BASELINE.tar.gz")) == _parent_digest, "parent Git baseline archive digest mismatch")
        status = json_value(store.read("STATUS.json", 1024 * 1024))
        need(isinstance(status, dict) and status.get("schema_version") == "knowledge-audit7-handoff.v1" and
             status.get("audit_revision") == REVISION and status.get("release_qualified") is False and
             status.get("production_linux_service") == "NOT_IMPLEMENTED" and status.get("stock_sip_macos") == "UNCONFIRMED",
             "status cannot promote unresolved release/platform gates")
        pins_raw = store.read("source/SOURCE_PINS.json", 8 * 1024 * 1024)
        pins = json_value(pins_raw)
        need(isinstance(pins, dict) and set(pins) == {"schema_version", "file_count", "files", "input_source_sha256", "parent_handoff_sha256"} and
             pins["schema_version"] == "knowledge-audit7-source-pins.v1" and type(pins["file_count"]) is int and
             isinstance(pins["files"], dict) and pins["file_count"] == len(pins["files"]) == SOURCE_COUNT and
             isinstance(pins["input_source_sha256"], str) and HEX.fullmatch(pins["input_source_sha256"]) and
             pins["parent_handoff_sha256"] == _handoff_digest, "source pins schema or parent binding")
        inventory_names(pins["files"])
        source_raw = store.read("source/SOURCE.zip")
        nested = Store(source_raw)
        try:
            need(set(nested.files) == {".knowledge/" + name for name in pins["files"]}, "source ZIP inventory mismatch")
            for name, expected in pins["files"].items():
                need(isinstance(expected, str) and HEX.fullmatch(expected) and
                     digest(nested.read(".knowledge/" + name)) == expected, "source pin mismatch: " + name)
        finally:
            nested.close()
        diagnostic_raw = store.read("diagnostic-package/knowledge-v3.4.4.zip")
        diagnostic = Store(diagnostic_raw)
        try:
            need(bool(diagnostic.files) and all(name.startswith(".knowledge/") for name in diagnostic.files), "diagnostic ZIP layout")
            for name in diagnostic.files:
                diagnostic.read(name)  # Validate CRC/size of every bounded entry without extraction or execution.
            package = json_value(diagnostic.read(".knowledge/package.json", 1024 * 1024))
            need(isinstance(package, dict) and package.get("version") == "3.4.4", "diagnostic package version")
        finally:
            diagnostic.close()
        need(digest(diagnostic_raw) == _diagnostic_digest, "diagnostic package fixed digest mismatch")
        need(status.get("source_file_count") == SOURCE_COUNT and type(status.get("source_file_count")) is int and
             status.get("source_archive_sha256") == digest(source_raw) and status.get("source_pins_sha256") == digest(pins_raw) and
             status.get("diagnostic_zip_sha256") == digest(diagnostic_raw), "status archive/source bindings")
        return {"status": "PASS_BUNDLE_INTEGRITY_ONLY", "schema_version": "knowledge-audit7-integrity-result.v1",
                "files": len(entries), "source_files": pins["file_count"], "manifest_sha256": digest(manifest_raw),
                "baseline_git_archive_sha256": _parent_digest, "parent_handoff_sha256": _handoff_digest, "diagnostic_sha256": _diagnostic_digest, "outer_sha256": outer_digest,
                "expected_outer_digest_matched": expected_sha256 is not None, "release_qualified": False,
                "production_linux_service": "NOT_IMPLEMENTED", "stock_sip_macos": "UNCONFIRMED",
                "diagnostic_package_release_qualified": False, "physical_runtime_facts_verified": False,
                "trust_limit": "Self-hashes prove internal consistency only. --expected-sha256 matches a caller-supplied independently trusted outer digest; neither mode independently validates physical native facts or qualifies a release."}
    finally:
        store.close()


def self_test():
    def zipped(files, special=None, duplicate=None):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            for name, body in files.items():
                info = zipfile.ZipInfo(name)
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | 0o644) << 16
                if special and name == special[0]: info.external_attr = special[1] << 16
                archive.writestr(info, body)
            if duplicate:
                import warnings
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", UserWarning)
                    archive.writestr(duplicate, files[duplicate])
        return buffer.getvalue()
    parent = zipped({"original.txt": b"fixed miniature parent, never executed"})
    source_files = {f"tools/probe-{i}.js": b'throw new Error("embedded code must never execute");\n' for i in range(SOURCE_COUNT)}
    def fixture():
        files = {"original/GIT_BASELINE.tar.gz": parent,
                 "source/SOURCE.zip": zipped({".knowledge/" + k: v for k, v in source_files.items()}),
                 "source/SOURCE_PINS.json": json.dumps({"schema_version": "knowledge-audit7-source-pins.v1", "file_count": SOURCE_COUNT,
                    "input_source_sha256": "a" * 64, "parent_handoff_sha256": digest(parent),
                    "files": {name: digest(body) for name, body in source_files.items()}}).encode(),
                 "diagnostic-package/knowledge-v3.4.4.zip": zipped({".knowledge/package.json": b'{"version":"3.4.4"}'})}
        files["STATUS.json"] = json.dumps({"schema_version": "knowledge-audit7-handoff.v1", "audit_revision": REVISION,
            "release_qualified": False, "production_linux_service": "NOT_IMPLEMENTED", "stock_sip_macos": "UNCONFIRMED",
            "source_file_count": SOURCE_COUNT, "source_archive_sha256": digest(files["source/SOURCE.zip"]),
            "source_pins_sha256": digest(files["source/SOURCE_PINS.json"]),
            "diagnostic_zip_sha256": digest(files["diagnostic-package/knowledge-v3.4.4.zip"])}).encode()
        return files
    def seal(files):
        files["MANIFEST.json"] = json.dumps({"schema_version": "audit7.manifest.v1", "files": {
            name: {"sha256": digest(body), "size": len(body)} for name, body in files.items() if name != "MANIFEST.json"}}).encode()
        return files
    baseline = seal(fixture()); archive = zipped(baseline)
    miniature_diagnostic_digest = digest(baseline["diagnostic-package/knowledge-v3.4.4.zip"])
    need(verify(archive, expected_sha256=digest(archive), _parent_digest=digest(parent), _handoff_digest=digest(parent),
                _diagnostic_digest=miniature_diagnostic_digest)["expected_outer_digest_matched"], "positive pinned ZIP")
    with tempfile.TemporaryDirectory(prefix="audit7-verifier-", dir=Path.cwd()) as root:
        for name, body in baseline.items():
            path = Path(root) / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(body)
        need(verify(root, _parent_digest=digest(parent), _handoff_digest=digest(parent), _diagnostic_digest=miniature_diagnostic_digest)["source_files"] == SOURCE_COUNT, "positive directory fixture")
    variants = []
    files = dict(baseline); files["STATUS.json"] += b" "; variants.append(("payload hash mismatch", zipped(files), None))
    files = dict(baseline); files["extra.txt"] = b"extra"; variants.append(("unmanifested addition", zipped(files), None))
    files = dict(baseline); del files["STATUS.json"]; variants.append(("missing member", zipped(files), None))
    files = fixture(); files["original/GIT_BASELINE.tar.gz"] = b"substituted parent"; variants.append(("resealed parent substitution", zipped(seal(files)), None))
    files = fixture(); files["STATUS.json"] = files["STATUS.json"].replace(b'"release_qualified": false', b'"release_qualified": true'); variants.append(("resealed release promotion", zipped(seal(files)), None))
    files = fixture(); files["STATUS.json"] = files["STATUS.json"].replace(b'{', b'{"release_qualified":false,', 1); variants.append(("duplicate JSON member", zipped(seal(files)), None))
    files = fixture(); files["STATUS.json"] = files["STATUS.json"].replace(b'{', b'{"extra_metric":1e400,', 1); variants.append(("JSON number overflow", zipped(seal(files)), None))
    files = fixture(); files["source/SOURCE.zip"] = zipped({".knowledge/" + k: (b"substituted" if k.endswith("-0.js") else v) for k, v in source_files.items()}); variants.append(("resealed source substitution", zipped(seal(files)), None))
    files = dict(baseline); files["../escape"] = b"bad"; variants.append(("ZIP traversal", zipped(files), None))
    variants.append(("ZIP symlink", zipped(baseline, ("STATUS.json", stat.S_IFLNK | 0o777)), None))
    variants.append(("ZIP duplicate entry", zipped(baseline, duplicate="STATUS.json"), None))
    variants.append(("ZIP setuid permission", zipped(baseline, ("STATUS.json", stat.S_IFREG | 0o4644)), None))
    files = dict(baseline); files["status.json"] = files["STATUS.json"]; variants.append(("portable case alias", zipped(seal(files)), None))
    variants.append(("independent outer digest mismatch", archive, "0" * 64))
    files = fixture(); files["diagnostic-package/knowledge-v3.4.4.zip"] = zipped({".knowledge/package.json": b'{"version":"3.4.4"}', ".knowledge/link": b"target"}, (".knowledge/link", stat.S_IFLNK | 0o777)); variants.append(("nested diagnostic symlink", zipped(seal(files)), None))
    files = fixture()
    files["diagnostic-package/knowledge-v3.4.4.zip"] = zipped({".knowledge/package.json": b'{"version":"3.4.4","name":"unrelated"}'})
    altered_status = json_value(files["STATUS.json"])
    altered_status["diagnostic_zip_sha256"] = digest(files["diagnostic-package/knowledge-v3.4.4.zip"])
    files["STATUS.json"] = json.dumps(altered_status).encode()
    variants.append(("coherently resealed diagnostic substitution", zipped(seal(files)), None))
    rejected = []
    for label, body, expected in variants:
        try: verify(body, expected_sha256=expected, _parent_digest=digest(parent), _handoff_digest=digest(parent),
                    _diagnostic_digest=miniature_diagnostic_digest)
        except (Invalid, OSError, ValueError, TypeError, KeyError, RuntimeError, zipfile.BadZipFile): rejected.append(label)
        else: raise Invalid("tamper accepted: " + label)
    return {"status": "PASS_SELF_TEST", "positive_fixtures": 2, "rejected_tamper_count": len(rejected),
            "rejected_tampers": rejected, "embedded_code_executed": False,
            "production_input_override": "No CLI/environment override; miniature parent and diagnostic digests are private self-test inputs only."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", nargs="?", help="handoff ZIP or extracted root directory")
    parser.add_argument("--expected-sha256", help="Independently trusted outer ZIP SHA-256; never a manifest self-hash")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        need(bool(args.input) != args.self_test, "Provide one handoff input or --self-test")
        need(not args.self_test or args.expected_sha256 is None, "Self-test has no caller artifact digest")
        result = self_test() if args.self_test else verify(args.input, expected_sha256=args.expected_sha256)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (Invalid, OSError, ValueError, TypeError, KeyError, RuntimeError, zipfile.BadZipFile) as error:
        print(json.dumps({"status": "FAIL", "reason": str(error)}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

