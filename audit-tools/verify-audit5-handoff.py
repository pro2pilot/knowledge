#!/usr/bin/env python3
"""Verify audit5 handoff integrity without executing or extracting its contents.

Manifest self-hashes are consistency checks, not independent authenticity or
runtime qualification. Authenticate the outer ZIP digest through a separate
trusted channel. The original AUDIT2 input has an independent fixed digest.
"""
from __future__ import annotations
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import unicodedata
import zipfile

ORIGINAL_SHA256 = "1ea39e5eaa94ba5e037187acb028857ff0bf03f1e096551e7d30eb692176d6b2"
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
    return json.loads(body.decode("utf-8", "strict"), object_pairs_hook=unique, parse_constant=nonfinite)


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
                        (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) ==
                        (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns)):
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


def verify(source, *, _original_digest=ORIGINAL_SHA256):
    store = Store(source)
    try:
        manifest_raw = store.read("MANIFEST.json", 16 * 1024 * 1024)
        manifest = json_value(manifest_raw)
        need(isinstance(manifest, dict) and set(manifest) == {"schema_version", "files"} and
             manifest["schema_version"] == "audit5.manifest.v1" and isinstance(manifest["files"], dict), "manifest schema")
        entries = manifest["files"]
        inventory_names(entries)
        need("MANIFEST.json" not in entries and set(entries) == set(store.files) - {"MANIFEST.json"}, "manifest inventory mismatch")
        for name, record in entries.items():
            need(isinstance(record, dict) and set(record) == {"sha256", "size"} and
                 isinstance(record["sha256"], str) and HEX.fullmatch(record["sha256"]) is not None and
                 type(record["size"]) is int and 0 <= record["size"] <= MAX_FILE, "manifest entry schema")
            body = store.read(name)
            need(len(body) == record["size"] and digest(body) == record["sha256"], "member hash/size mismatch: " + name)
        need(digest(store.read("original/AUDIT2_INPUT.zip")) == _original_digest, "original AUDIT2 input digest mismatch")
        status = json_value(store.read("STATUS.json", 1024 * 1024))
        need(isinstance(status, dict) and status.get("release_qualified") is False and
             status.get("production_linux_service") == "NOT_IMPLEMENTED" and status.get("stock_sip_macos") == "UNCONFIRMED",
             "status cannot promote unresolved release/platform gates")
        pins = json_value(store.read("source/SOURCE_PINS.json", 8 * 1024 * 1024))
        need(isinstance(pins, dict) and set(pins) == {"schema_version", "file_count", "files", "input_source_sha256"} and
             pins["schema_version"] == "knowledge-audit5-source-pins.v1" and type(pins["file_count"]) is int and
             isinstance(pins["files"], dict) and pins["file_count"] == len(pins["files"]) > 0 and
             isinstance(pins["input_source_sha256"], str) and HEX.fullmatch(pins["input_source_sha256"]), "source pins schema")
        inventory_names(pins["files"])
        nested = Store(store.read("source/SOURCE.zip"))
        try:
            need(set(nested.files) == {".knowledge/" + name for name in pins["files"]}, "source ZIP inventory mismatch")
            for name, expected in pins["files"].items():
                need(isinstance(expected, str) and HEX.fullmatch(expected) and
                     digest(nested.read(".knowledge/" + name)) == expected, "source pin mismatch: " + name)
        finally:
            nested.close()
        return {"status": "PASS_BUNDLE_INTEGRITY_ONLY", "files": len(entries), "source_files": pins["file_count"],
                "manifest_sha256": digest(manifest_raw), "release_qualified": False,
                "trust_limit": "Manifest self-hashes do not prove authenticity or runtime behavior; verify an independently supplied outer ZIP SHA-256."}
    finally:
        store.close()


def self_test():
    def zipped(files):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            for name, body in files.items():
                archive.writestr(name, body)
        return buffer.getvalue()
    original = zipped({"original.txt": b"fixed miniature original"})
    def fixture():
        body = b"module.exports=1;\n"
        return {"original/AUDIT2_INPUT.zip": original,
                "STATUS.json": json.dumps({"release_qualified": False, "production_linux_service": "NOT_IMPLEMENTED", "stock_sip_macos": "UNCONFIRMED"}).encode(),
                "source/SOURCE.zip": zipped({".knowledge/tools/probe.js": body}),
                "source/SOURCE_PINS.json": json.dumps({"schema_version": "knowledge-audit5-source-pins.v1", "file_count": 1,
                    "input_source_sha256": "a" * 64, "files": {"tools/probe.js": digest(body)}}).encode()}
    def seal(files):
        files["MANIFEST.json"] = json.dumps({"schema_version": "audit5.manifest.v1",
            "files": {name: {"sha256": digest(body), "size": len(body)} for name, body in files.items() if name != "MANIFEST.json"}}).encode()
        return files
    cases = []
    baseline = seal(fixture())
    need(verify(zipped(baseline), _original_digest=digest(original))["status"] == "PASS_BUNDLE_INTEGRITY_ONLY", "positive ZIP fixture")
    with tempfile.TemporaryDirectory(prefix="audit5-verifier-", dir=Path.cwd()) as root:
        for name, body in baseline.items():
            path = Path(root) / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(body)
        need(verify(root, _original_digest=digest(original))["files"] == 4, "positive directory fixture")
        if hasattr(os, "symlink"):
            try:
                (Path(root) / "alias").symlink_to("STATUS.json")
            except OSError:
                pass
            else:
                try:
                    verify(root, _original_digest=digest(original))
                except (Invalid, OSError):
                    cases.append("symlink")
                else:
                    raise Invalid("symlink tamper accepted")
    variants = []
    files = dict(baseline); files["STATUS.json"] += b" "; variants.append(("hash mismatch", files))
    files = dict(baseline); files["extra.txt"] = b"extra"; variants.append(("extra", files))
    files = dict(baseline); del files["STATUS.json"]; variants.append(("omission", files))
    files = fixture(); files["original/AUDIT2_INPUT.zip"] = b"substitute"; variants.append(("resealed original substitute", seal(files)))
    files = fixture(); files["STATUS.json"] = b'{"release_qualified":true,"production_linux_service":"NOT_IMPLEMENTED","stock_sip_macos":"UNCONFIRMED"}'; variants.append(("resealed promotion", seal(files)))
    files = fixture(); files["source/SOURCE.zip"] = zipped({".knowledge/tools/probe.js": b"changed"}); variants.append(("resealed source substitution", seal(files)))
    files = dict(baseline); files["../escape"] = b"bad"; variants.append(("path traversal", files))
    for label, files in variants:
        try:
            verify(zipped(files), _original_digest=digest(original))
        except (Invalid, OSError, zipfile.BadZipFile):
            cases.append(label)
        else:
            raise Invalid("tamper accepted: " + label)
    return {"status": "PASS_SELF_TEST", "positive_fixtures": 2, "rejected_tampers": cases,
            "production_input_override": "No CLI/environment override; miniature expected digest is private self-test input only."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", nargs="?", help="handoff ZIP or extracted root directory")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        need(bool(args.input) != args.self_test, "Provide one handoff input or --self-test")
        result = self_test() if args.self_test else verify(args.input)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (Invalid, OSError, ValueError, TypeError, KeyError, RuntimeError, zipfile.BadZipFile) as error:
        print(json.dumps({"status": "FAIL", "reason": str(error)}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
