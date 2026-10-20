#!/usr/bin/env python3
"""Run one corrected F5 Team Inspector test in an isolated source copy."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any


EXPECTED_SOURCE_FILES = 465
EXPECTED_RUNTIME_FILES = 408
TEST_RELATIVE = "tests/team-inspector-evidence.test.js"
TIMEOUT_SECONDS = 180
AGENT_ID = "rc5-team-inspector-followup"


class CellError(RuntimeError):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def manifest_tree(root: Path) -> dict[str, dict[str, Any]]:
    if not root.is_dir():
        raise CellError(f"source directory is missing: {root}")
    result: dict[str, dict[str, Any]] = {}
    for path in root.rglob("*"):
        if path.is_symlink():
            raise CellError(f"symlinks are not allowed in source trees: {path}")
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        result[relative] = {"bytes": path.stat().st_size, "sha256": sha256_file(path)}
    return result


def validate_manifest(root: Path, expected: dict[str, Any], label: str) -> dict[str, dict[str, Any]]:
    actual = manifest_tree(root)
    expected_paths = set(expected)
    actual_paths = set(actual)
    changed = sorted(
        path for path in expected_paths & actual_paths
        if actual[path]["bytes"] != expected[path].get("bytes")
        or actual[path]["sha256"] != expected[path].get("sha256")
    )
    extra = sorted(actual_paths - expected_paths)
    missing = sorted(expected_paths - actual_paths)
    if changed or extra or missing:
        raise CellError(
            f"{label} differs from freeze: changed={len(changed)} extra={len(extra)} missing={len(missing)}"
        )
    return actual


def safe_relative(value: str) -> PurePosixPath:
    relative = PurePosixPath(value.replace("\\", "/"))
    if (relative.is_absolute() or any(part in ("", ".", "..") for part in relative.parts)
            or (relative.parts and ":" in relative.parts[0])):
        raise CellError(f"unsafe relative path: {value!r}")
    return relative


def copy_manifest(source: Path, destination: Path, manifest: dict[str, Any]) -> None:
    destination.mkdir(parents=True, exist_ok=False)
    for name in sorted(manifest):
        relative = safe_relative(name)
        src = source.joinpath(*relative.parts)
        dst = destination.joinpath(*relative.parts)
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dst)


def file_pin(path: Path, label: str | None = None) -> dict[str, Any]:
    return {
        "path": label if label is not None else str(path),
        "bytes": path.stat().st_size,
        "sha256": sha256_file(path),
    }


def parse_tap(output: bytes) -> dict[str, int] | None:
    text = output.decode("utf-8", errors="replace")
    names = {"tests": "tests", "pass": "pass", "fail": "fail", "cancelled": "cancelled", "skipped": "skipped", "todo": "todo"}
    found: dict[str, int] = {}
    for label, key in names.items():
        match = re.search(rf"^# {re.escape(label)}\s+(\d+)\s*$", text, re.MULTILINE)
        if match:
            found[key] = int(match.group(1))
    return found if "tests" in found and "pass" in found and "fail" in found else None


def stop_owned_process(process: subprocess.Popen[bytes]) -> tuple[dict[str, Any], bytes, bytes]:
    method = "direct process handle"
    if process.poll() is not None:
        try:
            out, err = process.communicate(timeout=5)
        except subprocess.TimeoutExpired as exc:
            for pipe in (process.stdout, process.stderr):
                if pipe:
                    pipe.close()
            return {"attempted": True, "scope": method, "result": "cleanup_unconfirmed"}, exc.output or b"", exc.stderr or b""
        return {"attempted": False, "scope": "direct process handle", "result": "already exited"}, out or b"", err or b""
    if os.name == "nt":
        process.terminate()
        method = "Popen.terminate on the directly owned child only"
    else:
        # The child was started in its own session; signal only that owned group.
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        method = "SIGTERM to the directly owned child process group"
    try:
        out, err = process.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        if os.name == "nt":
            process.kill()
            method += "; Popen.kill on direct child after grace period"
        else:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            method += "; SIGKILL to owned child process group after grace period"
        try:
            out, err = process.communicate(timeout=5)
        except subprocess.TimeoutExpired as exc:
            for pipe in (process.stdout, process.stderr):
                if pipe:
                    pipe.close()
            return {"attempted": True, "scope": method, "result": "cleanup_unconfirmed"}, exc.output or b"", exc.stderr or b""
    return {"attempted": True, "scope": method, "result": "terminated"}, out or b"", err or b""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True, help="F5 .knowledge tree")
    parser.add_argument("--test", type=Path, required=True, help="corrected test file to install at the fixed test path")
    parser.add_argument("--output", type=Path, required=True, help="new directory for raw output and manifests")
    parser.add_argument("--work", type=Path, required=True, help="new fixture root; .knowledge and tmp are created inside")
    parser.add_argument("--node", type=Path, required=True, help="Node executable for the target OS")
    parser.add_argument("--freeze", type=Path, required=True, help="F5 FREEZE.json; its local manifest is used, not its absolute path")
    args = parser.parse_args()

    source = args.source.resolve(strict=True)
    test = args.test.resolve(strict=True)
    node = args.node.resolve(strict=True)
    freeze_path = args.freeze.resolve(strict=True)
    output = args.output.resolve()
    work = args.work.resolve()
    controller = Path(__file__).resolve(strict=True)
    if not node.is_file() or not test.is_file():
        raise CellError("Node and corrected test must be regular files")
    if output.exists() or work.exists():
        raise CellError("output and work paths must be new; refusing to reuse or overwrite either")
    if output == work or output in work.parents or work in output.parents:
        raise CellError("output and work directories must be separate")
    if (source == output or source in output.parents or output in source.parents
            or source == work or source in work.parents or work in source.parents):
        raise CellError("output/work paths must not be inside or equal to the frozen source")

    freeze = json.loads(freeze_path.read_text(encoding="utf-8-sig"))
    if freeze.get("schema") != "r20-source-freeze.v1":
        raise CellError("unsupported freeze schema")
    source_manifest = freeze.get("source_manifest")
    runtime_manifest = freeze.get("runtime_manifest")
    if not isinstance(source_manifest, dict) or len(source_manifest) != EXPECTED_SOURCE_FILES:
        raise CellError("freeze does not contain the expected 465-file source manifest")
    if not isinstance(runtime_manifest, dict) or len(runtime_manifest) != EXPECTED_RUNTIME_FILES:
        raise CellError("freeze does not contain the expected 408-file runtime manifest")
    for key in ("source_files", "source_count"):
        if key in freeze and freeze[key] != EXPECTED_SOURCE_FILES:
            raise CellError(f"freeze {key} is inconsistent")
    if freeze.get("runtime_files") != EXPECTED_RUNTIME_FILES:
        raise CellError("freeze runtime count is inconsistent")
    if TEST_RELATIVE not in source_manifest:
        raise CellError(f"freeze is missing the expected test path {TEST_RELATIVE}")

    before_source = validate_manifest(source, source_manifest, "F5 source")
    node_before = file_pin(node)
    controller_before = file_pin(controller)
    test_before = file_pin(test)
    if test_before["sha256"] == source_manifest[TEST_RELATIVE].get("sha256"):
        raise CellError("corrected test is byte-identical to the frozen test; refusing a no-op replay")

    output.mkdir(parents=True, exist_ok=False)
    work.mkdir(parents=True, exist_ok=False)
    fixture = work / ".knowledge"
    temp_root = work / "tmp"
    temp_root.mkdir()
    started = utc_now()
    monotonic_started = time.monotonic()
    run_result: dict[str, Any] = {
        "schema": "f5-team-inspector-followup.v1",
        "status": "fail",
        "started_at": started,
        "candidate": {
            "version": freeze.get("version"),
            "revision": freeze.get("release", {}).get("audit_revision"),
            "archive_sha256": freeze.get("archive_sha256"),
            "source_files_expected": EXPECTED_SOURCE_FILES,
            "runtime_files_expected": EXPECTED_RUNTIME_FILES,
            "source_manifest_sha256": freeze.get("source_manifest_sha256"),
            "runtime_manifest_sha256": freeze.get("runtime_manifest_sha256"),
            "freeze": {"path": str(freeze_path), "bytes": freeze_path.stat().st_size, "sha256": sha256_file(freeze_path)},
        },
        "source": {"before": {"file_count": len(before_source), "manifest": before_source}},
        "node": {"before": node_before},
        "controller": {"before": controller_before},
        "test_input": {"pin": test_before, "installed_path": TEST_RELATIVE},
        "command": None,
        "environment_overrides": None,
        "timeout_seconds": TIMEOUT_SECONDS,
        "tap": None,
        "process_cleanup": {"scope_limit": "owned process handle/group only; no general process-tree containment claim"},
        "limitations": ["A timeout is recorded as failure. Cleanup is limited to the directly owned child (Windows) or its owned session group (POSIX)."],
    }
    run_result["source"]["root"] = str(source)
    run_result["candidate"]["archive_observation"] = "ZIP is not opened by this source-only replay; its identity is reported from FREEZE.json and runtime files are bound by the 408-entry freeze manifest."

    stdout = b""
    stderr = b""
    process: subprocess.Popen[bytes] | None = None
    timed_out = False
    return_code: int | None = None
    try:
        copy_manifest(source, fixture, source_manifest)
        fixture_before_test = manifest_tree(fixture)
        if fixture_before_test != before_source:
            raise CellError("fresh fixture copy is not byte-identical to the F5 source")
        test_target = fixture / TEST_RELATIVE
        test_target.write_bytes(test.read_bytes())
        fixture_after_test = manifest_tree(fixture)
        changed = sorted(
            path for path in set(fixture_before_test) | set(fixture_after_test)
            if fixture_before_test.get(path) != fixture_after_test.get(path)
        )
        if changed != [TEST_RELATIVE] or len(fixture_after_test) != EXPECTED_SOURCE_FILES:
            raise CellError(f"fixture must differ in exactly {TEST_RELATIVE}; observed changes={changed}")
        run_result["fixture"] = {
            "root": str(fixture),
            "before": {"file_count": len(fixture_before_test), "manifest": fixture_before_test},
            "after_install": {"file_count": len(fixture_after_test), "manifest": fixture_after_test},
            "changed_paths": changed,
            "source_files_unchanged_except_test": True,
        }
        command = [str(node), "--test", "--test-concurrency=1", TEST_RELATIVE]
        env = {k: v for k, v in os.environ.items() if not k.startswith("KNOWLEDGE_")}
        overrides = {
            "TMPDIR": str(temp_root), "TEMP": str(temp_root), "TMP": str(temp_root),
            "KNOWLEDGE_DISABLE_GIT_DISCOVERY": "1", "GIT_CEILING_DIRECTORIES": str(work),
            "GIT_TERMINAL_PROMPT": "0", "KNOWLEDGE_UPDATE_DISABLE_ON_LAUNCH": "1",
            "KNOWLEDGE_FLOW_NO_OPEN": "1", "KNOWLEDGE_INSPECTOR_NO_OPEN": "1",
            "BROWSER": "none", "KNOWLEDGE_AGENT_ID": AGENT_ID,
        }
        env.update(overrides)
        run_result["command"] = command
        run_result["cwd"] = str(fixture)
        run_result["environment_overrides"] = overrides
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
        process = subprocess.Popen(
            command, cwd=fixture, env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=(os.name != "nt"), creationflags=creationflags,
        )
        try:
            stdout, stderr = process.communicate(timeout=TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            timed_out = True
            action, stdout, stderr = stop_owned_process(process)
            run_result["process_cleanup"]["timeout_action"] = action
        return_code = process.returncode
        run_result["timed_out"] = timed_out
        run_result["exit_code"] = return_code
        run_result["tap"] = parse_tap(stdout)
        tap = run_result["tap"]
        run_result["status"] = (
            "pass" if not timed_out and return_code == 0 and tap
            and tap.get("tests", 0) > 0 and tap.get("pass") == tap.get("tests")
            and tap.get("fail", 0) == 0 and tap.get("todo", 0) == 0
            and tap.get("skipped", 0) == 0 and tap.get("cancelled", 0) == 0
            else "fail"
        )
        run_result["failure_reason"] = None if run_result["status"] == "pass" else "timeout, nonzero exit, invalid TAP summary, test failure, skip, or cancellation"
    except Exception as exc:
        run_result["status"] = "fail"
        run_result["failure_reason"] = f"{type(exc).__name__}: {exc}"
        run_result["timed_out"] = timed_out
        run_result["exit_code"] = return_code
    finally:
        if process is not None and process.poll() is None and not timed_out:
            action, final_stdout, final_stderr = stop_owned_process(process)
            run_result["process_cleanup"]["final_action"] = action
            stdout += final_stdout
            stderr += final_stderr
            if run_result["status"] == "pass":
                run_result["status"] = "fail"
                run_result["failure_reason"] = "owned process remained active after API return"
        (output / "stdout.bin").write_bytes(stdout)
        (output / "stderr.bin").write_bytes(stderr)
        (output / "stdout.txt").write_text(stdout.decode("utf-8", errors="replace"), encoding="utf-8", newline="\n")
        (output / "stderr.txt").write_text(stderr.decode("utf-8", errors="replace"), encoding="utf-8", newline="\n")
        run_result["raw"] = {
            "stdout": file_pin(output / "stdout.bin", "stdout.bin"),
            "stderr": file_pin(output / "stderr.bin", "stderr.bin"),
            "stdout_text": file_pin(output / "stdout.txt", "stdout.txt"),
            "stderr_text": file_pin(output / "stderr.txt", "stderr.txt"),
        }
        after_source = manifest_tree(source)
        run_result["source"]["after"] = {
            "file_count": len(after_source),
            "unchanged": after_source == before_source,
            "manifest": after_source,
        }
        run_result["node"]["after"] = file_pin(node)
        run_result["node"]["unchanged"] = run_result["node"]["before"] == run_result["node"]["after"]
        run_result["controller"]["after"] = file_pin(controller)
        run_result["controller"]["unchanged"] = run_result["controller"]["before"] == run_result["controller"]["after"]
        run_result["test_input"]["unchanged"] = file_pin(test) == test_before
        if "fixture" in run_result:
            fixture_after_run = manifest_tree(fixture)
            run_result["fixture"]["after_run"] = {
                "file_count": len(fixture_after_run), "manifest": fixture_after_run,
                "unchanged": fixture_after_run == run_result["fixture"]["after_install"]["manifest"],
            }
        run_result["duration_ms"] = round((time.monotonic() - monotonic_started) * 1000, 3)
        run_result["finished_at"] = utc_now()
        run_result["api_return_observation"] = {
            "parent_child_poll_at_collection": None if process is None else process.poll(),
            "scope": "direct Node child handle only; descendants that escape the process group are outside this observation",
        }
        # Integrity failures override a test pass.
        if not run_result.get("source", {}).get("after", {}).get("unchanged") or not run_result["node"]["unchanged"] or not run_result["controller"]["unchanged"] or not run_result["test_input"]["unchanged"] or not run_result.get("fixture", {}).get("after_run", {}).get("unchanged"):
            run_result["status"] = "fail"
            run_result["failure_reason"] = "source, Node, controller, or corrected-test input changed during run"
        temp_manifest = manifest_tree(temp_root)
        run_result["temp_outputs"] = {"file_count": len(temp_manifest), "manifest": temp_manifest}
        tmp_json = output / "result.json.tmp"
        tmp_json.write_text(json.dumps(run_result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
        tmp_json.replace(output / "result.json")

    print(json.dumps({k: run_result.get(k) for k in ["status", "tap", "duration_ms", "failure_reason"]}))
    return 0 if run_result["status"] == "pass" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except CellError as exc:
        print(f"inspector cell preflight failed: {exc}", file=sys.stderr)
        raise SystemExit(2)
