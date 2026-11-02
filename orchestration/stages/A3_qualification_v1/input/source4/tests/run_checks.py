#!/usr/bin/env python3
"""Compile the private slice; execute ONLY its syscall-replaced ordinary model.

The translation-only object has no main function and is never executed.
The executable's undefined-symbol allowlist is checked before execution.
No native Main/H, clone, credential transition, gate, Node or privileged test
is run by this program. Every output directory is new, preserving old FAILs.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time


def sha(path: Path) -> dict:
    data = path.read_bytes()
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--compiler", default="cc")
    args = parser.parse_args()
    here = Path(__file__).resolve().parent
    source = here.parent
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    temporary = output / "compiler-tmp"
    temporary.mkdir()
    process_environment = {"PATH": os.environ.get("PATH", os.defpath),
                           "LANG": "C", "LC_ALL": "C", "TMPDIR": str(temporary)}
    actions: list[dict] = []
    report = {
        "schema": "main-h-source4-ordinary-model-run.v1",
        "classification": "SOURCE_COMPILER_SYSCALL_MODEL_ONLY",
        "started_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "cwd": str(source),
        "output_directory": str(output),
        "python": sys.version,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "runner_euid": os.geteuid() if hasattr(os, "geteuid") else None,
        "note": "Host euid is recorded, not used as a Main/H identity assertion; all subject OS operations are mocked.",
        "subprocess_environment": process_environment,
        "source_pins": {},
        "actions": actions,
        "native_Main_H": "NOT_RUN",
        "privileged_execution": "NOT_RUN",
        "Node_or_bundle_execution": "NOT_RUN",
        "runtime_gate_or_release_qualification": "NOT_RUN",
        "result": "IN_PROGRESS",
    }

    def persist() -> None:
        (output / "RESULT.json").write_text(json.dumps(report, indent=2) + "\n")

    def run(label: str, argv: list[str], timeout: int = 30) -> tuple[int, bytes, bytes]:
        index = len(actions)
        prefix = f"{index:02d}-{label}"
        start = time.monotonic_ns()
        action = {
            "label": label, "argv": argv, "cwd": str(source),
            "started_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
            "stdout": prefix + ".stdout.bin", "stderr": prefix + ".stderr.bin",
            "timeout_seconds": timeout,
        }
        try:
            result = subprocess.run(argv, cwd=source, env=process_environment,
                                    capture_output=True, timeout=timeout, check=False)
            rc, stdout, stderr = result.returncode, result.stdout, result.stderr
            action["timeout"] = False
        except subprocess.TimeoutExpired as exc:
            rc, stdout, stderr = 124, exc.stdout or b"", exc.stderr or b""
            action["timeout"] = True
        except OSError as exc:
            rc, stdout, stderr = 125, b"", str(exc).encode()
            action["invocation_error"] = type(exc).__name__
        action.update(rc=rc, duration_ns=time.monotonic_ns() - start)
        (output / action["stdout"]).write_bytes(stdout)
        (output / action["stderr"]).write_bytes(stderr)
        actions.append(action)
        persist()
        return rc, stdout, stderr

    def stop(reason: str, code: int = 1, result: str = "FAIL") -> int:
        report.update(result=result, reason=reason, finished_utc=dt.datetime.now(dt.timezone.utc).isoformat())
        persist()
        print(json.dumps({"result": result, "reason": reason, "evidence": str(output)}, ensure_ascii=False))
        return code

    frozen = output / "sources"
    for path in [source / "main-h-birth-core.inc", *sorted(here.glob("*.c")), Path(__file__).resolve()]:
        data = path.read_bytes()
        relative = path.relative_to(source)
        report["source_pins"][str(relative)] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        captured = frozen / relative
        captured.parent.mkdir(parents=True, exist_ok=True)
        captured.write_bytes(data)
    compiler = shutil.which(args.compiler)
    nm = shutil.which("nm")
    if platform.system() != "Linux" or platform.machine() not in ("x86_64", "amd64"):
        return stop("Linux x86_64 headers/ABI required; no platform result inferred", 2, "NOT_RUN")
    if not compiler or not nm:
        return stop("C compiler or nm unavailable", 2, "NOT_RUN")
    if run("compiler-version", [compiler, "--version"])[0]:
        return stop("Compiler version command failed")
    if run("nm-version", [nm, "--version"])[0]:
        return stop("nm version command failed")
    flags = ["-std=c11", "-D_GNU_SOURCE", "-Wall", "-Wextra", "-Werror", "-Wpedantic", "-O2", "-fno-builtin", "-save-temps=obj"]
    native_object = output / "translation-only.o"
    if run("native-translation-only", [compiler, *flags, "-c", str(frozen / "tests/main_h_core_compile.c"), "-o", str(native_object)])[0]:
        return stop("Translation-only compile failed; native object was never executed")
    rc, native_symbols, _ = run("native-emitted-symbols", [nm, "-a", str(native_object)])
    required_native = {"mh_compile_only_api", "mh_spawn_original", "mh_release_original", "mh_cancel_original",
                       "mh_progress_original", "mh_finish_original", "mh_stop_original", "mh_child_drop_checked"}
    emitted = {line.split()[-1] for line in native_symbols.decode().splitlines() if line.split()}
    missing = sorted(required_native - emitted)
    report["native_body_emission"] = {"required": sorted(required_native), "missing": missing,
                                      "native_object_execution": "NOT_RUN"}
    if rc or missing:
        return stop("Native compile fixture did not retain every private entry body")
    model_object = output / "syscall-model.o"
    if run("model-compile", [compiler, *flags, "-c", str(frozen / "tests/main_h_core_model.c"), "-o", str(model_object)])[0]:
        return stop("Syscall model compile failed")
    rc, symbols, _ = run("model-undefined-symbols", [nm, "-u", str(model_object)])
    if rc:
        return stop("Cannot inspect model unresolved symbols")
    # No subject OS primitive is permitted in the executable. The model has
    # access only to memory, formatting, error storage and nonlocal test exits.
    allowed = {
        "__errno_location", "_GLOBAL_OFFSET_TABLE_", "printf", "fprintf", "puts", "putchar",
        "fputs", "fputc", "snprintf", "vsnprintf", "memset", "memcpy", "memmove", "memcmp",
        "strcmp", "strncmp", "strlen", "strchr", "strstr", "strcpy", "strncpy",
        "stdout", "stderr", "setjmp", "_setjmp", "longjmp", "exit", "abort",
        "__stack_chk_fail", "__assert_fail",
        # Verified in the captured glibc headers: fortified longjmp/printf
        # and the putchar -> putc(stdout) inline. No subject OS primitive.
        "__longjmp_chk", "__printf_chk", "putc",
    }
    unresolved = sorted({line.split()[-1].split("@")[0] for line in symbols.decode().splitlines() if line.split()})
    unexpected = sorted(set(unresolved) - allowed)
    report["model_symbol_guard"] = {"unresolved": unresolved, "unexpected": unexpected, "pass": not unexpected}
    persist()
    if unexpected:
        return stop("Model contains an unapproved unresolved symbol; execution refused")
    executable = output / "syscall-model"
    if run("model-link", [compiler, str(model_object), "-o", str(executable)])[0]:
        return stop("Model link failed")
    rc, stdout, _ = run("model-execution", [str(executable)], 30)
    try:
        records = [json.loads(line) for line in stdout.decode().splitlines() if line.strip()]
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return stop("Model output is not complete JSONL: " + str(exc))
    summaries = [r for r in records if r.get("kind") == "summary"]
    report["model_summary"] = summaries[-1] if summaries else None
    report["model_records"] = len(records)
    report["build_artifacts"] = {p.name: sha(p) for p in sorted(output.iterdir())
                                 if p.is_file() and (p.suffix in (".o", ".i", ".s") or p == executable)}
    if rc or not summaries or summaries[-1].get("failed", 1) or summaries[-1].get("passed", 0) < 1:
        return stop("Model execution/assertions failed")
    return stop("Translation-only compile and actual-source syscall model passed; physical behavior NOT_RUN", 0, "PASS_SOURCE_MODEL_ONLY")


if __name__ == "__main__":
    raise SystemExit(main())
