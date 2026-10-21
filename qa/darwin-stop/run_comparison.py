"""Exact before/after Foundation regression; this does not qualify the backend."""
from pathlib import Path
import hashlib
import importlib.util
import json
import platform
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parents[1]
OUT = ROOT / "comparison"


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    require(platform.system() == "Darwin", "Darwin Foundation required; NOT_RUN is not PASS")
    OUT.mkdir(exist_ok=False)
    inputs = json.loads((ROOT / "INPUTS.json").read_bytes())
    for item in inputs["files"]:
        path = REPO / item["path"]
        require(path.is_file() and path.stat().st_size == item["bytes"]
                and digest(path) == item["sha256"], "input mismatch: " + item["path"])
    require(digest(ROOT / "helper.py") == inputs["helper_sha256"], "helper mismatch")
    spec = importlib.util.spec_from_file_location("stop_helper", ROOT / "helper.py")
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    names = helper.REQUIRED_CASES
    require(len(names) == 24 and len(set(names)) == 24, "unexpected case contract")
    records = []
    for label, expected_code in [("before", 1), ("after", 0)]:
        start = time.monotonic()
        source = ROOT / (label + ".m")
        argv = [sys.executable, str(ROOT / "helper.py"), "--source", str(source),
                "--output-dir", str(OUT / label)]
        with (OUT / (label + ".stdout.log")).open("wb") as stdout, \
                (OUT / (label + ".stderr.log")).open("wb") as stderr:
            run = subprocess.run(argv, stdout=stdout, stderr=stderr, timeout=180)
        report = json.loads((OUT / label / "RESULT.json").read_bytes())
        cases = report.get("cases", [])
        expected_flags = [True] * 19 + [label == "after"] * 5
        record = {"label": label, "argv": argv, "exit_code": run.returncode,
                  "elapsed_ms": round((time.monotonic() - start) * 1000, 3),
                  "source_sha256": digest(source),
                  "report_sha256": digest(OUT / label / "RESULT.json"),
                  "expected_passes": sum(expected_flags), "expected_failures": 24 - sum(expected_flags),
                  "matched": run.returncode == expected_code and report.get("compile_exit") == 0
                  and report.get("exit_code") == expected_code
                  and report.get("source_sha256") == inputs[label + "_sha256"]
                  and [row.get("name") for row in cases] == names
                  and [row.get("pass") for row in cases] == expected_flags
                  and report.get("status") == ("PASS" if label == "after" else "FAIL")}
        records.append(record)
    unchanged = all(digest(REPO / item["path"]) == item["sha256"] for item in inputs["files"])
    result = {"schema": "knowledge-darwin-stop-comparison.v1",
              "scope": "before/after actual producer functions with inert dependencies; no native qualification",
              "status": "PASS" if all(row["matched"] for row in records) and unchanged else "FAIL",
              "platform": platform.platform(), "machine": platform.machine(),
              "inputs_unchanged": unchanged, "runs": records, "capability_qualified": False}
    (OUT / "RESULT.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
