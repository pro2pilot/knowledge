#!/usr/bin/env python3
"""QA only. Explicit sudo installs/removes one own fixed C binary and own profiles.

Never changes a sysctl, existing profile, Node profile, host capabilities or SUID.
Do not run before reviewing this source, generated policy and the workflow.
"""
from __future__ import annotations
import argparse
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import queue
import re
import select
import signal
import stat
import struct
import subprocess
import sys
import threading
import time
import uuid

HERE = Path(__file__).resolve().parent
DENIAL = {errno.EPERM, errno.EACCES}
POLICY_FILES = (
    "/proc/sys/kernel/apparmor_restrict_unprivileged_userns",
    "/proc/sys/kernel/apparmor_restrict_unprivileged_unconfined",
    "/sys/module/apparmor/parameters/enabled",
)
CAP = 1024 * 1024

def digest(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()

def policy_snapshot() -> dict:
    values = {}
    for file in POLICY_FILES:
        try:
            values[file] = Path(file).read_text().strip()
        except OSError as error:
            values[file] = {"unavailable_errno": error.errno}
    return values

def command(argv: list[str], timeout: float = 10, env: dict | None = None) -> dict:
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=timeout, check=False,
                            env=env or {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
    if len(result.stdout) > CAP or len(result.stderr) > CAP:
        raise RuntimeError("bounded_admin_command_output_exceeded")
    return {"argv": argv, "exit_code": result.returncode,
            "stdout": result.stdout.decode(errors="replace"),
            "stderr": result.stderr.decode(errors="replace")}

def checked(argv: list[str], timeout: float = 10) -> dict:
    result = command(argv, timeout)
    if result["exit_code"] != 0:
        raise RuntimeError(json.dumps({"admin_command_failed": result}))
    return result

def static_elf(binary: Path) -> dict:
    body=binary.read_bytes()
    if len(body)<64 or body[:4]!=b"\x7fELF" or body[4]!=2 or body[5]!=1:
        raise RuntimeError("requires_static_64bit_little_endian_ELF")
    offset=struct.unpack_from("<Q",body,32)[0]
    size=struct.unpack_from("<H",body,54)[0]
    count=struct.unpack_from("<H",body,56)[0]
    if size<56 or count<1 or count>256 or offset+size*count>len(body):
        raise RuntimeError("invalid_ELF_program_headers")
    types=[struct.unpack_from("<I",body,offset+size*i)[0] for i in range(count)]
    if 2 in types or 3 in types:
        raise RuntimeError("authority_ELF_has_dynamic_or_interpreter_segment")
    return {"ELF64":True,"PT_INTERP":False,"PT_DYNAMIC":False}

def loader_tests(compiler: str, out: Path, executable: Path) -> dict:
    library=out/"untrusted-loader-sentinel.so"
    checked([compiler,"-shared","-fPIC","-Wall","-Wextra","-Werror",
             str(HERE/"loader_sentinel.c"),"-o",str(library)],30)
    result={"sentinel_source_sha256":digest((HERE/"loader_sentinel.c").read_bytes()),
            "sentinel_library_sha256":digest(library.read_bytes()),"cases":[]}
    for variable in ("LD_PRELOAD","LD_AUDIT"):
        positive=out/(variable+".positive.marker")
        negative=out/(variable+".authority.marker")
        environment={"PATH":"/usr/bin:/bin","LC_ALL":"C",variable:str(library),
                     "KNOWLEDGE_QA_LOADER_SENTINEL":str(positive)}
        positive_run=command(["/usr/bin/true"],5,environment)
        positive_ok=positive_run["exit_code"]==93 and positive.read_bytes()==b"UNTRUSTED_CONSTRUCTOR_EXECUTED\n" if positive.exists() else False
        environment["KNOWLEDGE_QA_LOADER_SENTINEL"]=str(negative)
        negative_run=command([str(executable),"--loader-check"],5,environment)
        try:
            report=json.loads(negative_run["stdout"])
        except ValueError:
            report={}
        negative_ok=negative_run["exit_code"]==0 and not negative.exists() and report.get("event")=="loader_check" and \
                    report.get("authority_label") is True and report.get("caps_zero") is True
        result["cases"].append({"variable":variable,"positive_constructor_valid":positive_ok,
                                "untrusted_constructor_blocked":negative_ok,
                                "positive_exit":positive_run["exit_code"],"authority_exit":negative_run["exit_code"],
                                "authority_report":report})
    result["passed"]=all(row["positive_constructor_valid"] and row["untrusted_constructor_blocked"] for row in result["cases"])
    return result

def denied(rc: int, operation_errno: int) -> dict:
    return {"denied": rc == -1 and operation_errno in DENIAL,
            "return_value": rc, "errno": operation_errno}

def traced_exec(executable: Path, arguments: list[str]) -> dict:
    """One own child; never writes registers/memory or targets another process.

    TRACEEXEC proves a successful exec stopped before its first instruction.
    EXITKILL and an exact pidfd bound failure cleanup. Userspace guard refusal
    after successful exec is recorded, but never qualifies kernel isolation.
    """
    libc = ctypes.CDLL(None, use_errno=True)
    libc.ptrace.restype = ctypes.c_long
    libc.ptrace.argtypes = [ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_void_p]
    read_fd, write_fd = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
    child = os.fork()
    if child == 0:
        try:
            os.close(read_fd)
            os.dup2(write_fd, 1)
            os.dup2(write_fd, 2)
            os.close(write_fd)
            null = os.open("/dev/null", os.O_RDONLY)
            os.dup2(null, 0)
            if null > 2:
                os.close(null)
            if libc.ptrace(0, 0, None, None) != 0:  # TRACEME
                os._exit(120)
            os.kill(os.getpid(), signal.SIGSTOP)
            try:
                os.execve(str(executable), [str(executable), *arguments], {"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
            except OSError as error:
                os.write(1, json.dumps({"exec_denied_errno": error.errno}).encode() + b"\n")
                os._exit(126)
        except BaseException:
            os._exit(121)
    os.close(write_fd)
    pidfd = None
    reaped = False
    report = {"initial_trace_stop": False, "exec_event_observed": False,
              "cleanup_confirmed": False, "qualification": False}
    body = bytearray()
    try:
        pidfd = os.pidfd_open(child)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            while True:
                try:
                    raw = os.read(read_fd, 4096)
                except BlockingIOError:
                    break
                if not raw:
                    break
                body.extend(raw)
                if len(body) > 8192:
                    raise RuntimeError("tracer_fixture_output_limit")
            got, status = os.waitpid(child, os.WNOHANG | os.WUNTRACED)
            if not got:
                time.sleep(.01)
                continue
            if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                reaped = True
                report["exit_code"] = os.waitstatus_to_exitcode(status)
                break
            if not os.WIFSTOPPED(status):
                raise RuntimeError("unexpected_trace_wait_status")
            if not report["initial_trace_stop"]:
                if os.WSTOPSIG(status) != signal.SIGSTOP:
                    raise RuntimeError("missing_initial_trace_stop")
                # PTRACE_O_TRACEEXEC | PTRACE_O_EXITKILL
                if libc.ptrace(0x4200, child, None, ctypes.c_void_p(0x10 | 0x100000)) != 0:
                    raise RuntimeError("trace_options_failed")
                report["initial_trace_stop"] = True
            elif status >> 16 == 4:  # PTRACE_EVENT_EXEC
                report["exec_event_observed"] = True
            else:
                raise RuntimeError("unexpected_trace_stop")
            if libc.ptrace(7, child, None, None) != 0:  # CONT; no signal injection
                raise RuntimeError("trace_continue_failed")
        if not reaped:
            raise RuntimeError("bounded_tracer_fixture_deadline")
        while True:
            try:
                raw = os.read(read_fd, 4096)
            except BlockingIOError:
                break
            if not raw:
                break
            body.extend(raw)
            if len(body) > 8192:
                raise RuntimeError("tracer_fixture_output_limit")
        rows = [json.loads(line) for line in body.splitlines()]
        report["exec_denied_errno"] = next((r.get("exec_denied_errno") for r in rows if "exec_denied_errno" in r), None)
        report["userspace_tracer_refused"] = any(r.get("event") == "pre_authority_tracer_refusal" and
                                                  r.get("tracer_present") is True and r.get("authority_entered") is False for r in rows)
        report["authority_work_observed"] = any(r.get("event") in ("parent_probe_ready", "authority_depth") for r in rows)
    except Exception as error:
        report["fixture_error"] = str(error)
    finally:
        if not reaped:
            try:
                if pidfd is not None:
                    signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                else:
                    # This exact direct child has not been reaped: its PID
                    # cannot be reused. No search or absence inference.
                    os.kill(child, signal.SIGKILL)
            except OSError as error:
                if error.errno != errno.ESRCH:
                    report["stop_errno"] = error.errno
            end = time.monotonic() + 2
            while time.monotonic() < end:
                got, _ = os.waitpid(child, os.WNOHANG)
                if got:
                    reaped = True
                    break
                time.sleep(.01)
        report["cleanup_confirmed"] = reaped and pidfd is not None and bool(select.select([pidfd], [], [], 0)[0])
        if pidfd is not None:
            os.close(pidfd)
        os.close(read_fd)
    return report

def preexec_tracer_tests(compiler: str, out: Path, executable: Path) -> dict:
    source = HERE / "ptrace_sentinel.c"
    sentinel = out / "inert-static-tracer-target"
    checked([compiler, "-O2", "-Wall", "-Wextra", "-Werror", "-static", "-fno-pie", "-no-pie",
             str(source), "-o", str(sentinel)], 30)
    elf = static_elf(sentinel)
    positive = traced_exec(sentinel, [])
    negative = traced_exec(executable, ["--suite"])
    positive_ok = positive.get("initial_trace_stop") is True and positive.get("exec_event_observed") is True and \
                  positive.get("exit_code") == 0 and positive.get("cleanup_confirmed") is True and "fixture_error" not in positive
    kernel_refused = negative.get("initial_trace_stop") is True and negative.get("exec_event_observed") is False and \
                     negative.get("exec_denied_errno") in DENIAL and negative.get("exit_code") == 126 and \
                     negative.get("cleanup_confirmed") is True and "fixture_error" not in negative
    return {"source_sha256": digest(source.read_bytes()), "binary_sha256": digest(sentinel.read_bytes()), "ELF": elf,
            "positive": positive, "negative": negative, "positive_valid": positive_ok,
            "kernel_exec_refused": kernel_refused, "passed": positive_ok and kernel_refused,
            "scope": "Inherited own-child tracer; userspace refusal alone is not isolation"}

def parent_access_tests(pid: int, ready: dict) -> dict:
    """Only the known paused own C child's fixed marker is targeted."""
    libc = ctypes.CDLL(None, use_errno=True)
    libc.ptrace.restype = ctypes.c_long
    libc.ptrace.argtypes = [ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_void_p]
    ctypes.set_errno(0)
    rc = libc.ptrace(16, pid, None, None)  # PTRACE_ATTACH
    tests = {"ptrace_attach": denied(rc, ctypes.get_errno())}
    if rc == 0:
        end = time.monotonic() + 2
        stopped = False
        while time.monotonic() < end:
            got, status = os.waitpid(pid, os.WUNTRACED | os.WNOHANG)
            if got and os.WIFSTOPPED(status):
                stopped = True
                break
            time.sleep(.01)
        if not stopped or libc.ptrace(17, pid, None, None) != 0:  # DETACH
            raise RuntimeError("unexpected_ptrace_allowed_detach_unconfirmed")

    class IOVec(ctypes.Structure):
        _fields_ = [("base", ctypes.c_void_p), ("length", ctypes.c_size_t)]
    word = ctypes.c_uint64(int(ready["fixed_word"]))
    local = IOVec(ctypes.addressof(word), ctypes.sizeof(word))
    remote = IOVec(int(ready["address"]), ctypes.sizeof(word))
    for name in ("process_vm_readv", "process_vm_writev"):
        call = getattr(libc, name)
        call.restype = ctypes.c_ssize_t
        call.argtypes = [ctypes.c_int, ctypes.POINTER(IOVec), ctypes.c_ulong,
                         ctypes.POINTER(IOVec), ctypes.c_ulong, ctypes.c_ulong]
        ctypes.set_errno(0)
        value = call(pid, ctypes.byref(local), 1, ctypes.byref(remote), 1, 0)
        tests[name] = denied(value, ctypes.get_errno())
    for label, flags in (("proc_mem_read", os.O_RDONLY), ("proc_mem_write", os.O_RDWR)):
        fd = None
        try:
            fd = os.open(f"/proc/{pid}/mem", flags | os.O_CLOEXEC)
            if label.endswith("read"):
                value = len(os.pread(fd, 8, int(ready["address"])))
            else:
                value = os.pwrite(fd, int(ready["fixed_word"]).to_bytes(8, sys.byteorder), int(ready["address"]))
            tests[label] = denied(value, 0)
        except OSError as error:
            tests[label] = denied(-1, error.errno)
        finally:
            if fd is not None:
                os.close(fd)
    fd = None
    try:
        # Access to an actual fixed private pipe, not merely listing fd names.
        fd = os.open(f"/proc/{pid}/fd/{int(ready['probe_fd'])}", os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
        tests["proc_fd_access"] = denied(fd, 0)
    except OSError as error:
        tests["proc_fd_access"] = denied(-1, error.errno)
    finally:
        if fd is not None:
            os.close(fd)
    return tests

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    if not out.is_relative_to(HERE) or out == HERE or out.exists():
        raise SystemExit("Output must be a new strict descendant of this QA directory.")
    out.mkdir(parents=True, mode=0o700)
    os.chmod(out, 0o700)
    inputs = {name: digest((HERE / name).read_bytes()) for name in
              ("run_probe.py", "probe.c", "profile.template", "loader_sentinel.c", "ptrace_sentinel.c")}

    def refuse_preflight(code: str) -> int:
        summary = {"schema": "knowledge-linux-admin-primitive-probe.v1", "qualification": False,
                   "status": "FAIL_OR_INCOMPLETE", "phase": "pre_install_admission",
                   "error_code": code, "input_sha256": inputs,
                   "admin_steps": [], "owned_installation_created": False,
                   "native_processes_admitted": False, "global_policy_changes_attempted": False}
        (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
        os.chmod(out / "summary.json", 0o600)
        return 1

    if sys.platform != "linux":
        return refuse_preflight("linux_required")
    if os.getresuid() != (1001, 1001, 1001) or os.getresgid() != (1001, 1001, 1001):
        return refuse_preflight("dedicated_nonroot_uid_gid_required")
    try:
        if Path("/proc/self/attr/current").read_text().strip() != "unconfined":
            return refuse_preflight("unconfined_parent_required")
    except OSError:
        return refuse_preflight("parent_label_unavailable")
    token = uuid.uuid4().hex
    profile = "knowledge_qa27_" + token
    install = Path("/var/lib") / ("knowledge-qa27-" + token)
    if not re.fullmatch(r"/var/lib/knowledge-qa27-[a-f0-9]{32}", str(install)):
        raise RuntimeError("invalid_owned_install_path")
    # Hosted runners intentionally make /opt writable by their normal user.
    # Use a separate fixed administration parent; never repair its permissions.
    try:
        if install.exists() or install.is_symlink():
            raise RuntimeError("existing_owned_install_path")
        for parent in install.parents:
            identity = parent.lstat()
            if not stat.S_ISDIR(identity.st_mode) or identity.st_uid != 0 or identity.st_mode & 0o022:
                raise RuntimeError("unsafe_install_parent")
    except (OSError, RuntimeError) as error:
        return refuse_preflight(str(error) if isinstance(error, RuntimeError) else "install_parent_unavailable")
    before = policy_snapshot()
    if before[POLICY_FILES[0]] != "1" or before[POLICY_FILES[2]] not in ("Y", "1"):
        return refuse_preflight("enforcing_restricted_userns_required")
    source = (HERE / "probe.c").read_bytes()
    template = (HERE / "profile.template").read_text()
    binary = out / "probe"
    profile_file = out / "profile"
    policy = template.replace("@PROFILE@", profile).replace("@EXECUTABLE@", str(install / "probe")) \
                     .replace("@STACK@", profile + "//&" + profile + "//worker") \
                     .replace("@STACK_REVERSE@", profile + "//worker//&" + profile)
    profile_file.write_text(policy)
    summary = {"schema": "knowledge-linux-admin-primitive-probe.v1", "qualification": False,
               "status": "NOT_RUN", "profile": profile, "source_sha256": digest(source), "input_sha256": inputs,
               "policy_sha256": digest(policy.encode()), "global_policy_before": before,
               "scope": "Fixed C QA primitives only, not production runtime support", "admin_steps": []}
    process = None
    root_pidfd = None
    profile_load_attempted = False
    install_created = False
    sent_go = False
    root_closed = False
    final = None
    preexec_cleanup_confirmed = True
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    events: list[dict] = []
    event_queue: queue.Queue = queue.Queue()

    def admin(*argv: str) -> None:
        result = checked(["sudo", "-n", *argv])
        summary["admin_steps"].append(result)

    def collect(kind: str, stream) -> None:
        try:
            while True:
                raw = stream.readline(8193)
                if not raw:
                    break
                if len(captured[kind]) + len(raw) > CAP:
                    event_queue.put({"collection_error": "output_limit"})
                    break
                captured[kind].extend(raw)
                if kind == "stdout":
                    try:
                        value = json.loads(raw)
                        if not isinstance(value, dict):
                            raise ValueError()
                        event_queue.put(value)
                    except ValueError:
                        event_queue.put({"collection_error": "invalid_fixed_probe_json"})
        finally:
            stream.close()

    try:
        compiler_path = Path("/usr/bin/cc").resolve(strict=True)
        for artifact in (compiler_path, *compiler_path.parents):
            identity = artifact.lstat()
            if identity.st_uid != 0 or identity.st_mode & 0o022 or stat.S_ISLNK(identity.st_mode):
                raise RuntimeError("unsafe_system_compiler_path")
        compiler = str(compiler_path)
        summary["compiler_path"] = compiler
        summary["compiler_sha256"] = digest(compiler_path.read_bytes())
        checked([compiler, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-Wno-misleading-indentation", "-static", "-fno-pie", "-no-pie",
                 f'-DPROBE_PROFILE="{profile}"', f'-DPROBE_EXECUTABLE="{install}/probe"',
                 str(HERE / "probe.c"), "-o", str(binary)], 30)
        if (HERE / "probe.c").read_bytes() != source:
            raise RuntimeError("probe_source_changed_during_compile")
        summary["binary_sha256"] = digest(binary.read_bytes())
        summary["authority_ELF"] = static_elf(binary)
        admin("install", "-d", "-o", "root", "-g", "root", "-m", "0755", str(install))
        install_created = True
        admin("install", "-o", "root", "-g", "root", "-m", "0555", str(binary), str(install / "probe"))
        admin("install", "-o", "root", "-g", "root", "-m", "0644", str(profile_file), str(install / "profile"))
        for file, expected in ((install / "probe", summary["binary_sha256"]), (install / "profile", summary["policy_sha256"])):
            identity = file.lstat()
            if not stat.S_ISREG(identity.st_mode) or identity.st_uid != 0 or identity.st_nlink != 1 or identity.st_mode & 0o022 or digest(file.read_bytes()) != expected:
                raise RuntimeError("installed_owned_artifact_invalid")
        profile_load_attempted = True
        admin("apparmor_parser", "-a", str(install / "profile"))
        summary["loader_sentinel"] = loader_tests(compiler,out,install/"probe")
        if not summary["loader_sentinel"]["passed"]:
            raise RuntimeError("untrusted_loader_sentinel_boundary_failed")
        preexec_cleanup_confirmed = False
        summary["preexec_tracer"] = preexec_tracer_tests(compiler, out, install / "probe")
        preexec_cleanup_confirmed = all(summary["preexec_tracer"][case]["cleanup_confirmed"] for case in ("positive", "negative"))
        if not preexec_cleanup_confirmed:
            raise RuntimeError("preexec_tracer_cleanup_unconfirmed")
        process = subprocess.Popen([str(install / "probe"), "--suite"], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True,
                                   env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
        root_pidfd = os.pidfd_open(process.pid)
        threads = [threading.Thread(target=collect, args=(kind, getattr(process, kind)), daemon=True)
                   for kind in ("stdout", "stderr")]
        for thread in threads:
            thread.start()
        deadline = time.monotonic() + 40
        ready_seen = False
        while time.monotonic() < deadline:
            try:
                event = event_queue.get(timeout=.05)
                events.append(event)
                if "collection_error" in event:
                    raise RuntimeError(event["collection_error"])
                if event.get("event") == "parent_probe_ready":
                    if ready_seen or event.get("pid") != process.pid or process.poll() is not None:
                        raise RuntimeError("invalid_parent_probe_identity")
                    ready_seen = True
                    summary["same_uid_parent_tests"] = parent_access_tests(process.pid, event)
                    process.stdin.write(b"GO\n")
                    process.stdin.flush()
                    process.stdin.close()
                    sent_go = True
                if event.get("event") == "result":
                    if final is not None:
                        raise RuntimeError("duplicate_result")
                    final = event
            except queue.Empty:
                pass
            if process.poll() is not None and all(not thread.is_alive() for thread in threads) and event_queue.empty():
                break
        else:
            raise RuntimeError("bounded_probe_deadline")
        process.wait(timeout=1)
        root_closed = bool(select.select([root_pidfd], [], [], 0)[0])
        parent_ok = bool(summary.get("same_uid_parent_tests")) and all(v["denied"] for v in summary["same_uid_parent_tests"].values())
        depths = [e.get("depth") for e in events if e.get("event") == "authority_depth"]
        worker = [e for e in events if e.get("event") == "worker_negatives"]
        scopes = [e for e in events if e.get("event") == "scope_closure"]
        ok = summary["preexec_tracer"]["passed"] and root_closed and process.returncode == 0 and parent_ok and final and final.get("ok") is True and final.get("native_cleanup_confirmed") is True and \
             sorted(depths) == [1, 2, 3] and len(worker) == 1 and worker[0].get("ok") is True and len(scopes) == 3 and \
             all(e.get("init_pidfd_signalled_and_reaped") is True for e in scopes)
        summary["status"] = "PASS_SCOPED_QA_PRIMITIVES" if ok else "FAIL_OR_INCOMPLETE"
        summary["native_result"] = final
        summary["depths"] = depths
        summary["worker_negative_projection"] = worker
        summary["root_pidfd_exit_observed"] = root_closed
        summary["exit_code"] = process.returncode
    except Exception as error:
        summary["status"] = "FAIL_OR_INCOMPLETE"
        summary["error"] = str(error)
    finally:
        if process is not None and process.poll() is None:
            if root_pidfd is not None:
                try:
                    signal.pidfd_send_signal(root_pidfd, signal.SIGKILL)
                except OSError as error:
                    if error.errno != errno.ESRCH:
                        summary["root_stop_error_errno"] = error.errno
            try:
                process.wait(timeout=3)
                root_closed = root_pidfd is not None and bool(select.select([root_pidfd], [], [], 0)[0])
            except subprocess.TimeoutExpired:
                root_closed = False
        if root_pidfd is not None:
            os.close(root_pidfd)
        # No numeric-PID absence inference. Successful fixed native result proves
        # exact namespace-init pidfd signal+waitpid closure. Failure without that
        # proof deliberately retains own profiles and installation for inspection.
        safe_cleanup = preexec_cleanup_confirmed and (process is None or (root_closed and (not sent_go or bool(final and final.get("native_cleanup_confirmed") is True))))
        summary["owned_cleanup_authorized_by_native_proof"] = safe_cleanup
        summary["owned_profiles_removed"] = False
        try:
            if safe_cleanup:
                if profile_load_attempted:
                    # Also covers a failed/partial parser add. Inspect exact own
                    # unique labels; never replace or unload a pre-existing name.
                    loaded = checked(["sudo", "-n", "cat", "/sys/kernel/security/apparmor/profiles"])
                    own = [line for line in loaded["stdout"].splitlines()
                           if line.startswith(profile + " ") or line.startswith(profile + "//")]
                    if own:
                        admin("apparmor_parser", "-R", str(install / "profile"))
                    loaded = checked(["sudo", "-n", "cat", "/sys/kernel/security/apparmor/profiles"])
                    if any(line.startswith(profile + " ") or line.startswith(profile + "//")
                           for line in loaded["stdout"].splitlines()):
                        raise RuntimeError("owned_profiles_still_loaded")
                summary["owned_profiles_removed"] = True
                if install_created:
                    # Fixed files only; no recursive remove, no glob, no shared path.
                    for file in (install / "probe", install / "profile"):
                        if file.exists():
                            identity = file.lstat()
                            if not stat.S_ISREG(identity.st_mode) or identity.st_uid != 0 or identity.st_nlink != 1:
                                raise RuntimeError("owned_cleanup_file_identity_invalid")
                            admin("rm", "--", str(file))
                    admin("rmdir", "--", str(install))
            else:
                summary["retained_owned_installation"] = str(install)
                summary["cleanup_unconfirmed"] = True
                summary["status"] = "FAIL_OR_INCOMPLETE"
        except Exception as error:
            summary["cleanup_error"] = str(error)
            summary["retained_owned_installation"] = str(install)
            summary["status"] = "FAIL_OR_INCOMPLETE"
        after = policy_snapshot()
        summary["global_policy_after"] = after
        summary["global_restrictions_unchanged"] = before == after
        if before != after:
            summary["status"] = "FAIL_OR_INCOMPLETE"
        for kind, body in captured.items():
            (out / (kind + ".private.log")).write_bytes(body)
            summary[kind] = {"bytes": len(body), "sha256": digest(body)}
        (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
        os.chmod(out / "summary.json", 0o600)
        for kind in captured:
            os.chmod(out / (kind + ".private.log"), 0o600)
    print(json.dumps({"status": summary["status"], "qualification": False,
                      "summary": str(out / "summary.json"),
                      "owned_profiles_removed": summary["owned_profiles_removed"]}))
    return 0 if summary["status"] == "PASS_SCOPED_QA_PRIMITIVES" else 1

if __name__ == "__main__":
    raise SystemExit(main())
