#!/usr/bin/env python3
"""Reproduce only the NEW private Main derivative; never patch pinned inputs.
No compiler/model/native subject is invoked. Default is read-only verification.
"""
from pathlib import Path
import argparse, hashlib, json
PINNED_INPUTS = {'BASE_MAIN/verification-linux-service-main.c': {'bytes': 11359, 'sha256': '579eebd839c026d19daee3c7619a7ff260dab9212a79910f2d3a51fdbb59e157'}, 'BASE_MAIN/verification-linux-service-configuration.h': {'bytes': 2230, 'sha256': 'b6a7ffc3c804e62b3dd3268701313713b65a9e16fce1718ff440c6fc754287ec'}, 'BASE_MAIN/verification-linux-service-daemon.h': {'bytes': 2056, 'sha256': '97987849bd9658b9bc4afec6ca913fb47ccf40168a370ae1a65b3ee603f923ff'}, 'BASE_MAIN/verification-linux-service-runtime-front.h': {'bytes': 2092, 'sha256': 'c4c7ccf5dd02765e939125a275edefb0928024b0d2e048b28c011a293dac19ca'}, 'main-h-birth-core.inc': {'bytes': 24700, 'sha256': '6f7855f99258ac702ba6e12e2759a0609e646b190ae0f7474d01faf94478dc7f'}}
DERIVATIVE = "private-main-intake.c"
PROVENANCE = "DERIVATIVE_PINS.json"


def pin(data):
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def build(root):
    for name, expected in PINNED_INPUTS.items():
        actual = pin((root / name).read_bytes())
        if actual != expected:
            raise SystemExit("pinned input mismatch: " + name)
    before = (root / "BASE_MAIN/verification-linux-service-main.c").read_bytes()
    source = before.decode("utf-8")
    changes = []

    def replace(label, old, new):
        nonlocal source
        if source.count(old) != 1:
            raise SystemExit("anchor occurrence mismatch: " + label)
        changes.append({"label": label, "before_anchor": old,
                        "before_anchor_sha256": hashlib.sha256(old.encode()).hexdigest(),
                        "after_anchor": new,
                        "after_anchor_sha256": hashlib.sha256(new.encode()).hexdigest()})
        source = source.replace(old, new, 1)

    replace("relative_configuration_include",
            '#include "verification-linux-service-configuration.h"',
            '#include "../BASE_MAIN/verification-linux-service-configuration.h"')
    replace("private_include_after_unistd", '#include <unistd.h>\n',
            '#include <unistd.h>\n#include "../main-h-birth-core.inc"\n#include "main-intake.inc"\n')
    replace("signal_only_latch", 'static void stop_signal(int number){(void)number;stopping=1;}',
            'static void stop_signal(int number){(void)number;stopping=1;mi_stop_original();}')
    replace("no_executable_main_entry", 'int main(int argc,char **argv){',
            '/* SOURCE ONLY. This file deliberately has no executable main entry. */\n'
            'static __attribute__((used)) int mi_private_main_source_only(int argc,char **argv){')
    replace("no_administrative_initialize_entry",
            '    int initialize=argc==2&&!strcmp(argv[1],"--initialize");\n'
            '    if(argc!=1&&!initialize)_exit(1);\n',
            '    if(argc!=1)_exit(1);\n    (void)argv;\n')
    replace("no_initialize_socket_branch",
            '    if(initialize){\n'
            '        struct stat existing;\n'
            '        if(!fstatat(runtime,KV_LINUX_SERVICE_RUNTIME_SOCKET_NAME,&existing,AT_SYMLINK_NOFOLLOW)||errno!=ENOENT)goto done;\n'
            '    }\n', '')
    replace("existing_singleton_only", '    lock=singleton(state,initialize);if(lock<0)goto done;\n',
            '    lock=singleton(state,0);if(lock<0)goto done;\n')
    replace("no_uid_initialization_branch",
            '    if(initialize){\n'
            '        result=kv_linux_uid_initialize(&configuration.history,NULL)?1:0;goto done;\n'
            '    }\n', '')
    replace("remove_old_front_owner", '    kv_linux_runtime_front *front=NULL;\n',
            '    /* A2 does not open the old runtime front or create any child. */\n')
    replace("terminal_only_intake_from_actual_listener",
"    front=kv_linux_runtime_front_open(original,&configuration.history,&configuration.policy,&configuration.pins);\n    if(!front)goto done;\n    /* Only Main's original and front's duplicate exist. Retire the original\n     * BEFORE the first poll can clone. Raw child in reviewed front7ec closes\n     * its inherited front duplicate before all parent checks/FD overwrites. */\n    {int closed=close(original);original=-1;if(closed)goto done;}\n    result=0;\n    while(!stopping){\n        if(kv_linux_runtime_front_poll(front,100)<0){result=1;break;}\n    }\n",
"    /* Fixed source origin: these are Main's local verified administrative\n     * configuration and its sole actual listener. No packet chooses either. */\n    struct mi_admin intake_admin={configuration.policy.authorized_uid,\n        configuration.policy.authorized_gid,configuration.policy.setup_ns,\n        configuration.policy.work_ns,configuration.policy.cleanup_ns};\n    if(mi_main_capture(original,&intake_admin))goto done;\n    /* One bounded intake attempt. This is not an H/recovery event loop.\n     * Every outcome is terminal unavailable; no public reply/authority. */\n    while(!stopping){\n        int step=mi_state.phase==MI_MAIN_CAPTURED?mi_accept_original():\n            mi_state.phase==MI_PEER_HELD?mi_receive_original():-1;\n        if(step<0)break;\n        if(mi_state.phase==MI_B1_READY){(void)mi_core_offer_original();break;}\n        if(mi_guard())break;\n        struct pollfd watches[2]={{mi_state.phase==MI_MAIN_CAPTURED?original:\n            mi_state.fd[MI_CONNECTION],POLLIN|POLLHUP,0},\n            {mi_state.fd[MI_PEER_PIDFD],POLLIN,0}};\n        uint64_t now=mi_now();if(!now||now>=mi_state.admission_end)break;\n        uint64_t ms=(mi_state.admission_end-now)/UINT64_C(1000000);\n        if(ms>10)ms=10;\n        if(poll(watches,mi_state.phase==MI_MAIN_CAPTURED?1:2,(int)ms)<0)break;\n        if(watches[0].revents&(POLLERR|POLLNVAL))break;\n        if(watches[1].revents)break;\n    }\n    if(stopping)mi_stop_original();\n    result=1; /* unavailable is never a successful birth/release receipt */\n")
    replace("remove_old_front_cleanup",
'    if(front){\n        (void)kv_linux_runtime_front_stop(front);\n        while(kv_linux_runtime_front_close(&front)){\n            if(errno!=EBUSY)result=1;\n            (void)kv_linux_runtime_front_poll(front,100);\n        }\n    }\n',
            '    (void)mi_cancel_original();\n    (void)mi_finish_original();\n')
    after = source.encode("utf-8")
    receipt = {"schema":"a2-pinned-main-derivative.v1",
               "status":"SOURCE_ONLY_NOT_EXECUTED", "input_pins":PINNED_INPUTS,
               "before":pin(before),"after":pin(after),"anchors":changes,
               "entry":"static used mi_private_main_source_only; no main or exported intake symbol",
               "full_translation_unit":"BLOCKED_MISSING_PINNED_TRANSITIVE_HEADERS",
               "no_base_overwrite":True}
    return after, (json.dumps(receipt, ensure_ascii=False, indent=2)+"\n").encode()


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--write",action="store_true",help="create absent derivative/provenance only")
    parser.add_argument("--check",action="store_true",help="read-only exact reproduction check (default)")
    args=parser.parse_args()
    if args.write and args.check:
        parser.error("choose one mode")
    directory=Path(__file__).resolve().parent
    after, receipt=build(directory.parent)
    paths=[(directory/DERIVATIVE,after),(directory/PROVENANCE,receipt)]
    if args.write:
        if any(p.exists() for p,_ in paths):
            raise SystemExit("refusing to overwrite existing derivative/provenance")
        for p,data in paths:
            p.write_bytes(data)
    for p,data in paths:
        if p.read_bytes()!=data:
            raise SystemExit("derivative mismatch: "+p.name)
    print(json.dumps({"status":"PASS_EXACT_DERIVATIVE_REPRODUCTION",
                      "files":{p.name:pin(data) for p,data in paths},
                      "native_execution":"NOT_RUN"},ensure_ascii=False))

if __name__=="__main__":
    main()
