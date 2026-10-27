"""Exact C gate/pipe tests; no root namespaces or production claim."""
from pathlib import Path
import json
import os
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent


class NativeFaultContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="knowledge-native-fault-")
        cls.directory = Path(cls.temp.name)
        cls.harness = cls.directory / "fault-contract.c"
        cls.harness.write_text(r'''#define _GNU_SOURCE
#define main slice_program_main
#include SOURCE
#undef main
#define CHECK(x) do { if(!(x)){fprintf(stderr,"failed line %d: %s errno=%d\n",__LINE__,#x,errno);return 1;} }while(0)
int main(int argc,char **argv){
  CHECK(argc==2);signal(SIGPIPE,SIG_IGN);
  if(!strncmp(argv[1],"observation-",12)){
    int pair[2],one=1,held=pidfd(getpid());CHECK(held>=0);
    CHECK(socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_NONBLOCK|SOCK_CLOEXEC,0,pair)==0);
    int credentials=strcmp(argv[1],"observation-no-credentials")!=0;
    if(credentials&&setsockopt(pair[0],SOL_SOCKET,SO_PASSCRED,&one,sizeof(one))){
      if(errno==EPERM){fprintf(stderr,"Host sandbox denies SO_PASSCRED; physical CI must exercise this path\n");return 77;}
      CHECK(0);
    }
    observation_channel=pair[1];
    if(!strcmp(argv[1],"observation-short"))CHECK(send(pair[1],"X",1,MSG_NOSIGNAL)==1);
    else if(!strcmp(argv[1],"observation-no-fd"))CHECK(observe_send(OBS_INIT,NULL,-1,getpid(),0,0,NULL,0)==0);
    else if(!strcmp(argv[1],"observation-extra-fd"))CHECK(observe_send(OBS_DRAIN,NULL,held,getpid(),0,0,NULL,0)==0);
    else CHECK(observe_send(OBS_INIT,NULL,held,getpid(),0,0,NULL,0)==0);
    struct observation event;memset(&event,0xa5,sizeof(event));int received=-1,sender=-1;
    int ok=observe_receive(pair[0],&event,&received,&sender);
    if(!strcmp(argv[1],"observation-authenticated")&&getuid()==0&&getgid()==0){
      CHECK(ok==1&&sender==getpid()&&received>=0&&event.pid==getpid()&&event.bytes==0);
      CHECK(held_pid(received)==getpid()&&!dead(received));close(received);
    }else CHECK(ok==-1&&received==-1);
    close(held);close(pair[0]);close(pair[1]);return 0;
  }
  if(!strcmp(argv[1],"drain-boundary")){
    struct keeper_result first={.kind=3,.init=701,.reason=3,.drain_entered=1,.stop_dispatched=1,
      .work_ms=30001,.cleanup_started_ms=40000,.cleanup_deadline_ms=50000,
      .work={.phase=3,.fault_reached=1,.worker_status=0,.importer_wait_status=0}};
    struct keeper_result other=first;CHECK(same_drain(&first,&other));
    other.stop_dispatched=0;CHECK(!same_drain(&first,&other));other=first;
    other.drain_entered=0;CHECK(!same_drain(&first,&other));other=first;
    other.init++;CHECK(!same_drain(&first,&other));other=first;
    other.cleanup_deadline_ms++;CHECK(!same_drain(&first,&other));other=first;
    other.cleanup_started_ms++;CHECK(!same_drain(&first,&other));other=first;
    other.work_ms++;CHECK(!same_drain(&first,&other));other=first;
    other.work.phase=4;CHECK(!same_drain(&first,&other));other=first;
    other.work.fault_reached=0;CHECK(!same_drain(&first,&other));other=first;
    other.work.worker_status=9;CHECK(!same_drain(&first,&other));other=first;
    other.work.importer_wait_status=9;CHECK(!same_drain(&first,&other));
    return 0;
  }
  if(!strcmp(argv[1],"held-pipe")){
    int report[2];CHECK(pipe2(report,O_CLOEXEC)==0);pid_t child=fork();CHECK(child>=0);
    if(!child){close(report[0]);struct work_result marker={.phase=3,.worker_status=0,.authority_status=-1};hold_fault_pipe(report[1],&marker);_exit(190);}
    close(report[1]);int exact=pidfd(child);CHECK(exact>=0);struct work_result observed;CHECK(read(report[0],&observed,sizeof(observed))==sizeof(observed));
    CHECK(observed.fault_reached==1&&observed.phase==3&&observed.worker_status==0&&observed.authority_status==-1);
    CHECK(!dead(exact));int status=-1;CHECK(waitpid(child,&status,WNOHANG)==0);CHECK(kill_exact(exact)==0);CHECK(exact_reap(child,&status)==0);
    CHECK(WIFSIGNALED(status)&&WTERMSIG(status)==SIGKILL&&dead(exact));CHECK(read(report[0],&observed,sizeof(observed))==0);
    close(exact);close(report[0]);return 0;
  }
  int owner=pidfd(getpid()),gate[2];CHECK(owner>=0&&pipe2(gate,O_CLOEXEC|O_NONBLOCK)==0);
  long long start=now_ms(),end=start+5000;int expected=0,permitted=1;
  if(!strcmp(argv[1],"cancelled")){cancelled=1;expected=1;}
  else if(!strcmp(argv[1],"late-setup")){end=start;expected=3;}
  else if(!strcmp(argv[1],"late-work")){start-=WORK_MS;expected=3;}
  else if(!strcmp(argv[1],"no-permit")){permitted=0;expected=5;}
  else if(!strcmp(argv[1],"owner-exited")){
    close(owner);pid_t child=fork();CHECK(child>=0);if(!child)_exit(0);owner=pidfd(child);CHECK(owner>=0);int status;CHECK(exact_reap(child,&status)==0);expected=2;
  }else CHECK(!strcmp(argv[1],"normal"));
  CHECK(grant_setup_permit(gate[1],owner,permitted,start,end)==expected);char byte;ssize_t n=read(gate[0],&byte,1);
  if(expected)CHECK(n==-1&&(errno==EAGAIN||errno==EWOULDBLOCK));else CHECK(n==1&&byte=='G');
  close(owner);close(gate[0]);close(gate[1]);return 0;
}
'''.replace("#include SOURCE", "#include " + json.dumps(str(HERE / "native-slice.c"))), encoding="utf-8")
        cls.base = ["/usr/bin/cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-Wno-misleading-indentation",
                    '-DSLICE_ROOT="/run/never-executed"', '-DSLICE_CGROUP="/sys/fs/cgroup/never-executed"',
                    "-DSLICE_A_UID=1000010300", "-DSLICE_W_UID=1000010301"]
        cls.binary = cls.directory / "fault-contract"
        built = subprocess.run(cls.base + [str(cls.harness), "-o", str(cls.binary)], capture_output=True, timeout=30)
        if built.returncode:
            raise RuntimeError(built.stderr.decode())

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def run_case(self, name):
        observed = subprocess.run([str(self.binary), name], capture_output=True, timeout=5)
        if observed.returncode == 77:
            self.skipTest(observed.stderr.decode().strip())
        self.assertEqual(observed.returncode, 0, observed.stderr.decode())

    def test_normal_permit(self): self.run_case("normal")
    def test_cancel_blocks_permit(self): self.run_case("cancelled")
    def test_setup_expiry_blocks_late_permit(self): self.run_case("late-setup")
    def test_work_expiry_blocks_late_permit(self): self.run_case("late-work")
    def test_missing_permit(self): self.run_case("no-permit")
    def test_dead_owner_blocks_permit(self): self.run_case("owner-exited")
    def test_real_held_pipe_actor_has_marker_and_exact_exit(self): self.run_case("held-pipe")
    def test_observer_requires_kernel_root_credentials_and_exact_pidfd(self): self.run_case("observation-authenticated")
    def test_observer_rejects_short_packet(self): self.run_case("observation-short")
    def test_observer_rejects_missing_pidfd(self): self.run_case("observation-no-fd")
    def test_observer_rejects_extra_pidfd(self): self.run_case("observation-extra-fd")
    def test_observer_rejects_missing_credentials(self): self.run_case("observation-no-credentials")
    def test_drain_boundary_requires_exact_matching_stop_transaction(self): self.run_case("drain-boundary")

    def test_closed_build_time_enum(self):
        for mode, expected in [(0, True), (1, True), (2, True), (3, True), (4, True), (-1, False), (5, False)]:
            with self.subTest(mode=mode):
                target = self.directory / f"mode-{mode}"
                built = subprocess.run(self.base + [f"-DSLICE_FAULT_MODE={mode}", str(HERE / "native-slice.c"), "-o", str(target)],
                                       capture_output=True, timeout=30)
                self.assertEqual(built.returncode == 0, expected, built.stderr.decode())


if __name__ == "__main__":
    unittest.main()
