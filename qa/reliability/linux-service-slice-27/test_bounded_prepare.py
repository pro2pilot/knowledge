"""Real unprivileged fixed-tool capture regressions; no root/native service."""
import importlib.util
import os
from pathlib import Path
import sys
import time
import unittest

spec = importlib.util.spec_from_file_location("bounded_prepare_controller", Path(__file__).with_name("controller.py"))
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)


@unittest.skipUnless(os.name == "posix" and hasattr(os, "WNOWAIT"), "Requires POSIX unreaped process-session custody")
class BoundedPrepare(unittest.TestCase):
    def run_code(self, code, timeout=2, maximum=4096):
        return c.bounded_process([sys.executable, "-c", code], timeout, maximum, Path.cwd(), {"PATH": "/usr/bin:/bin"})

    def test_exact_stdout_stderr_and_exit_are_preserved(self):
        rc, out, err, elapsed = self.run_code("import sys; print('out'); print('err',file=sys.stderr); sys.exit(7)")
        self.assertEqual((rc, out, err), (7, b"out\n", b"err\n"))
        self.assertLess(elapsed, 2)

    def test_output_flood_is_stopped_before_unbounded_collection(self):
        before = time.monotonic()
        with self.assertRaises(c.SliceFailure) as error:
            self.run_code("import os;\nwhile True: os.write(1,b'x'*65536)", maximum=1024)
        self.assertEqual(error.exception.code, "prepare_command_output_limit")
        self.assertLess(time.monotonic() - before, 4)

    def test_quiet_timeout_does_not_wait_for_pipe_communication(self):
        before = time.monotonic()
        with self.assertRaises(c.SliceFailure) as error:
            self.run_code("import time; time.sleep(10)", timeout=0.1)
        self.assertEqual(error.exception.code, "prepare_command_timeout")
        self.assertLess(time.monotonic() - before, 4)

    def test_exited_leader_with_live_inherited_pipe_child_is_bounded(self):
        before = time.monotonic()
        rc, out, err, _ = self.run_code("import os,time; child=os.fork();\nif child==0: time.sleep(10); os._exit(0)\nos.write(1,b'leader exit\\n'); os._exit(0)")
        self.assertEqual((rc, out, err), (0, b"leader exit\n", b""))
        self.assertLess(time.monotonic() - before, 2)


if __name__ == "__main__": unittest.main()
