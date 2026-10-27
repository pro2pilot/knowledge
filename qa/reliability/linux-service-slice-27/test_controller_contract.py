import importlib.util
from pathlib import Path
import unittest

MODULE_PATH = Path(__file__).with_name("controller.py")
spec = importlib.util.spec_from_file_location("linux_service_slice_controller", MODULE_PATH)
controller = importlib.util.module_from_spec(spec)
spec.loader.exec_module(controller)


class ControllerPureContractTests(unittest.TestCase):
    def valid_tap(self):
        name = controller.EXPECTED_TEST_NAME
        return ("TAP version 13\n"
                f"# Subtest: {name}\n"
                f"ok 1 - {name}\n"
                "  ---\n"
                "  duration_ms: 12.5\n"
                "  type: 'test'\n"
                "  ...\n"
                "1..1\n"
                "# tests 1\n"
                "# suites 0\n"
                "# pass 1\n"
                "# fail 0\n"
                "# cancelled 0\n"
                "# skipped 0\n"
                "# todo 0\n"
                "# duration_ms 20.5\n").encode()

    def valid_native(self):
        return {
            "status": "WORK_CLOSED", "observer_ack_required": True,
            "cleanup_confirmed": True, "importer_namespace_drained": True,
            "importer_detached_writer_ready": True, "source_readonly": True,
            "authority_readback": True, "cgroup_empty": True, "output_eof": True,
            "phase": 4, "stop_reason": 4, "init_wait_status": 0,
            "keeper_wait_status": 0, "worker_wait_status": 0,
            "authority_wait_status": 0,
        }

    def test_node_tap_diagnostic_and_inventory_are_accepted(self):
        got = controller.tap_inventory(self.valid_tap())
        self.assertEqual(got["tests"], 1)
        self.assertEqual(got["pass"], 1)
        self.assertEqual(got["fail"], 0)
        self.assertEqual(got["skipped"], 0)

    def test_tap_rejects_skip_extra_test_and_unknown_diagnostic(self):
        good = self.valid_tap().decode()
        self.assertIsNone(controller.tap_inventory(good.replace("# skipped 0", "# skipped 1").encode()))
        self.assertIsNone(controller.tap_inventory(good.replace("1..1", "1..2").encode()))
        self.assertIsNone(controller.tap_inventory(good.replace("  type: 'test'", "  type: 'test'\n  extra: true").encode()))

    def test_acceptance_requires_observer_ack_and_reaped_systemd_child(self):
        value = self.valid_native()
        tap = controller.tap_inventory(self.valid_tap())
        self.assertTrue(controller.component_acceptance(0, value, True, True, tap))
        self.assertFalse(controller.component_acceptance(0, value, False, True, tap))
        self.assertFalse(controller.component_acceptance(0, value, True, False, tap))
        self.assertFalse(controller.component_acceptance(1, value, True, True, tap))

    def test_acceptance_requires_live_detached_writer_proof(self):
        value = self.valid_native()
        value["importer_detached_writer_ready"] = False
        tap = controller.tap_inventory(self.valid_tap())
        self.assertFalse(controller.component_acceptance(0, value, True, True, tap))



if __name__ == "__main__":
    unittest.main()
