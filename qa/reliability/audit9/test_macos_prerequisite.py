import unittest

from macos_prerequisite import admission, sip_status, translation_status


class PrerequisiteAdmissionTests(unittest.TestCase):
    def test_failed_translation_cannot_reuse_success_looking_stdout(self):
        base = {'exit_code': 0, 'stdout': b'0\n', 'stderr': b''}
        self.assertEqual(translation_status(base, 'arm64', 'arm64'), '0')
        for change in ({'exit_code': 1}, {'timed_out': True}, {'error': 'OSError'}, {'stderr': b'warning'}):
            with self.subTest(change=change):
                self.assertEqual(translation_status({**base, **change}, 'arm64', 'arm64'), 'unknown')
        intel = {'exit_code': 1, 'stdout': b'', 'stderr': b"sysctl: unknown oid 'sysctl.proc_translated'\n"}
        self.assertEqual(translation_status(intel, 'x64', 'x86_64'), 'not_available_on_intel')
        self.assertEqual(translation_status(intel, 'arm64', 'arm64'), 'unknown')
        self.assertEqual(translation_status({**intel, 'stdout': b'0'}, 'x64', 'x86_64'), 'unknown')

    def test_exact_enabled_only(self):
        base = {'exit_code': 0, 'stdout': b'System Integrity Protection status: enabled.\n', 'stderr': b''}
        self.assertEqual(sip_status(base), 'enabled')
        for change in (
            {'exit_code': 1}, {'timed_out': True}, {'error': 'OSError'},
            {'stderr': b'warning'}, {'stdout': b'System Integrity Protection status: enabled (Custom Configuration).'},
            {'stdout': base['stdout'] + b'disabled\n'},
        ):
            with self.subTest(change=change):
                self.assertEqual(sip_status({**base, **change}), 'unknown')
        self.assertEqual(sip_status({**base, 'stdout': b'System Integrity Protection status: disabled.'}), 'disabled')

    def test_enabled_sip_does_not_override_environment(self):
        base = dict(system='Darwin', machine='arm64', architecture='arm64', uid=501,
                    github_actions='true', sip='enabled', translated='0')
        self.assertEqual(admission(**base), [])
        for change, expected in (
            ({'uid': 0}, 'ordinary_user_required'), ({'uid': None}, 'ordinary_user_required'),
            ({'machine': 'x86_64'}, 'architecture_mismatch'),
            ({'translated': '1'}, 'native_execution_unconfirmed'),
            ({'translated': ''}, 'native_execution_unconfirmed'),
            ({'github_actions': 'false'}, 'github_actions_runner_required'),
            ({'sip': 'disabled'}, 'stock_sip_not_enabled'),
            ({'sip': 'unknown'}, 'stock_sip_not_enabled'),
            ({'system': 'Linux'}, 'darwin_required'),
        ):
            with self.subTest(change=change):
                self.assertIn(expected, admission(**{**base, **change}))


if __name__ == '__main__':
    unittest.main()
