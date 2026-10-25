#!/usr/bin/env python3
import copy, hashlib, importlib.util, json, subprocess, sys, tempfile, unittest
from pathlib import Path

target = Path(__file__).with_name('darwin-production-summary.py')
spec = importlib.util.spec_from_file_location('production_summary', target)
summary = importlib.util.module_from_spec(spec);spec.loader.exec_module(summary)


class ProductionEvidence(unittest.TestCase):
    def good(self):
        return {'status': 'PASS_PHYSICAL_PRODUCTION_NORMAL', 'architecture': 'arm64', 'source_unchanged': True,
            'cleanup_confirmed': True, 'cases': [{'name': 'normal', 'status': 'PASS_PHYSICAL_PRODUCTION',
                'KVE_KVF_ACK_verified': True, 'terminal': {'success': True, 'stage': 'complete'}}],
            'binary_history': [{'kind': 'shipping', 'qa_io_enabled': False, **{key: 'a'*64 for key in
                ('broker_sha256', 'stub_sha256', 'source_sha256', 'stub_source_sha256')}}],
            'native_addon': {'source_sha256': 'a'*64, 'binary_sha256': 'b'*64, 'platform': 'darwin', 'architecture': 'arm64'}}

    def test_cli_rejects_incomplete_evidence_even_after_zero_controller_exit(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder);private = root/'private';private.mkdir();source = root/'source';source.mkdir()
            (source/'seed.js').write_bytes(b'fixture');(source/'seed.js').chmod(0o600)
            inputs = {'files': [{'path': 'source/seed.js', 'bytes': 7, 'sha256': hashlib.sha256(b'fixture').hexdigest(), 'executable': False}],
                'controller_sha256': 'c'*64, 'lifecycle_sha256': 'd'*64, 'reference_runner_sha256': 'e'*64}
            (private/'INPUTS.json').write_text(json.dumps(inputs))
            values = [('valid', self.good(), 0)]
            for name, mutate in (
                ('missing-case', lambda v: v.update(cases=[])),
                ('duplicate-case', lambda v: v['cases'].append(v['cases'][0])),
                ('no-cleanup', lambda v: v.update(cleanup_confirmed=False)),
                ('source-drift', lambda v: v.update(source_unchanged=False)),
                ('wrong-arch', lambda v: v.update(architecture='x86_64')),
                ('qa-build', lambda v: v['binary_history'][0].update(qa_io_enabled=True)),
                ('missing-addon', lambda v: v.update(native_addon={})),
                ('missing-ack', lambda v: v['cases'][0].update(KVE_KVF_ACK_verified=False)),
                ('unaccepted', lambda v: v['cases'][0]['terminal'].update(success=False))):
                value = self.good();mutate(value);values.append((name, value, 1))
            for name, value, expected in values:
                with self.subTest(name=name):
                    (private/'SUMMARY.json').write_text(json.dumps(value));public = root/name
                    result = subprocess.run([sys.executable, str(target), '--private', str(private), '--public', str(public),
                        '--source', str(source), '--controller-status', '0', '--expected-arch', 'arm64'], capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode, expected, result.stdout+result.stderr)
                    self.assertEqual(sorted(p.name for p in public.iterdir()), ['stages.json', 'summary.json'])
            (private/'SUMMARY.json').write_text(json.dumps(self.good()))
            for bad in ({}, {**inputs, 'files': inputs['files']*2}, {**inputs, 'files': []}):
                (private/'INPUTS.json').write_text(json.dumps(bad))
                actual, _ = summary.build(private, source, 0, 'arm64');self.assertEqual(actual['status'], 'FAIL_OR_INCOMPLETE')

    def test_raw_native_and_payload_fields_cannot_escape(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder);private = root/'private';private.mkdir();source = root/'source';source.mkdir()
            secret = 'NEVER_PUBLIC_native_token_or_payload_value'
            value = self.good();value.update(token=secret, failure=secret, hostname=secret, raw_traceback=secret)
            value['installation_parent'] = {'created': True, 'exists_before': False, 'errno': 2, 'path': secret,
                'identity': {'dev': secret, 'ino': secret}, 'message': secret}
            value['cases'][0]['terminal'].update(token=secret, result=secret, acceptances=secret,
                error_code=secret, error={'message': secret, 'containment': {'reason': secret}})
            value['records'] = [{'name': '001-'+secret, 'exit_code': 1, 'stdout': secret}]
            value['diagnostics'] = [{'type': 'ValueError', 'stage': 'execute', 'args': secret,
                'frames': [{'file': 'darwin-production-lifecycle.py', 'line': 200, 'locals': secret}, {'file': secret, 'line': 1}]}]
            (private/'SUMMARY.json').write_text(json.dumps(value))
            public, stages = summary.build(private, source, 1, 'arm64')
            self.assertNotIn(secret, json.dumps([public, stages]));self.assertFalse(public['release_gate_qualified'])
            self.assertIsNone(public['cases'][0]['error_code']);self.assertIsNone(public['cases'][0]['containment_reason'])
            self.assertEqual(stages['stages'][0]['stage'], '001-unclassified-stage')
            self.assertTrue(public['installation_parent']['created']);self.assertFalse(public['installation_parent']['exists_before'])
            self.assertEqual(public['installation_parent']['errno'], 2)


if __name__ == '__main__': unittest.main()
