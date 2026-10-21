"""Ordinary-user positive transport and negative production admission probe."""
import hashlib
import json
import os
import secrets
import subprocess
import sys

binary, socket = sys.argv[1:]
assert os.getuid() != 0 and sys.platform == 'darwin'
def rpc(body):
    r = subprocess.run([binary, '--request', '--socket=' + socket], input=json.dumps(body).encode(),
                       capture_output=True, timeout=20)
    assert len(r.stdout) <= 65536 and r.stdout, 'native guard transport unavailable'
    return r.returncode, json.loads(r.stdout)

code, probe = rpc({'op': 'probe'})
assert code == 0 and probe['ok'] is True and probe['capability_qualified'] is False
assert probe['qualification_mode'] is False and probe['registry_healthy'] is True
code, denial = rpc({'op': 'prepare', 'mode': 'isolated_copy', 'attempt_nonce': secrets.token_hex(32),
                    'work_budget_ms': 120000, 'cleanup_budget_ms': 10000})
assert code == 1 and denial['ok'] is False and denial['error'] == 'CAPABILITY_UNQUALIFIED'
assert 'attempt_id' not in denial and 'token' not in denial
print(json.dumps({'scope': 'production admission refusal before reservation, not backend qualification',
                  'guard_passed': True, 'probe': probe, 'denial': denial}))
