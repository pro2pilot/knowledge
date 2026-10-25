#!/usr/bin/env python3
"""Compile the exact shipping native sources and bind every input/output.

This proves compilation and inert --describe only, never runtime containment.
The physical lifecycle controller must run separately before qualification.
"""
import argparse, hashlib, json, os, platform, subprocess, sys, time
from pathlib import Path

def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', required=True)
    parser.add_argument('--evidence', required=True)
    args = parser.parse_args()
    source = Path(args.source).resolve()
    evidence = Path(args.evidence).resolve()
    evidence.mkdir(parents=True, exist_ok=False)
    names = {'broker': 'verification-darwin-broker.m', 'stub': 'verification-darwin-stub.c',
        'history_header': 'verification-darwin-uid-history.h', 'history_source': 'verification-darwin-uid-history.m',
        'transport_header': 'verification-darwin-transport.h'}
    paths = {key: source / 'tools' / 'lib' / name for key, name in names.items()}
    hashes = {key: sha(path) for key, path in paths.items()}
    result = {'schema': 'knowledge-reliability-native-compile.v1', 'platform': platform.platform(),
        'machine': platform.machine(), 'source': str(source), 'input_sha256': hashes,
        'runtime_qualification': 'NOT_RUN', 'capability_qualified': False, 'attempts': []}
    def record(name, argv, timeout=180):
        started = time.monotonic()
        child = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        timed_out = False
        try:
            out, err = child.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            child.kill()
            out, err = child.communicate()
        (evidence / (name + '.stdout')).write_bytes(out)
        (evidence / (name + '.stderr')).write_bytes(err)
        result['attempts'].append({'name': name, 'argv': argv, 'exit_code': child.returncode,
            'timed_out': timed_out, 'child_reaped': True, 'elapsed_ms': (time.monotonic()-started)*1000,
            'stdout_sha256': hashlib.sha256(out).hexdigest(), 'stderr_sha256': hashlib.sha256(err).hexdigest()})
        if child.returncode != 0 or timed_out:
            raise RuntimeError(name + '_failed')
        return out
    try:
        if sys.platform != 'darwin':
            result['status'] = 'NOT_RUN_DARWIN_REQUIRED'
            return 2
        record('compiler-version', ['/usr/bin/clang', '--version'])
        binary = evidence / 'broker-shipping'
        stub = evidence / 'stub-shipping'
        define = lambda key, value: '-D' + key + '=\"' + value + '\"'
        defs = [define('KNOWLEDGE_BROKER_SOURCE_SHA', hashes['broker']),
            define('KNOWLEDGE_DARWIN_STUB_SOURCE_SHA', hashes['stub']),
            define('KNOWLEDGE_DARWIN_UID_HISTORY_HEADER_SHA', hashes['history_header']),
            define('KNOWLEDGE_DARWIN_UID_HISTORY_SOURCE_SHA', hashes['history_source']),
            define('KNOWLEDGE_DARWIN_TRANSPORT_HEADER_SHA', hashes['transport_header'])]
        record('compile-shipping-broker', ['/usr/bin/clang', '-fobjc-arc', '-Wall', '-Wextra',
            '-Wno-deprecated-declarations', '-framework', 'Foundation', *defs, '-I', str(paths['broker'].parent),
            str(paths['broker']), str(paths['history_source']), '-o', str(binary)])
        record('compile-shipping-stub', ['/usr/bin/clang', '-std=c11', '-D_DARWIN_C_SOURCE', '-O2',
            '-Wall', '-Wextra', '-Wno-deprecated-declarations', define('KNOWLEDGE_BROKER_BINARY_SHA', sha(binary)),
            define('KNOWLEDGE_BROKER_SOURCE_SHA', hashes['broker']), define('KNOWLEDGE_DARWIN_STUB_SOURCE_SHA', hashes['stub']),
            str(paths['stub']), '-o', str(stub)])
        pair = json.loads(record('shipping-stub-describe', [str(stub), '--describe'], 15))
        expected = {'schema': 'knowledge-darwin-stub.v1', 'broker_binary_sha256': sha(binary),
            'broker_source_sha256': hashes['broker'], 'stub_source_sha256': hashes['stub'], 'capability_qualified': False}
        if pair != expected:
            raise RuntimeError('shipping_stub_pin_mismatch')
        result['output_sha256'] = {'broker': sha(binary), 'stub': sha(stub)}
        result['status'] = 'PASS_COMPILE_AND_INERT_ONLY'
        return 0
    except Exception as error:
        result['status'] = 'FAIL'
        result['error'] = str(error)
        return 1
    finally:
        result['source_unchanged'] = all(sha(paths[key]) == value for key, value in hashes.items())
        (evidence / 'SUMMARY.json').write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps(result, indent=2))

if __name__ == '__main__':
    sys.exit(main())
