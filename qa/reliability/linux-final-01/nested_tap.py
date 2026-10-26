"""Strict Node TAP inventory: nested assertions and top-level tests stay distinct."""
import re

FIELDS = {'tests', 'suites', 'pass', 'fail', 'cancelled', 'skipped', 'todo'}


def parse_nested_tap(output):
    if not isinstance(output, str) or len(output.encode('utf-8')) > 8 * 1024 * 1024:
        return {'valid_structure': False, 'errors': ['output_type_or_limit'], 'cases': [], 'counts': {}}
    root = {'name': None, 'path': [], 'children': [], 'plan': None}
    stack, cases, totals, errors = [], [], {}, []
    version = 0
    def reject(code, number):
        errors.append({'line': number, 'code': code})
    for number, line in enumerate(output.splitlines(), 1):
        if re.match(r'^\s*Bail out!', line, re.I): reject('bailout', number); continue
        if line == 'TAP version 13':
            version += 1
            if version != 1 or cases or stack: reject('version_position', number)
            continue
        summary = re.fullmatch(r'# (tests|suites|pass|fail|cancelled|skipped|todo) (0|[1-9]\d*)', line)
        if summary:
            key, value = summary.groups()
            if key in totals or stack or root['plan'] is None: reject('summary_duplicate_or_position', number)
            totals[key] = int(value)
            continue
        declaration = re.fullmatch(r'( *)# Subtest: (.+)', line)
        outcome = re.fullmatch(r'( *)(ok|not ok) ([1-9]\d*) - (.*?)(?: # (SKIP|TODO)(?: (.*))?)?', line)
        plan = re.fullmatch(r'( *)1\.\.(0|[1-9]\d*)', line)
        if declaration or outcome or plan:
            match = declaration or outcome or plan
            spaces = len(match.group(1))
            if spaces % 4 or spaces > 256:
                reject('invalid_indentation', number); continue
            depth = spaces // 4
            if declaration:
                if len(stack) != depth:
                    reject('overlapping_or_missing_parent', number); continue
                parent = stack[-1] if stack else root
                if parent['plan'] is not None or totals:
                    reject('case_after_plan_or_summary', number); continue
                name = declaration.group(2)
                stack.append({'name': name, 'path': parent['path'] + [name], 'children': [], 'plan': None})
            elif outcome:
                if len(stack) != depth + 1:
                    reject('outcome_without_exact_declaration', number); continue
                frame = stack[-1]
                parent = stack[-2] if len(stack) > 1 else root
                _, status, index, name, directive, reason = outcome.groups()
                if name != frame['name'] or int(index) != len(parent['children']) + 1:
                    reject('outcome_name_or_number', number)
                if frame['children'] and frame['plan'] != len(frame['children']) or frame['plan'] is not None and frame['plan'] != len(frame['children']):
                    reject('nested_plan_mismatch', number)
                record = {'path': frame['path'], 'number': int(index), 'outcome': status,
                          'directive': directive, 'reason': reason, 'depth': depth}
                cases.append(record); parent['children'].append(record); stack.pop()
            else:
                if len(stack) != depth:
                    reject('plan_before_cases_finish', number); continue
                parent = stack[-1] if stack else root
                count = int(plan.group(2))
                if parent['plan'] is not None or count < 1 or count != len(parent['children']):
                    reject('plan_duplicate_zero_or_count', number)
                parent['plan'] = count
            continue
        if totals and line.strip() and not line.startswith('#'):
            reject('unexpected_trailer', number)
        if re.match(r'^\s*(?:# Subtest:|(?:not )?ok\b|1\.\.|TAP version|# (?:tests|suites|pass|fail|cancelled|skipped|todo)\b)', line):
            reject('malformed_control_line', number)
    if stack: errors.append({'code': 'unfinished_subtest'})
    if version != 1 or not cases or root['plan'] != len(root['children']) or root['plan'] is None:
        errors.append({'code': 'missing_nonempty_root_plan'})
    if set(totals) != FIELDS:
        errors.append({'code': 'missing_summary'})
    paths = [tuple(row['path']) for row in cases]
    if len(set(paths)) != len(paths): errors.append({'code': 'duplicate_case_path'})
    return {'valid_structure': not errors, 'errors': errors, 'cases': cases, 'counts': totals,
            'top_level': len(root['children']), 'nested_cases': len(cases) - len(root['children'])}


def assess_nested_tap(output, platform_name, group, policy):
    parsed = parse_nested_tap(output)
    try:
        required = policy['nested_required_paths'][group]
        valid_policy = isinstance(required, list) and len(required) > 0 and all(
            isinstance(row, list) and 0 < len(row) <= 64 and all(isinstance(name, str) and name for name in row) for row in required)
        expected = {tuple(row) for row in required} if valid_policy else set()
        valid_policy = valid_policy and len(expected) == len(required)
    except (KeyError, TypeError):
        valid_policy, expected = False, set()
    cases, totals = parsed['cases'], parsed['counts']
    observed = {tuple(row['path']) for row in cases}
    passed = sum(row['outcome'] == 'ok' and row['directive'] is None for row in cases)
    valid = platform_name == 'linux' and parsed['valid_structure'] and valid_policy and observed == expected and passed > 0 and \
        len(cases) == len(expected) == totals.get('tests') == totals.get('pass') == passed and \
        all(totals.get(key) == 0 for key in ['suites', 'fail', 'cancelled', 'skipped', 'todo'])
    return {'valid': bool(valid), 'counts': totals, 'top_level': parsed.get('top_level', 0),
            'nested_cases': parsed.get('nested_cases', 0), 'structure_errors': parsed['errors'],
            'missing_required_paths': [list(row) for row in sorted(expected-observed)],
            'unexpected_case_paths': [list(row) for row in sorted(observed-expected)],
            'skips': [row for row in cases if row['directive']],
            'qualified_case_paths': [row['path'] for row in cases if row['outcome'] == 'ok' and row['directive'] is None]}
