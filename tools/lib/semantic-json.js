'use strict';

const FAILURE_STATUSES = new Set([
  'blocked',
  'degraded',
  'error',
  'fail',
  'failed',
  'broken',
  'needs_repair',
  'runtime_error',
  'storage_unavailable',
  'unhealthy',
  'unexpected_failure'
]);

const EXPECTED_OUTCOMES = new Set([
  'expected_failure_observed',
  'expected_semantic_failure',
  'blocked_external_quota',
  'blocked_missing_credentials',
  'blocked_network'
]);

function parseJsonOutput(value) {
  const text = String(value || '').trim();
  if (!text) throw new Error('stdout is empty');
  return JSON.parse(text);
}

function isExpectedRow(row) {
  return Boolean(
    row && (
      row.expected === true ||
      row.expected_failure === true ||
      row.expected_semantic_failure === true ||
      row.expected_block === true ||
      row.semantic_pass === true && EXPECTED_OUTCOMES.has(String(row.semantic_outcome || '').toLowerCase())
    )
  );
}

function rowSemanticErrors(row, rowPath) {
  if (!row || typeof row !== 'object' || Array.isArray(row)) return [];
  const errors = [];
  if (row.expected_nonzero_exit === true) {
    if (row.expected_failure !== true) {
      errors.push(
        `${rowPath}.expected_failure was not confirmed`
      );
    }
    if (
      !Number.isInteger(row.exit_code) ||
      row.exit_code === 0
    ) {
      errors.push(
        `${rowPath}.expected_nonzero_exit requires an integer nonzero exit_code`
      );
    }
  }
  if (isExpectedRow(row)) return errors;
  const status = String(row.status || '').toLowerCase();
  const outcome = String(row.semantic_outcome || '').toLowerCase();
  if (row.ok === false) errors.push(`${rowPath}.ok is false`);
  if (row.success === false) errors.push(`${rowPath}.success is false`);
  if (row.process_success === false) errors.push(`${rowPath}.process_success is false`);
  if (row.semantic_pass === false) errors.push(`${rowPath}.semantic_pass is false`);
  if (row.exit_code !== undefined && row.exit_code !== null && Number(row.exit_code) !== 0) {
    errors.push(`${rowPath}.exit_code is ${row.exit_code}`);
  }
  if (row.exit !== undefined && row.exit !== null && Number(row.exit) !== 0) {
    errors.push(`${rowPath}.exit is ${row.exit}`);
  }
  if (FAILURE_STATUSES.has(status)) errors.push(`${rowPath}.status is ${status}`);
  if (FAILURE_STATUSES.has(outcome)) errors.push(`${rowPath}.semantic_outcome is ${outcome}`);
  return errors;
}

function positiveCounterErrors(value, rootPath = '$') {
  const errors = [];
  for (const key of [
    'unexpected_failure_count',
    'unexpected_failed_count',
    'unexpected_semantic_failure_count',
    'critical_failed_count'
  ]) {
    const count = Number(value?.[key] || 0);
    if (Number.isFinite(count) && count > 0) errors.push(`${rootPath}.${key} is ${count}`);
  }
  return errors;
}

function parseEmbeddedObject(value) {
  const text = String(value || '').trim().replace(/^\uFEFF/, '');
  if (!text.startsWith('{')) return null;
  return JSON.parse(text);
}

function inspectSemanticJsonAt(value, options, rootPath, depth) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return { ok: false, errors: [`${rootPath} must be an object`] };
  }

  const errors = [
    ...rowSemanticErrors(value, rootPath),
    ...positiveCounterErrors(value, rootPath)
  ];

  if (Array.isArray(value.failures) && value.failures.length > 0 && !options.allowFailuresArray) {
    errors.push(`${rootPath}.failures contains ${value.failures.length} item(s)`);
  }

  for (const collection of ['commands', 'results', 'checks', 'steps']) {
    if (!Array.isArray(value[collection])) continue;
    value[collection].forEach((row, index) => {
      errors.push(...rowSemanticErrors(row, `${rootPath}.${collection}[${index}]`));
    });
  }

  if (options.inspectEmbeddedJson !== false && depth < Number(options.maxEmbeddedDepth || 6)) {
    const visit = (node, nodePath) => {
      if (!node || typeof node !== 'object' || isExpectedRow(node)) return;
      if (Array.isArray(node)) {
        node.forEach((item, index) => visit(item, `${nodePath}[${index}]`));
        return;
      }
      for (const [key, child] of Object.entries(node)) {
        const childPath = `${nodePath}.${key}`;
        if (key === 'stdout' && typeof child === 'string') {
          try {
            const embedded = parseEmbeddedObject(child);
            if (embedded) {
              const inspected = inspectSemanticJsonAt(embedded, options, `${childPath}<json>`, depth + 1);
              errors.push(...inspected.errors);
            }
          } catch (error) {
            if (options.failOnInvalidEmbeddedJson) errors.push(`${childPath} contains invalid JSON: ${error.message}`);
          }
        } else if (child && typeof child === 'object') {
          visit(child, childPath);
        }
      }
    };
    visit(value, rootPath);
  }

  return { ok: errors.length === 0, errors };
}

function inspectSemanticJson(value, options = {}) {
  return inspectSemanticJsonAt(value, options, '$', 0);
}

module.exports = {
  FAILURE_STATUSES,
  EXPECTED_OUTCOMES,
  inspectSemanticJson,
  isExpectedRow,
  parseJsonOutput
};
