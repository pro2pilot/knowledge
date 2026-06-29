'use strict';

function toArray(value) {
  if (!value) return [];
  return Array.isArray(value) ? value : [value];
}

const DEFAULT_MANIFEST = {
  schema_version: '3.2.1',
  purpose: 'Free-core paid Inspector manifest.',
  free_boundary: 'Free core shows local truth and disabled paid actions only.',
  paid_layer_root: 'pro2pilot-inspector/',
  pricing_policy: {
    prices_in_free_core: false,
    feature_plan_bindings_in_free_core: false
  },
  capabilities: [],
  conversion_signals: [],
  billing_dimensions: [],
  do_not_charge_for: [],
  usage_billing_policy: {},
  add_on_streams: [],
  license_and_provenance_rules: {},
  anti_patterns: []
};

function normalizePaidManifest(manifest = {}) {
  const out = { ...DEFAULT_MANIFEST, ...manifest };
  out.pricing_policy = { ...DEFAULT_MANIFEST.pricing_policy, ...(manifest.pricing_policy || {}) };
  out.capabilities = toArray(manifest.capabilities);
  out.conversion_signals = toArray(manifest.conversion_signals);
  out.billing_dimensions = toArray(manifest.billing_dimensions);
  out.do_not_charge_for = toArray(manifest.do_not_charge_for);
  out.add_on_streams = toArray(manifest.add_on_streams);
  out.anti_patterns = toArray(manifest.anti_patterns);
  out.license_and_provenance_rules = manifest.license_and_provenance_rules || {};
  return out;
}

function paidSurfaceMetrics(data) {
  const repairQueue = toArray(data.repair?.queue);
  const staleItems = toArray(data.stale?.items || data.stale?.stale_items);
  const criticalFiles = toArray(data.fileCriticality?.files)
    .filter((file) => ['critical', 'important'].includes(file.classification));
  const providers = Array.isArray(data.external?.providers)
    ? data.external.providers
    : Object.values(data.external?.providers || {});
  const qualityScore = Number(data.quality?.quality_score ?? data.quality?.score ?? 0);
  return {
    repair_queue_count: repairQueue.length,
    stale_item_count: staleItems.length,
    critical_file_count: criticalFiles.length,
    team_workspace_count: Number(data.team?.workspaces_total || 0),
    shared_external_memory_count: providers.filter((provider) => provider.mode === 'shared').length,
    quality_score: Number.isFinite(qualityScore) ? qualityScore : 0
  };
}

function compareMetric(actual, op, expected) {
  const left = Number(actual);
  const right = Number(expected);
  if (!Number.isFinite(left) || !Number.isFinite(right)) return false;
  if (op === '>') return left > right;
  if (op === '>=') return left >= right;
  if (op === '<') return left < right;
  if (op === '<=') return left <= right;
  if (op === '==') return left === right;
  if (op === '!=') return left !== right;
  return false;
}

function evaluateConversionSignal(signal, metrics) {
  const conditions = toArray(signal.conditions);
  if (!conditions.length) return false;
  return conditions.every((condition) => compareMetric(
    metrics[condition.metric],
    condition.op || '>',
    condition.value
  ));
}

function forbiddenBindingKeys(value, trail = []) {
  const findings = [];
  if (!value || typeof value !== 'object') return findings;
  for (const [key, child] of Object.entries(value)) {
    const nextTrail = [...trail, key];
    if (/^(plan|plans|plan_id|plan_ids|tier|tiers|sku|skus|package|packages|price|prices|amount|currency)$/i.test(key)) {
      findings.push(nextTrail.join('.'));
    }
    if (child && typeof child === 'object') findings.push(...forbiddenBindingKeys(child, nextTrail));
  }
  return findings;
}

function validateNoPricingOrPlanBindings(manifest) {
  const errors = [];
  const normalized = normalizePaidManifest(manifest);
  if (normalized.pricing_policy.prices_in_free_core !== false) {
    errors.push('pricing_policy.prices_in_free_core must be false');
  }
  if (normalized.pricing_policy.feature_plan_bindings_in_free_core !== false) {
    errors.push('pricing_policy.feature_plan_bindings_in_free_core must be false');
  }
  const serialized = JSON.stringify(normalized);
  if (/\$\s*\d|\bUSD\b|\bEUR\b|\bseat\/month\b|\bworkspace\/month\b/i.test(serialized)) {
    errors.push('free paid-feature manifest must not contain concrete prices or currency terms');
  }
  normalized.capabilities.forEach((capability, index) => {
    for (const finding of forbiddenBindingKeys(capability)) {
      errors.push(`capabilities[${index}].${finding} must not bind features to plans or prices`);
    }
  });
  return errors;
}

module.exports = {
  normalizePaidManifest,
  paidSurfaceMetrics,
  evaluateConversionSignal,
  validateNoPricingOrPlanBindings
};
