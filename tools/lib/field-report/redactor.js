'use strict';

const { sanitizeExportString } = require('../export-sanitizer');

const RULES = Object.freeze([
  {
    id: 'private_key',
    severity: 'critical',
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY-----/g
  },
  {
    id: 'github_token',
    severity: 'high',
    pattern: /\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/g
  },
  {
    id: 'api_key',
    severity: 'high',
    pattern: /\b(?:sk-ant-|sk-)[A-Za-z0-9_-]{20,}\b/g
  },
  {
    id: 'credential_assignment',
    severity: 'high',
    pattern: /\b(?:[A-Z][A-Z0-9_]*_(?:TOKEN|SECRET|KEY|PASSWORD)|DATABASE_URL)\s*=\s*[^\s]+/g
  },
  {
    id: 'credentials_url',
    severity: 'high',
    pattern: /https?:\/\/[^\s/@]+:[^\s/@]+@[^\s/]+/gi
  },
  {
    id: 'unsafe_link_protocol',
    severity: 'high',
    pattern: /\b(?:javascript|data):[^\s)>\]]+/gi
  },
  {
    id: 'internal_hostname',
    severity: 'medium',
    pattern: /\b[a-z0-9][a-z0-9.-]*\.(?:internal|local|corp|lan)\b/gi
  },
  {
    id: 'private_network_address',
    severity: 'medium',
    pattern: /\b(?:10\.(?:\d{1,3}\.){2}\d{1,3}|127\.(?:\d{1,3}\.){2}\d{1,3}|169\.254\.(?:\d{1,3}\.)\d{1,3}|192\.168\.(?:\d{1,3}\.)\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.(?:\d{1,3}\.)\d{1,3})\b/g
  },
  {
    id: 'private_ipv6_address',
    severity: 'medium',
    pattern: /(?<![0-9a-f:])(?:::1|f[cd][0-9a-f]{0,2}:[0-9a-f:]+|fe[89ab][0-9a-f]?:[0-9a-f:]+)(?![0-9a-f:])/gi
  },
  {
    id: 'file_uri',
    severity: 'medium',
    pattern: /\bfile:\/\/\/?[^\s)>\]]+/gi
  },
  {
    id: 'absolute_posix_path',
    severity: 'medium',
    pattern: /(?<![A-Za-z0-9._~-])(?<![A-Za-z0-9+.-]:)(?<!\/)\/(?!\/)(?:[^\s"'`,;)}\]]+\/)+[^\s"'`,;)}\]]+/g
  }
]);



const GENERIC_WORKSPACE_DESCRIPTION = 'a larger local multi-project workspace';
const GENERIC_ORGANIZATION_DESCRIPTION = 'an internal organization';
const GENERIC_CLIENT_DESCRIPTION = 'an internal client organization';
const PUBLIC_WORKSPACE_LABEL_ALLOWLIST = new Set([
  'actions', 'after', 'any', 'before', 'contained', 'contains', 'covered',
  'current', 'during', 'each', 'every', 'for', 'from', 'github', 'github actions', 'had', 'has',
  'held', 'included', 'includes', 'inside', 'is', 'local', 'outside', 'over',
  'multiple', 'one', 'our', 'project', 'registered', 'remained', 'reported',
  'repository', 'same', 'single', 'spanned', 'standalone', 'supported', 'supports',
  'team', 'that', 'their', 'this', 'to', 'under', 'used', 'uses', 'your',
  'visual', 'visual studio code', 'vscode', 'was', 'when', 'where', 'with',
  'without', 'workspace'
]);
const ENGLISH_SIGNAL_WORDS = new Set([
  'a', 'an', 'and', 'are', 'as', 'at', 'be', 'because', 'but', 'by', 'for',
  'from', 'has', 'have', 'in', 'is', 'it', 'not', 'of', 'on', 'or', 'that',
  'the', 'this', 'to', 'was', 'were', 'with', 'without'
]);
const NON_ENGLISH_LATIN_SIGNAL_WORDS = new Set([
  'aber', 'avec', 'como', 'con', 'dans', 'das', 'de', 'del', 'des', 'die',
  'el', 'en', 'est', 'et', 'für', 'ist', 'la', 'las', 'le', 'les', 'los',
  'mais', 'mit', 'não', 'para', 'pero', 'por', 'que', 'se', 'sin', 'sur',
  'und', 'une', 'una', 'uno', 'y'
]);

function normalizedOrganizationLabel(value) {
  return String(value || '')
    .replace(/["'`]/g, '')
    .replace(/\s+/g, ' ')
    .trim()
    .toLowerCase()
    .replace(/^(?:the|a|an)(?:\s+|$)/, '');
}

function publicOrganizationLabel(value) {
  const normalized = normalizedOrganizationLabel(value);
  return !normalized || PUBLIC_WORKSPACE_LABEL_ALLOWLIST.has(normalized);
}

function generalizationRecord(replacement) {
  return {
    rule: 'internal_organization_generalized',
    severity: 'medium',
    replacement
  };
}

function generalizeInternalOrganization(value) {
  let text = String(value ?? '');
  const changes = [];
  const replaceLabel = (match, label, replacement) => {
    if (publicOrganizationLabel(label)) return match;
    const finalReplacement = /^The\b/.test(match)
      ? replacement.charAt(0).toUpperCase() + replacement.slice(1)
      : replacement;
    changes.push(generalizationRecord(finalReplacement));
    return finalReplacement;
  };

  // Explicitly quoted labels are safest to generalize because the boundaries are clear.
  text = text.replace(
    /\b(?:The\s+|the\s+)?(workspace|department|client|organization|organisation|team)\s+(?:named\s+|called\s+)?["'`]([^"'`]{2,80})["'`]/giu,
    (match, kind, label) => replaceLabel(
      match,
      label,
      /^workspace$/i.test(kind)
        ? GENERIC_WORKSPACE_DESCRIPTION
        : /^client$/i.test(kind) ? GENERIC_CLIENT_DESCRIPTION : GENERIC_ORGANIZATION_DESCRIPTION
    )
  );

  // Unquoted TitleCase labels cover common developer wording such as "workspace Design".
  text = text.replace(
    /\b(?:The\s+|the\s+)?workspace\s+(?:named\s+|called\s+)?([A-Z][\p{L}\p{N}_-]*(?:\s+[A-Z][\p{L}\p{N}_-]*){0,2})\b/gu,
    (match, label) => replaceLabel(match, label, GENERIC_WORKSPACE_DESCRIPTION)
  );
  // A single lowercase slug after `workspace` is also a common internal label.
  // Common prose verbs/adjectives are allowlisted so phrases such as
  // `the workspace contained one repository` remain unchanged.
  text = text.replace(
    /\b(?:The\s+|the\s+)?workspace\s+(?:named\s+|called\s+)?([a-z][a-z0-9._-]{1,39})\b/g,
    (match, label) => replaceLabel(match, label, GENERIC_WORKSPACE_DESCRIPTION)
  );
  text = text.replace(
    /\b(?:The\s+|the\s+)?([A-Z][\p{L}\p{N}_-]*(?:\s+[A-Z][\p{L}\p{N}_-]*){0,2})\s+workspace\b/gu,
    (match, label) => replaceLabel(match, label, GENERIC_WORKSPACE_DESCRIPTION)
  );
  text = text.replace(
    /\b(?:The\s+|the\s+)?(client|department|organization|organisation)\s+(?:named\s+|called\s+)?([A-Z][\p{L}\p{N}_-]*(?:\s+[A-Z][\p{L}\p{N}_-]*){0,2})\b/gu,
    (match, kind, label) => replaceLabel(
      match,
      label,
      /^client$/i.test(kind) ? GENERIC_CLIENT_DESCRIPTION : GENERIC_ORGANIZATION_DESCRIPTION
    )
  );
  text = text.replace(
    /\b(?:internal|private)\s+(?:organization|organisation|department|team)\s*(?:named|called|:)?\s*["'`]?([A-Z][\p{L}\p{N}_-]*(?:\s+[A-Z][\p{L}\p{N}_-]*){0,2})["'`]?\b/giu,
    (match, label) => replaceLabel(match, label, GENERIC_ORGANIZATION_DESCRIPTION)
  );
  return { text, changes };
}

function scanEnglishLanguage(value) {
  const source = String(value || '')
    .replace(/```[\s\S]*?```/g, ' ')
    .replace(/`[^`]*`/g, ' ')
    .replace(/https?:\/\/\S+/gi, ' ')
    .replace(/[a-f0-9]{32,}/gi, ' ');
  const nonLatin = source.match(/[\u0370-\u052F\u0590-\u06FF\u0900-\u097F\u3040-\u30FF\u3400-\u9FFF\uAC00-\uD7AF]/g) || [];
  const words = (source.toLowerCase().match(/[a-zÀ-ÿ]+/g) || [])
    .filter((word) => word.length > 1);
  const englishSignals = words.filter((word) => ENGLISH_SIGNAL_WORDS.has(word)).length;
  const foreignSignals = words.filter((word) => NON_ENGLISH_LATIN_SIGNAL_WORDS.has(word)).length;
  const findings = [];
  if (nonLatin.length >= 4) {
    findings.push({
      rule: 'public_language_not_english',
      severity: 'high',
      reason: 'substantial_non_latin_text',
      characters: nonLatin.length
    });
  }
  if (words.length >= 8 && foreignSignals >= 3 && foreignSignals > englishSignals * 1.25) {
    findings.push({
      rule: 'public_language_not_english',
      severity: 'high',
      reason: 'latin_language_signal',
      foreign_signal_words: foreignSignals,
      english_signal_words: englishSignals
    });
  }
  return {
    status: findings.length ? 'blocked' : 'pass',
    findings,
    heuristic: 'knowledge-field-report-english-publication.v1'
  };
}

function protectHttpUrls(value) {
  const urls = [];
  const text = String(value).replace(/\bhttps?:\/\/[^\s)>\]]+/gi, (match) => {
    const marker = `__FIELD_REPORT_HTTP_URL_${urls.length}__`;
    urls.push([marker, match]);
    return marker;
  });
  return {
    text,
    restore(output) {
      let restored = output;
      for (const [marker, url] of urls) restored = restored.split(marker).join(url);
      return restored;
    }
  };
}

function redactText(value, anonymize = false) {
  const generalized = generalizeInternalOrganization(value);
  let text = generalized.text;
  const redactions = [...generalized.changes];
  const reviewFindings = [];
  for (const rule of RULES) {
    const protectedUrls = rule.id === 'absolute_posix_path'
      ? protectHttpUrls(text)
      : { text, restore: (output) => output };
    text = protectedUrls.restore(protectedUrls.text.replace(rule.pattern, () => {
      const replacement = `[REDACTED:${rule.id}]`;
      redactions.push({
        rule: rule.id,
        severity: rule.severity,
        replacement
      });
      if (rule.severity === 'high' || rule.severity === 'critical') {
        reviewFindings.push({ rule: rule.id, severity: rule.severity });
      }
      return replacement;
    }));
  }
  const sanitized = sanitizeExportString(text, { redactWorkspaceName: Boolean(anonymize) });
  if (sanitized !== text) {
    redactions.push({
      rule: 'export_sanitizer',
      severity: 'medium',
      replacement: '<redacted>'
    });
    text = sanitized;
  }
  if (anonymize) {
    const anonymized = text.replace(
      /https?:\/\/github\.com\/[^\s/]+\/[^\s/#)]+/gi,
      '[REDACTED:repository-url]'
    );
    if (anonymized !== text) {
      redactions.push({
        rule: 'repository_url',
        severity: 'medium',
        replacement: '[REDACTED:repository-url]'
      });
      text = anonymized;
    }
  }
  return {
    text,
    redactions,
    unresolved_findings: reviewFindings,
    requires_tester_review: reviewFindings.length > 0
  };
}

function redactAnswers(answers, anonymize = false) {
  const output = {};
  const redactions = [];
  const unresolvedFindings = [];
  for (const [field, raw] of Object.entries(answers || {})) {
    const wrapped = raw && typeof raw === 'object' &&
      Object.prototype.hasOwnProperty.call(raw, 'value');
    const value = wrapped ? raw.value : raw;
    const metadata = wrapped
      ? redactStructure(
        Object.fromEntries(Object.entries(raw).filter(([key]) => key !== 'value')),
        anonymize,
        field
      )
      : { value: {}, redactions: [], unresolved_findings: [] };
    redactions.push(...metadata.redactions);
    unresolvedFindings.push(...metadata.unresolved_findings);
    if (typeof value === 'string') {
      const scan = redactText(value, anonymize);
      output[field] = {
        ...metadata.value,
        value: scan.text,
        kind: raw?.kind || 'tester',
        source: raw?.source || 'tester_answer'
      };
      redactions.push(...scan.redactions.map((finding) => ({ field, ...finding })));
      unresolvedFindings.push(
        ...scan.unresolved_findings.map((finding) => ({ field, ...finding }))
      );
    } else {
      output[field] = wrapped
        ? { ...metadata.value, value }
        : { value, kind: 'tester', source: 'tester_answer' };
    }
  }
  return {
    answers: output,
    report: {
      schema_version: 'knowledge-field-report-redaction.v2',
      status: unresolvedFindings.length ? 'blocked' : redactions.length ? 'warning' : 'pass',
      redactions,
      unresolved_findings: unresolvedFindings
    }
  };
}

function redactStructure(value, anonymize = false, location = 'metadata') {
  if (typeof value === 'string') {
    const scan = redactText(value, anonymize);
    return {
      value: scan.text,
      redactions: scan.redactions.map((item) => ({ field: location, ...item })),
      unresolved_findings: scan.unresolved_findings.map((item) => ({
        field: location,
        ...item
      }))
    };
  }
  if (Array.isArray(value)) {
    const parts = value.map((item, index) =>
      redactStructure(item, anonymize, `${location}[${index}]`));
    return {
      value: parts.map((item) => item.value),
      redactions: parts.flatMap((item) => item.redactions),
      unresolved_findings: parts.flatMap((item) => item.unresolved_findings)
    };
  }
  if (value && typeof value === 'object') {
    const output = {};
    const redactions = [];
    const unresolvedFindings = [];
    for (const [key, item] of Object.entries(value)) {
      const result = redactStructure(item, anonymize, `${location}.${key}`);
      output[key] = result.value;
      redactions.push(...result.redactions);
      unresolvedFindings.push(...result.unresolved_findings);
    }
    return { value: output, redactions, unresolved_findings: unresolvedFindings };
  }
  return { value, redactions: [], unresolved_findings: [] };
}

function scanPublication(input, anonymize = false, options = {}) {
  const fields = {
    title: input?.title || '',
    body: input?.body || '',
    supporting_material: input?.supporting_material || '',
    generated_links: Array.isArray(input?.generated_links)
      ? input.generated_links.join('\n')
      : input?.generated_links || ''
  };
  const output = {};
  const redactions = [];
  const unresolvedFindings = [];
  for (const [field, value] of Object.entries(fields)) {
    const scan = redactText(value, anonymize);
    output[field] = scan.text;
    redactions.push(...scan.redactions.map((finding) => ({ field, ...finding })));
    unresolvedFindings.push(
      ...scan.unresolved_findings.map((finding) => ({ field, ...finding }))
    );
  }
  const languageScan = options.requireEnglish
    ? scanEnglishLanguage(`${output.title}\n${output.body}`)
    : { status: 'not_required', findings: [], heuristic: null };
  const languageFindings = (languageScan.findings || []).map((finding) => ({
    field: 'publication_language',
    ...finding
  }));
  unresolvedFindings.push(...languageFindings);
  return {
    title: output.title,
    body: output.body,
    supporting_material: output.supporting_material,
    generated_links: output.generated_links
      ? output.generated_links.split('\n').filter(Boolean)
      : [],
    report: {
      schema_version: 'knowledge-field-report-final-redaction.v2',
      scanned_fields: Object.keys(fields),
      status: unresolvedFindings.length ? 'blocked' : redactions.length ? 'warning' : 'pass',
      redactions,
      unresolved_findings: unresolvedFindings,
      language_scan: languageScan
    }
  };
}

module.exports = {
  RULES,
  generalizeInternalOrganization,
  redactAnswers,
  redactStructure,
  redactText,
  scanEnglishLanguage,
  scanPublication
};
