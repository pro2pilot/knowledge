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
  let text = String(value ?? '');
  const redactions = [];
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

function scanPublication(input, anonymize = false) {
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
      unresolved_findings: unresolvedFindings
    }
  };
}

module.exports = {
  RULES,
  redactAnswers,
  redactStructure,
  redactText,
  scanPublication
};
