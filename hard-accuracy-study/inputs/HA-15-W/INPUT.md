TASK
The current audit event redaction behavior must be updated. Before editing, identify the application module that is wired into the active runtime, the shared package used by that implementation, and the first source file to inspect.

FIRST-READ CONTEXT
[pkg-delta-v1-3/src/policy.js]
exports.legacy = (input) => applyDeprecatedRedactionRule(input);

[notes/redaction.md]
The previous implementation remains for rollback. UI and audit copies use similar names but are not runtime handlers.

[runtime/wiring.conf]
redaction=handler:h15|policy:p15|entry:e15
redaction-previous=handler:hx15|policy:px15|entry:ex15

[runtime/module-aliases.conf]
h15=svc-violet-3; hx15=svc-violet-legacy-3; w15=web-violet-3; a15=svc-delta-3

[runtime/package-aliases.conf]
p15=pkg-delta-3; px15=pkg-delta-v1-3

[runtime/file-aliases.conf]
e15=svc-violet-3/src/redact.js; ex15=svc-violet-legacy-3/src/redact.js; ew15=web-violet-3/src/redact.js; ea15=svc-delta-3/src/redact.js

[svc-violet-legacy-3/src/redact.js]
const policy = require("pkg-delta-v1-3"); function redactEvent(input) { return policy.legacy(input); }

[web-violet-3/src/redact.js]
function redactEvent(input) { return renderOnly(input); }

[pkg-delta-3/src/policy.js]
exports.current = (input) => applyCurrentRedactionRule(input);

[svc-violet-3/src/redact.js]
const policy = require("pkg-delta-3"); function redactEvent(input) { return policy.current(input); }

[svc-delta-3/src/redact.js]
function redactEvent(input) { return auditOnly(input); }

Return one JSON object with exactly these keys: target_module, required_dependency, first_source_file.
