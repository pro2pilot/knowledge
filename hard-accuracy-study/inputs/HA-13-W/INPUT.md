TASK
The current audit event redaction behavior must be updated. Before editing, identify the application module that is wired into the active runtime, the shared package used by that implementation, and the first source file to inspect.

FIRST-READ CONTEXT
[notes/redaction.md]
The previous implementation remains for rollback. UI and audit copies use similar names but are not runtime handlers.

[runtime/wiring.conf]
redaction=handler:h13|policy:p13|entry:e13
redaction-previous=handler:hx13|policy:px13|entry:ex13

[runtime/module-aliases.conf]
h13=svc-pearl-1; hx13=svc-pearl-legacy-1; w13=web-pearl-1; a13=svc-willow-1

[runtime/package-aliases.conf]
p13=pkg-willow-1; px13=pkg-willow-v1-1

[runtime/file-aliases.conf]
e13=svc-pearl-1/src/redact.js; ex13=svc-pearl-legacy-1/src/redact.js; ew13=web-pearl-1/src/redact.js; ea13=svc-willow-1/src/redact.js

[svc-pearl-legacy-1/src/redact.js]
const policy = require("pkg-willow-v1-1"); function redactEvent(input) { return policy.legacy(input); }

[web-pearl-1/src/redact.js]
function redactEvent(input) { return renderOnly(input); }

[pkg-willow-1/src/policy.js]
exports.current = (input) => applyCurrentRedactionRule(input);

[svc-pearl-1/src/redact.js]
const policy = require("pkg-willow-1"); function redactEvent(input) { return policy.current(input); }

[svc-willow-1/src/redact.js]
function redactEvent(input) { return auditOnly(input); }

[pkg-willow-v1-1/src/policy.js]
exports.legacy = (input) => applyDeprecatedRedactionRule(input);

Return one JSON object with exactly these keys: target_module, required_dependency, first_source_file.
