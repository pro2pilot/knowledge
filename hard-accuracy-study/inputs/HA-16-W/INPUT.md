TASK
The current audit event redaction behavior must be updated. Before editing, identify the application module that is wired into the active runtime, the shared package used by that implementation, and the first source file to inspect.

FIRST-READ CONTEXT
[runtime/file-aliases.conf]
e16=svc-yarrow-4/src/redact.js; ex16=svc-yarrow-legacy-4/src/redact.js; ew16=web-yarrow-4/src/redact.js; ea16=svc-garnet-4/src/redact.js

[svc-yarrow-legacy-4/src/redact.js]
const policy = require("pkg-garnet-v1-4"); function redactEvent(input) { return policy.legacy(input); }

[web-yarrow-4/src/redact.js]
function redactEvent(input) { return renderOnly(input); }

[pkg-garnet-4/src/policy.js]
exports.current = (input) => applyCurrentRedactionRule(input);

[svc-yarrow-4/src/redact.js]
const policy = require("pkg-garnet-4"); function redactEvent(input) { return policy.current(input); }

[svc-garnet-4/src/redact.js]
function redactEvent(input) { return auditOnly(input); }

[pkg-garnet-v1-4/src/policy.js]
exports.legacy = (input) => applyDeprecatedRedactionRule(input);

[notes/redaction.md]
The previous implementation remains for rollback. UI and audit copies use similar names but are not runtime handlers.

[runtime/wiring.conf]
redaction=handler:h16|policy:p16|entry:e16
redaction-previous=handler:hx16|policy:px16|entry:ex16

[runtime/module-aliases.conf]
h16=svc-yarrow-4; hx16=svc-yarrow-legacy-4; w16=web-yarrow-4; a16=svc-garnet-4

[runtime/package-aliases.conf]
p16=pkg-garnet-4; px16=pkg-garnet-v1-4

Return one JSON object with exactly these keys: target_module, required_dependency, first_source_file.
