TASK
The current audit event redaction behavior must be updated. Before editing, identify the application module that is wired into the active runtime, the shared package used by that implementation, and the first source file to inspect.

FIRST-READ CONTEXT
[svc-sable-legacy-2/src/redact.js]
const policy = require("pkg-zephyr-v1-2"); function redactEvent(input) { return policy.legacy(input); }

[web-sable-2/src/redact.js]
function redactEvent(input) { return renderOnly(input); }

[pkg-zephyr-2/src/policy.js]
exports.current = (input) => applyCurrentRedactionRule(input);

[svc-sable-2/src/redact.js]
const policy = require("pkg-zephyr-2"); function redactEvent(input) { return policy.current(input); }

[svc-zephyr-2/src/redact.js]
function redactEvent(input) { return auditOnly(input); }

[pkg-zephyr-v1-2/src/policy.js]
exports.legacy = (input) => applyDeprecatedRedactionRule(input);

[notes/redaction.md]
The previous implementation remains for rollback. UI and audit copies use similar names but are not runtime handlers.

[runtime/wiring.conf]
redaction=handler:h14|policy:p14|entry:e14
redaction-previous=handler:hx14|policy:px14|entry:ex14

[runtime/module-aliases.conf]
h14=svc-sable-2; hx14=svc-sable-legacy-2; w14=web-sable-2; a14=svc-zephyr-2

[runtime/package-aliases.conf]
p14=pkg-zephyr-2; px14=pkg-zephyr-v1-2

[runtime/file-aliases.conf]
e14=svc-sable-2/src/redact.js; ex14=svc-sable-legacy-2/src/redact.js; ew14=web-sable-2/src/redact.js; ea14=svc-zephyr-2/src/redact.js

Return one JSON object with exactly these keys: target_module, required_dependency, first_source_file.
