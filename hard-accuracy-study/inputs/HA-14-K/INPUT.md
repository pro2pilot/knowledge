TASK
The current audit event redaction behavior must be updated. Before editing, identify the application module that is wired into the active runtime, the shared package used by that implementation, and the first source file to inspect.

FIRST-READ CONTEXT
[task-route/current]
selected=h14,p14; entry=e14; excluded=hx14,w14,a14,px14

[runtime/module-aliases.conf]
h14=svc-sable-2; hx14=svc-sable-legacy-2; w14=web-sable-2; a14=svc-zephyr-2

[runtime/package-aliases.conf]
p14=pkg-zephyr-2; px14=pkg-zephyr-v1-2

[runtime/file-aliases.conf]
e14=svc-sable-2/src/redact.js; ex14=svc-sable-legacy-2/src/redact.js; ew14=web-sable-2/src/redact.js; ea14=svc-zephyr-2/src/redact.js

[svc-sable-2/src/redact.js]
const policy = require("pkg-zephyr-2"); function redactEvent(input) { return policy.current(input); }

[pkg-zephyr-2/src/policy.js]
exports.current = (input) => applyCurrentRedactionRule(input);

[svc-sable-legacy-2/src/redact.js]
const policy = require("pkg-zephyr-v1-2"); function redactEvent(input) { return policy.legacy(input); }

Return one JSON object with exactly these keys: target_module, required_dependency, first_source_file.
