TASK
The current audit event redaction behavior must be updated. Before editing, identify the application module that is wired into the active runtime, the shared package used by that implementation, and the first source file to inspect.

FIRST-READ CONTEXT
[task-route/current]
selected=h13,p13; entry=e13; excluded=hx13,w13,a13,px13

[runtime/module-aliases.conf]
h13=svc-pearl-1; hx13=svc-pearl-legacy-1; w13=web-pearl-1; a13=svc-willow-1

[runtime/package-aliases.conf]
p13=pkg-willow-1; px13=pkg-willow-v1-1

[runtime/file-aliases.conf]
e13=svc-pearl-1/src/redact.js; ex13=svc-pearl-legacy-1/src/redact.js; ew13=web-pearl-1/src/redact.js; ea13=svc-willow-1/src/redact.js

[svc-pearl-1/src/redact.js]
const policy = require("pkg-willow-1"); function redactEvent(input) { return policy.current(input); }

[pkg-willow-1/src/policy.js]
exports.current = (input) => applyCurrentRedactionRule(input);

[svc-pearl-legacy-1/src/redact.js]
const policy = require("pkg-willow-v1-1"); function redactEvent(input) { return policy.legacy(input); }

Return one JSON object with exactly these keys: target_module, required_dependency, first_source_file.
