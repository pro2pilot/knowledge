TASK
The current audit event redaction behavior must be updated. Before editing, identify the application module that is wired into the active runtime, the shared package used by that implementation, and the first source file to inspect.

FIRST-READ CONTEXT
[task-route/current]
selected=h15,p15; entry=e15; excluded=hx15,w15,a15,px15

[runtime/module-aliases.conf]
h15=svc-violet-3; hx15=svc-violet-legacy-3; w15=web-violet-3; a15=svc-delta-3

[runtime/package-aliases.conf]
p15=pkg-delta-3; px15=pkg-delta-v1-3

[runtime/file-aliases.conf]
e15=svc-violet-3/src/redact.js; ex15=svc-violet-legacy-3/src/redact.js; ew15=web-violet-3/src/redact.js; ea15=svc-delta-3/src/redact.js

[svc-violet-3/src/redact.js]
const policy = require("pkg-delta-3"); function redactEvent(input) { return policy.current(input); }

[pkg-delta-3/src/policy.js]
exports.current = (input) => applyCurrentRedactionRule(input);

[svc-violet-legacy-3/src/redact.js]
const policy = require("pkg-delta-v1-3"); function redactEvent(input) { return policy.legacy(input); }

Return one JSON object with exactly these keys: target_module, required_dependency, first_source_file.
