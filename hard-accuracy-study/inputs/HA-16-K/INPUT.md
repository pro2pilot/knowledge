TASK
The current audit event redaction behavior must be updated. Before editing, identify the application module that is wired into the active runtime, the shared package used by that implementation, and the first source file to inspect.

FIRST-READ CONTEXT
[task-route/current]
selected=h16,p16; entry=e16; excluded=hx16,w16,a16,px16

[runtime/module-aliases.conf]
h16=svc-yarrow-4; hx16=svc-yarrow-legacy-4; w16=web-yarrow-4; a16=svc-garnet-4

[runtime/package-aliases.conf]
p16=pkg-garnet-4; px16=pkg-garnet-v1-4

[runtime/file-aliases.conf]
e16=svc-yarrow-4/src/redact.js; ex16=svc-yarrow-legacy-4/src/redact.js; ew16=web-yarrow-4/src/redact.js; ea16=svc-garnet-4/src/redact.js

[svc-yarrow-4/src/redact.js]
const policy = require("pkg-garnet-4"); function redactEvent(input) { return policy.current(input); }

[pkg-garnet-4/src/policy.js]
exports.current = (input) => applyCurrentRedactionRule(input);

[svc-yarrow-legacy-4/src/redact.js]
const policy = require("pkg-garnet-v1-4"); function redactEvent(input) { return policy.legacy(input); }

Return one JSON object with exactly these keys: target_module, required_dependency, first_source_file.
