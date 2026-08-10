TASK
The current analytics consent filtering behavior must be updated. Before editing, identify the application module that is wired into the active runtime, the shared package used by that implementation, and the first source file to inspect.

FIRST-READ CONTEXT
[task-route/current]
selected=h25,p25; entry=e25; excluded=hx25,w25,a25,px25

[runtime/module-aliases.conf]
h25=svc-amber-1; hx25=svc-amber-legacy-1; w25=web-amber-1; a25=svc-indigo-1

[runtime/package-aliases.conf]
p25=pkg-indigo-1; px25=pkg-indigo-v1-1

[runtime/file-aliases.conf]
e25=svc-amber-1/src/filter.js; ex25=svc-amber-legacy-1/src/filter.js; ew25=web-amber-1/src/filter.js; ea25=svc-indigo-1/src/filter.js

[svc-amber-1/src/filter.js]
const policy = require("pkg-indigo-1"); function filterConsent(input) { return policy.current(input); }

[pkg-indigo-1/src/rules.js]
exports.current = (input) => applyCurrentConsentRule(input);

[svc-amber-legacy-1/src/filter.js]
const policy = require("pkg-indigo-v1-1"); function filterConsent(input) { return policy.legacy(input); }

Return one JSON object with exactly these keys: target_module, required_dependency, first_source_file.
