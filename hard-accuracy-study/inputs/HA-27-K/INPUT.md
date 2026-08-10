TASK
The current analytics consent filtering behavior must be updated. Before editing, identify the application module that is wired into the active runtime, the shared package used by that implementation, and the first source file to inspect.

FIRST-READ CONTEXT
[task-route/current]
selected=h27,p27; entry=e27; excluded=hx27,w27,a27,px27

[runtime/module-aliases.conf]
h27=svc-harbor-3; hx27=svc-harbor-legacy-3; w27=web-harbor-3; a27=svc-onyx-3

[runtime/package-aliases.conf]
p27=pkg-onyx-3; px27=pkg-onyx-v1-3

[runtime/file-aliases.conf]
e27=svc-harbor-3/src/filter.js; ex27=svc-harbor-legacy-3/src/filter.js; ew27=web-harbor-3/src/filter.js; ea27=svc-onyx-3/src/filter.js

[svc-harbor-3/src/filter.js]
const policy = require("pkg-onyx-3"); function filterConsent(input) { return policy.current(input); }

[pkg-onyx-3/src/rules.js]
exports.current = (input) => applyCurrentConsentRule(input);

[svc-harbor-legacy-3/src/filter.js]
const policy = require("pkg-onyx-v1-3"); function filterConsent(input) { return policy.legacy(input); }

Return one JSON object with exactly these keys: target_module, required_dependency, first_source_file.
