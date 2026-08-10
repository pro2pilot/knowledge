TASK
The current analytics consent filtering behavior must be updated. Before editing, identify the application module that is wired into the active runtime, the shared package used by that implementation, and the first source file to inspect.

FIRST-READ CONTEXT
[task-route/current]
selected=h28,p28; entry=e28; excluded=hx28,w28,a28,px28

[runtime/module-aliases.conf]
h28=svc-kestrel-4; hx28=svc-kestrel-legacy-4; w28=web-kestrel-4; a28=svc-raven-4

[runtime/package-aliases.conf]
p28=pkg-raven-4; px28=pkg-raven-v1-4

[runtime/file-aliases.conf]
e28=svc-kestrel-4/src/filter.js; ex28=svc-kestrel-legacy-4/src/filter.js; ew28=web-kestrel-4/src/filter.js; ea28=svc-raven-4/src/filter.js

[svc-kestrel-4/src/filter.js]
const policy = require("pkg-raven-4"); function filterConsent(input) { return policy.current(input); }

[pkg-raven-4/src/rules.js]
exports.current = (input) => applyCurrentConsentRule(input);

[svc-kestrel-legacy-4/src/filter.js]
const policy = require("pkg-raven-v1-4"); function filterConsent(input) { return policy.legacy(input); }

Return one JSON object with exactly these keys: target_module, required_dependency, first_source_file.
