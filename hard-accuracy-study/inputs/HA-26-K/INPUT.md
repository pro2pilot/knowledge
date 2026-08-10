TASK
The current analytics consent filtering behavior must be updated. Before editing, identify the application module that is wired into the active runtime, the shared package used by that implementation, and the first source file to inspect.

FIRST-READ CONTEXT
[task-route/current]
selected=h26,p26; entry=e26; excluded=hx26,w26,a26,px26

[runtime/module-aliases.conf]
h26=svc-ember-2; hx26=svc-ember-legacy-2; w26=web-ember-2; a26=svc-lumen-2

[runtime/package-aliases.conf]
p26=pkg-lumen-2; px26=pkg-lumen-v1-2

[runtime/file-aliases.conf]
e26=svc-ember-2/src/filter.js; ex26=svc-ember-legacy-2/src/filter.js; ew26=web-ember-2/src/filter.js; ea26=svc-lumen-2/src/filter.js

[svc-ember-2/src/filter.js]
const policy = require("pkg-lumen-2"); function filterConsent(input) { return policy.current(input); }

[pkg-lumen-2/src/rules.js]
exports.current = (input) => applyCurrentConsentRule(input);

[svc-ember-legacy-2/src/filter.js]
const policy = require("pkg-lumen-v1-2"); function filterConsent(input) { return policy.legacy(input); }

Return one JSON object with exactly these keys: target_module, required_dependency, first_source_file.
