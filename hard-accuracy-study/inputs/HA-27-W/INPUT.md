TASK
The current analytics consent filtering behavior must be updated. Before editing, identify the application module that is wired into the active runtime, the shared package used by that implementation, and the first source file to inspect.

FIRST-READ CONTEXT
[runtime/file-aliases.conf]
e27=svc-harbor-3/src/filter.js; ex27=svc-harbor-legacy-3/src/filter.js; ew27=web-harbor-3/src/filter.js; ea27=svc-onyx-3/src/filter.js

[svc-harbor-legacy-3/src/filter.js]
const policy = require("pkg-onyx-v1-3"); function filterConsent(input) { return policy.legacy(input); }

[web-harbor-3/src/filter.js]
function filterConsent(input) { return renderOnly(input); }

[pkg-onyx-3/src/rules.js]
exports.current = (input) => applyCurrentConsentRule(input);

[svc-harbor-3/src/filter.js]
const policy = require("pkg-onyx-3"); function filterConsent(input) { return policy.current(input); }

[svc-onyx-3/src/filter.js]
function filterConsent(input) { return auditOnly(input); }

[pkg-onyx-v1-3/src/rules.js]
exports.legacy = (input) => applyDeprecatedConsentRule(input);

[notes/consent.md]
The previous implementation remains for rollback. UI and audit copies use similar names but are not runtime handlers.

[runtime/wiring.conf]
consent=handler:h27|policy:p27|entry:e27
consent-previous=handler:hx27|policy:px27|entry:ex27

[runtime/module-aliases.conf]
h27=svc-harbor-3; hx27=svc-harbor-legacy-3; w27=web-harbor-3; a27=svc-onyx-3

[runtime/package-aliases.conf]
p27=pkg-onyx-3; px27=pkg-onyx-v1-3

Return one JSON object with exactly these keys: target_module, required_dependency, first_source_file.
