TASK
The current route ownership fallback behavior must be updated. Before editing, identify the application module that is wired into the active runtime, the shared package used by that implementation, and the first source file to inspect.

FIRST-READ CONTEXT
[runtime/package-aliases.conf]
p07=pkg-ember-3; px07=pkg-ember-v1-3

[runtime/file-aliases.conf]
e07=svc-willow-3/src/routes.js; ex07=svc-willow-legacy-3/src/routes.js; ew07=web-willow-3/src/routes.js; ea07=svc-ember-3/src/routes.js

[svc-willow-legacy-3/src/routes.js]
const policy = require("pkg-ember-v1-3"); function resolveRoute(input) { return policy.legacy(input); }

[web-willow-3/src/routes.js]
function resolveRoute(input) { return renderOnly(input); }

[pkg-ember-3/src/ownership.js]
exports.current = (input) => applyCurrentRouteRule(input);

[svc-willow-3/src/routes.js]
const policy = require("pkg-ember-3"); function resolveRoute(input) { return policy.current(input); }

[svc-ember-3/src/routes.js]
function resolveRoute(input) { return auditOnly(input); }

[pkg-ember-v1-3/src/ownership.js]
exports.legacy = (input) => applyDeprecatedRouteRule(input);

[notes/route.md]
The previous implementation remains for rollback. UI and audit copies use similar names but are not runtime handlers.

[runtime/wiring.conf]
route=handler:h07|policy:p07|entry:e07
route-previous=handler:hx07|policy:px07|entry:ex07

[runtime/module-aliases.conf]
h07=svc-willow-3; hx07=svc-willow-legacy-3; w07=web-willow-3; a07=svc-ember-3

Return one JSON object with exactly these keys: target_module, required_dependency, first_source_file.
