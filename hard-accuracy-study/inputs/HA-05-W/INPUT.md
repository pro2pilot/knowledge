TASK
The current route ownership fallback behavior must be updated. Before editing, identify the application module that is wired into the active runtime, the shared package used by that implementation, and the first source file to inspect.

FIRST-READ CONTEXT
[runtime/file-aliases.conf]
e05=svc-quartz-1/src/routes.js; ex05=svc-quartz-legacy-1/src/routes.js; ew05=web-quartz-1/src/routes.js; ea05=svc-xenon-1/src/routes.js

[svc-quartz-legacy-1/src/routes.js]
const policy = require("pkg-xenon-v1-1"); function resolveRoute(input) { return policy.legacy(input); }

[web-quartz-1/src/routes.js]
function resolveRoute(input) { return renderOnly(input); }

[pkg-xenon-1/src/ownership.js]
exports.current = (input) => applyCurrentRouteRule(input);

[svc-quartz-1/src/routes.js]
const policy = require("pkg-xenon-1"); function resolveRoute(input) { return policy.current(input); }

[svc-xenon-1/src/routes.js]
function resolveRoute(input) { return auditOnly(input); }

[pkg-xenon-v1-1/src/ownership.js]
exports.legacy = (input) => applyDeprecatedRouteRule(input);

[notes/route.md]
The previous implementation remains for rollback. UI and audit copies use similar names but are not runtime handlers.

[runtime/wiring.conf]
route=handler:h05|policy:p05|entry:e05
route-previous=handler:hx05|policy:px05|entry:ex05

[runtime/module-aliases.conf]
h05=svc-quartz-1; hx05=svc-quartz-legacy-1; w05=web-quartz-1; a05=svc-xenon-1

[runtime/package-aliases.conf]
p05=pkg-xenon-1; px05=pkg-xenon-v1-1

Return one JSON object with exactly these keys: target_module, required_dependency, first_source_file.
