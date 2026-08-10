TASK
The current route ownership fallback behavior must be updated. Before editing, identify the application module that is wired into the active runtime, the shared package used by that implementation, and the first source file to inspect.

FIRST-READ CONTEXT
[svc-zephyr-4/src/routes.js]
const policy = require("pkg-harbor-4"); function resolveRoute(input) { return policy.current(input); }

[svc-harbor-4/src/routes.js]
function resolveRoute(input) { return auditOnly(input); }

[pkg-harbor-v1-4/src/ownership.js]
exports.legacy = (input) => applyDeprecatedRouteRule(input);

[notes/route.md]
The previous implementation remains for rollback. UI and audit copies use similar names but are not runtime handlers.

[runtime/wiring.conf]
route=handler:h08|policy:p08|entry:e08
route-previous=handler:hx08|policy:px08|entry:ex08

[runtime/module-aliases.conf]
h08=svc-zephyr-4; hx08=svc-zephyr-legacy-4; w08=web-zephyr-4; a08=svc-harbor-4

[runtime/package-aliases.conf]
p08=pkg-harbor-4; px08=pkg-harbor-v1-4

[runtime/file-aliases.conf]
e08=svc-zephyr-4/src/routes.js; ex08=svc-zephyr-legacy-4/src/routes.js; ew08=web-zephyr-4/src/routes.js; ea08=svc-harbor-4/src/routes.js

[svc-zephyr-legacy-4/src/routes.js]
const policy = require("pkg-harbor-v1-4"); function resolveRoute(input) { return policy.legacy(input); }

[web-zephyr-4/src/routes.js]
function resolveRoute(input) { return renderOnly(input); }

[pkg-harbor-4/src/ownership.js]
exports.current = (input) => applyCurrentRouteRule(input);

Return one JSON object with exactly these keys: target_module, required_dependency, first_source_file.
