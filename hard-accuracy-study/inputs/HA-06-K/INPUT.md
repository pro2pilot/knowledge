TASK
The current route ownership fallback behavior must be updated. Before editing, identify the application module that is wired into the active runtime, the shared package used by that implementation, and the first source file to inspect.

FIRST-READ CONTEXT
[task-route/current]
selected=h06,p06; entry=e06; excluded=hx06,w06,a06,px06

[runtime/module-aliases.conf]
h06=svc-topaz-2; hx06=svc-topaz-legacy-2; w06=web-topaz-2; a06=svc-amber-2

[runtime/package-aliases.conf]
p06=pkg-amber-2; px06=pkg-amber-v1-2

[runtime/file-aliases.conf]
e06=svc-topaz-2/src/routes.js; ex06=svc-topaz-legacy-2/src/routes.js; ew06=web-topaz-2/src/routes.js; ea06=svc-amber-2/src/routes.js

[svc-topaz-2/src/routes.js]
const policy = require("pkg-amber-2"); function resolveRoute(input) { return policy.current(input); }

[pkg-amber-2/src/ownership.js]
exports.current = (input) => applyCurrentRouteRule(input);

[svc-topaz-legacy-2/src/routes.js]
const policy = require("pkg-amber-v1-2"); function resolveRoute(input) { return policy.legacy(input); }

Return one JSON object with exactly these keys: target_module, required_dependency, first_source_file.
