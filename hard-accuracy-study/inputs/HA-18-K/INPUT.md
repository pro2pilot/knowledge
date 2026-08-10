TASK
The current locale fallback selection behavior must be updated. Before editing, identify the application module that is wired into the active runtime, the shared package used by that implementation, and the first source file to inspect.

FIRST-READ CONTEXT
[task-route/current]
selected=h18,p18; entry=e18; excluded=hx18,w18,a18,px18

[runtime/module-aliases.conf]
h18=svc-frost-2; hx18=svc-frost-legacy-2; w18=web-frost-2; a18=svc-mango-2

[runtime/package-aliases.conf]
p18=pkg-mango-2; px18=pkg-mango-v1-2

[runtime/file-aliases.conf]
e18=svc-frost-2/src/locale.js; ex18=svc-frost-legacy-2/src/locale.js; ew18=web-frost-2/src/locale.js; ea18=svc-mango-2/src/locale.js

[svc-frost-2/src/locale.js]
const policy = require("pkg-mango-2"); function selectLocale(input) { return policy.current(input); }

[pkg-mango-2/src/fallback.js]
exports.current = (input) => applyCurrentLocaleRule(input);

[svc-frost-legacy-2/src/locale.js]
const policy = require("pkg-mango-v1-2"); function selectLocale(input) { return policy.legacy(input); }

Return one JSON object with exactly these keys: target_module, required_dependency, first_source_file.
