TASK
The current locale fallback selection behavior must be updated. Before editing, identify the application module that is wired into the active runtime, the shared package used by that implementation, and the first source file to inspect.

FIRST-READ CONTEXT
[task-route/current]
selected=h17,p17; entry=e17; excluded=hx17,w17,a17,px17

[runtime/module-aliases.conf]
h17=svc-cobalt-1; hx17=svc-cobalt-legacy-1; w17=web-cobalt-1; a17=svc-juniper-1

[runtime/package-aliases.conf]
p17=pkg-juniper-1; px17=pkg-juniper-v1-1

[runtime/file-aliases.conf]
e17=svc-cobalt-1/src/locale.js; ex17=svc-cobalt-legacy-1/src/locale.js; ew17=web-cobalt-1/src/locale.js; ea17=svc-juniper-1/src/locale.js

[svc-cobalt-1/src/locale.js]
const policy = require("pkg-juniper-1"); function selectLocale(input) { return policy.current(input); }

[pkg-juniper-1/src/fallback.js]
exports.current = (input) => applyCurrentLocaleRule(input);

[svc-cobalt-legacy-1/src/locale.js]
const policy = require("pkg-juniper-v1-1"); function selectLocale(input) { return policy.legacy(input); }

Return one JSON object with exactly these keys: target_module, required_dependency, first_source_file.
