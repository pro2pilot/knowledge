TASK
The current locale fallback selection behavior must be updated. Before editing, identify the application module that is wired into the active runtime, the shared package used by that implementation, and the first source file to inspect.

FIRST-READ CONTEXT
[task-route/current]
selected=h19,p19; entry=e19; excluded=hx19,w19,a19,px19

[runtime/module-aliases.conf]
h19=svc-indigo-3; hx19=svc-indigo-legacy-3; w19=web-indigo-3; a19=svc-pearl-3

[runtime/package-aliases.conf]
p19=pkg-pearl-3; px19=pkg-pearl-v1-3

[runtime/file-aliases.conf]
e19=svc-indigo-3/src/locale.js; ex19=svc-indigo-legacy-3/src/locale.js; ew19=web-indigo-3/src/locale.js; ea19=svc-pearl-3/src/locale.js

[svc-indigo-3/src/locale.js]
const policy = require("pkg-pearl-3"); function selectLocale(input) { return policy.current(input); }

[pkg-pearl-3/src/fallback.js]
exports.current = (input) => applyCurrentLocaleRule(input);

[svc-indigo-legacy-3/src/locale.js]
const policy = require("pkg-pearl-v1-3"); function selectLocale(input) { return policy.legacy(input); }

Return one JSON object with exactly these keys: target_module, required_dependency, first_source_file.
