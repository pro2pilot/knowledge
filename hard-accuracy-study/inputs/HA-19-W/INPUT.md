TASK
The current locale fallback selection behavior must be updated. Before editing, identify the application module that is wired into the active runtime, the shared package used by that implementation, and the first source file to inspect.

FIRST-READ CONTEXT
[svc-indigo-3/src/locale.js]
const policy = require("pkg-pearl-3"); function selectLocale(input) { return policy.current(input); }

[svc-pearl-3/src/locale.js]
function selectLocale(input) { return auditOnly(input); }

[pkg-pearl-v1-3/src/fallback.js]
exports.legacy = (input) => applyDeprecatedLocaleRule(input);

[notes/locale.md]
The previous implementation remains for rollback. UI and audit copies use similar names but are not runtime handlers.

[runtime/wiring.conf]
locale=handler:h19|policy:p19|entry:e19
locale-previous=handler:hx19|policy:px19|entry:ex19

[runtime/module-aliases.conf]
h19=svc-indigo-3; hx19=svc-indigo-legacy-3; w19=web-indigo-3; a19=svc-pearl-3

[runtime/package-aliases.conf]
p19=pkg-pearl-3; px19=pkg-pearl-v1-3

[runtime/file-aliases.conf]
e19=svc-indigo-3/src/locale.js; ex19=svc-indigo-legacy-3/src/locale.js; ew19=web-indigo-3/src/locale.js; ea19=svc-pearl-3/src/locale.js

[svc-indigo-legacy-3/src/locale.js]
const policy = require("pkg-pearl-v1-3"); function selectLocale(input) { return policy.legacy(input); }

[web-indigo-3/src/locale.js]
function selectLocale(input) { return renderOnly(input); }

[pkg-pearl-3/src/fallback.js]
exports.current = (input) => applyCurrentLocaleRule(input);

Return one JSON object with exactly these keys: target_module, required_dependency, first_source_file.
