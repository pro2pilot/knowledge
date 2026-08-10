TASK
The current locale fallback selection behavior must be updated. Before editing, identify the application module that is wired into the active runtime, the shared package used by that implementation, and the first source file to inspect.

FIRST-READ CONTEXT
[svc-juniper-1/src/locale.js]
function selectLocale(input) { return auditOnly(input); }

[pkg-juniper-v1-1/src/fallback.js]
exports.legacy = (input) => applyDeprecatedLocaleRule(input);

[notes/locale.md]
The previous implementation remains for rollback. UI and audit copies use similar names but are not runtime handlers.

[runtime/wiring.conf]
locale=handler:h17|policy:p17|entry:e17
locale-previous=handler:hx17|policy:px17|entry:ex17

[runtime/module-aliases.conf]
h17=svc-cobalt-1; hx17=svc-cobalt-legacy-1; w17=web-cobalt-1; a17=svc-juniper-1

[runtime/package-aliases.conf]
p17=pkg-juniper-1; px17=pkg-juniper-v1-1

[runtime/file-aliases.conf]
e17=svc-cobalt-1/src/locale.js; ex17=svc-cobalt-legacy-1/src/locale.js; ew17=web-cobalt-1/src/locale.js; ea17=svc-juniper-1/src/locale.js

[svc-cobalt-legacy-1/src/locale.js]
const policy = require("pkg-juniper-v1-1"); function selectLocale(input) { return policy.legacy(input); }

[web-cobalt-1/src/locale.js]
function selectLocale(input) { return renderOnly(input); }

[pkg-juniper-1/src/fallback.js]
exports.current = (input) => applyCurrentLocaleRule(input);

[svc-cobalt-1/src/locale.js]
const policy = require("pkg-juniper-1"); function selectLocale(input) { return policy.current(input); }

Return one JSON object with exactly these keys: target_module, required_dependency, first_source_file.
