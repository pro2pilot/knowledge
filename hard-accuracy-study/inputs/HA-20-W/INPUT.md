TASK
The current locale fallback selection behavior must be updated. Before editing, identify the application module that is wired into the active runtime, the shared package used by that implementation, and the first source file to inspect.

FIRST-READ CONTEXT
[runtime/module-aliases.conf]
h20=svc-lumen-4; hx20=svc-lumen-legacy-4; w20=web-lumen-4; a20=svc-sable-4

[runtime/package-aliases.conf]
p20=pkg-sable-4; px20=pkg-sable-v1-4

[runtime/file-aliases.conf]
e20=svc-lumen-4/src/locale.js; ex20=svc-lumen-legacy-4/src/locale.js; ew20=web-lumen-4/src/locale.js; ea20=svc-sable-4/src/locale.js

[svc-lumen-legacy-4/src/locale.js]
const policy = require("pkg-sable-v1-4"); function selectLocale(input) { return policy.legacy(input); }

[web-lumen-4/src/locale.js]
function selectLocale(input) { return renderOnly(input); }

[pkg-sable-4/src/fallback.js]
exports.current = (input) => applyCurrentLocaleRule(input);

[svc-lumen-4/src/locale.js]
const policy = require("pkg-sable-4"); function selectLocale(input) { return policy.current(input); }

[svc-sable-4/src/locale.js]
function selectLocale(input) { return auditOnly(input); }

[pkg-sable-v1-4/src/fallback.js]
exports.legacy = (input) => applyDeprecatedLocaleRule(input);

[notes/locale.md]
The previous implementation remains for rollback. UI and audit copies use similar names but are not runtime handlers.

[runtime/wiring.conf]
locale=handler:h20|policy:p20|entry:e20
locale-previous=handler:hx20|policy:px20|entry:ex20

Return one JSON object with exactly these keys: target_module, required_dependency, first_source_file.
