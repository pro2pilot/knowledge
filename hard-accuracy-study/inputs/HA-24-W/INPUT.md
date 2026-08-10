TASK
The current avatar normalization behavior must be updated. Before editing, identify the application module that is wired into the active runtime, the shared package used by that implementation, and the first source file to inspect.

FIRST-READ CONTEXT
[notes/media.md]
The previous implementation remains for rollback. UI and audit copies use similar names but are not runtime handlers.

[runtime/wiring.conf]
media=handler:h24|policy:p24|entry:e24
media-previous=handler:hx24|policy:px24|entry:ex24

[runtime/module-aliases.conf]
h24=svc-xenon-4; hx24=svc-xenon-legacy-4; w24=web-xenon-4; a24=svc-frost-4

[runtime/package-aliases.conf]
p24=pkg-frost-4; px24=pkg-frost-v1-4

[runtime/file-aliases.conf]
e24=svc-xenon-4/src/avatar.js; ex24=svc-xenon-legacy-4/src/avatar.js; ew24=web-xenon-4/src/avatar.js; ea24=svc-frost-4/src/avatar.js

[svc-xenon-legacy-4/src/avatar.js]
const policy = require("pkg-frost-v1-4"); function normalizeAvatar(input) { return policy.legacy(input); }

[web-xenon-4/src/avatar.js]
function normalizeAvatar(input) { return renderOnly(input); }

[pkg-frost-4/src/normalize.js]
exports.current = (input) => applyCurrentMediaRule(input);

[svc-xenon-4/src/avatar.js]
const policy = require("pkg-frost-4"); function normalizeAvatar(input) { return policy.current(input); }

[svc-frost-4/src/avatar.js]
function normalizeAvatar(input) { return auditOnly(input); }

[pkg-frost-v1-4/src/normalize.js]
exports.legacy = (input) => applyDeprecatedMediaRule(input);

Return one JSON object with exactly these keys: target_module, required_dependency, first_source_file.
