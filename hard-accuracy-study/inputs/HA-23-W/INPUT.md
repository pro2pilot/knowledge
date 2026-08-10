TASK
The current avatar normalization behavior must be updated. Before editing, identify the application module that is wired into the active runtime, the shared package used by that implementation, and the first source file to inspect.

FIRST-READ CONTEXT
[web-umber-3/src/avatar.js]
function normalizeAvatar(input) { return renderOnly(input); }

[pkg-cobalt-3/src/normalize.js]
exports.current = (input) => applyCurrentMediaRule(input);

[svc-umber-3/src/avatar.js]
const policy = require("pkg-cobalt-3"); function normalizeAvatar(input) { return policy.current(input); }

[svc-cobalt-3/src/avatar.js]
function normalizeAvatar(input) { return auditOnly(input); }

[pkg-cobalt-v1-3/src/normalize.js]
exports.legacy = (input) => applyDeprecatedMediaRule(input);

[notes/media.md]
The previous implementation remains for rollback. UI and audit copies use similar names but are not runtime handlers.

[runtime/wiring.conf]
media=handler:h23|policy:p23|entry:e23
media-previous=handler:hx23|policy:px23|entry:ex23

[runtime/module-aliases.conf]
h23=svc-umber-3; hx23=svc-umber-legacy-3; w23=web-umber-3; a23=svc-cobalt-3

[runtime/package-aliases.conf]
p23=pkg-cobalt-3; px23=pkg-cobalt-v1-3

[runtime/file-aliases.conf]
e23=svc-umber-3/src/avatar.js; ex23=svc-umber-legacy-3/src/avatar.js; ew23=web-umber-3/src/avatar.js; ea23=svc-cobalt-3/src/avatar.js

[svc-umber-legacy-3/src/avatar.js]
const policy = require("pkg-cobalt-v1-3"); function normalizeAvatar(input) { return policy.legacy(input); }

Return one JSON object with exactly these keys: target_module, required_dependency, first_source_file.
