TASK
The current avatar normalization behavior must be updated. Before editing, identify the application module that is wired into the active runtime, the shared package used by that implementation, and the first source file to inspect.

FIRST-READ CONTEXT
[pkg-violet-1/src/normalize.js]
exports.current = (input) => applyCurrentMediaRule(input);

[svc-onyx-1/src/avatar.js]
const policy = require("pkg-violet-1"); function normalizeAvatar(input) { return policy.current(input); }

[svc-violet-1/src/avatar.js]
function normalizeAvatar(input) { return auditOnly(input); }

[pkg-violet-v1-1/src/normalize.js]
exports.legacy = (input) => applyDeprecatedMediaRule(input);

[notes/media.md]
The previous implementation remains for rollback. UI and audit copies use similar names but are not runtime handlers.

[runtime/wiring.conf]
media=handler:h21|policy:p21|entry:e21
media-previous=handler:hx21|policy:px21|entry:ex21

[runtime/module-aliases.conf]
h21=svc-onyx-1; hx21=svc-onyx-legacy-1; w21=web-onyx-1; a21=svc-violet-1

[runtime/package-aliases.conf]
p21=pkg-violet-1; px21=pkg-violet-v1-1

[runtime/file-aliases.conf]
e21=svc-onyx-1/src/avatar.js; ex21=svc-onyx-legacy-1/src/avatar.js; ew21=web-onyx-1/src/avatar.js; ea21=svc-violet-1/src/avatar.js

[svc-onyx-legacy-1/src/avatar.js]
const policy = require("pkg-violet-v1-1"); function normalizeAvatar(input) { return policy.legacy(input); }

[web-onyx-1/src/avatar.js]
function normalizeAvatar(input) { return renderOnly(input); }

Return one JSON object with exactly these keys: target_module, required_dependency, first_source_file.
