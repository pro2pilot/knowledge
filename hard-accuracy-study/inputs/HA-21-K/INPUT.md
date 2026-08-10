TASK
The current avatar normalization behavior must be updated. Before editing, identify the application module that is wired into the active runtime, the shared package used by that implementation, and the first source file to inspect.

FIRST-READ CONTEXT
[task-route/current]
selected=h21,p21; entry=e21; excluded=hx21,w21,a21,px21

[runtime/module-aliases.conf]
h21=svc-onyx-1; hx21=svc-onyx-legacy-1; w21=web-onyx-1; a21=svc-violet-1

[runtime/package-aliases.conf]
p21=pkg-violet-1; px21=pkg-violet-v1-1

[runtime/file-aliases.conf]
e21=svc-onyx-1/src/avatar.js; ex21=svc-onyx-legacy-1/src/avatar.js; ew21=web-onyx-1/src/avatar.js; ea21=svc-violet-1/src/avatar.js

[svc-onyx-1/src/avatar.js]
const policy = require("pkg-violet-1"); function normalizeAvatar(input) { return policy.current(input); }

[pkg-violet-1/src/normalize.js]
exports.current = (input) => applyCurrentMediaRule(input);

[svc-onyx-legacy-1/src/avatar.js]
const policy = require("pkg-violet-v1-1"); function normalizeAvatar(input) { return policy.legacy(input); }

Return one JSON object with exactly these keys: target_module, required_dependency, first_source_file.
