TASK
The current avatar normalization behavior must be updated. Before editing, identify the application module that is wired into the active runtime, the shared package used by that implementation, and the first source file to inspect.

FIRST-READ CONTEXT
[task-route/current]
selected=h23,p23; entry=e23; excluded=hx23,w23,a23,px23

[runtime/module-aliases.conf]
h23=svc-umber-3; hx23=svc-umber-legacy-3; w23=web-umber-3; a23=svc-cobalt-3

[runtime/package-aliases.conf]
p23=pkg-cobalt-3; px23=pkg-cobalt-v1-3

[runtime/file-aliases.conf]
e23=svc-umber-3/src/avatar.js; ex23=svc-umber-legacy-3/src/avatar.js; ew23=web-umber-3/src/avatar.js; ea23=svc-cobalt-3/src/avatar.js

[svc-umber-3/src/avatar.js]
const policy = require("pkg-cobalt-3"); function normalizeAvatar(input) { return policy.current(input); }

[pkg-cobalt-3/src/normalize.js]
exports.current = (input) => applyCurrentMediaRule(input);

[svc-umber-legacy-3/src/avatar.js]
const policy = require("pkg-cobalt-v1-3"); function normalizeAvatar(input) { return policy.legacy(input); }

Return one JSON object with exactly these keys: target_module, required_dependency, first_source_file.
