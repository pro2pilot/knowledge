TASK
The current avatar normalization behavior must be updated. Before editing, identify the application module that is wired into the active runtime, the shared package used by that implementation, and the first source file to inspect.

FIRST-READ CONTEXT
[task-route/current]
selected=h24,p24; entry=e24; excluded=hx24,w24,a24,px24

[runtime/module-aliases.conf]
h24=svc-xenon-4; hx24=svc-xenon-legacy-4; w24=web-xenon-4; a24=svc-frost-4

[runtime/package-aliases.conf]
p24=pkg-frost-4; px24=pkg-frost-v1-4

[runtime/file-aliases.conf]
e24=svc-xenon-4/src/avatar.js; ex24=svc-xenon-legacy-4/src/avatar.js; ew24=web-xenon-4/src/avatar.js; ea24=svc-frost-4/src/avatar.js

[svc-xenon-4/src/avatar.js]
const policy = require("pkg-frost-4"); function normalizeAvatar(input) { return policy.current(input); }

[pkg-frost-4/src/normalize.js]
exports.current = (input) => applyCurrentMediaRule(input);

[svc-xenon-legacy-4/src/avatar.js]
const policy = require("pkg-frost-v1-4"); function normalizeAvatar(input) { return policy.legacy(input); }

Return one JSON object with exactly these keys: target_module, required_dependency, first_source_file.
