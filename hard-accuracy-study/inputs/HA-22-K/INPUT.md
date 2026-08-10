TASK
The current avatar normalization behavior must be updated. Before editing, identify the application module that is wired into the active runtime, the shared package used by that implementation, and the first source file to inspect.

FIRST-READ CONTEXT
[task-route/current]
selected=h22,p22; entry=e22; excluded=hx22,w22,a22,px22

[runtime/module-aliases.conf]
h22=svc-raven-2; hx22=svc-raven-legacy-2; w22=web-raven-2; a22=svc-yarrow-2

[runtime/package-aliases.conf]
p22=pkg-yarrow-2; px22=pkg-yarrow-v1-2

[runtime/file-aliases.conf]
e22=svc-raven-2/src/avatar.js; ex22=svc-raven-legacy-2/src/avatar.js; ew22=web-raven-2/src/avatar.js; ea22=svc-yarrow-2/src/avatar.js

[svc-raven-2/src/avatar.js]
const policy = require("pkg-yarrow-2"); function normalizeAvatar(input) { return policy.current(input); }

[pkg-yarrow-2/src/normalize.js]
exports.current = (input) => applyCurrentMediaRule(input);

[svc-raven-legacy-2/src/avatar.js]
const policy = require("pkg-yarrow-v1-2"); function normalizeAvatar(input) { return policy.legacy(input); }

Return one JSON object with exactly these keys: target_module, required_dependency, first_source_file.
