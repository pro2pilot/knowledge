TASK
The current document preview formatting behavior must be updated. Before editing, identify the application module that is wired into the active runtime, the shared package used by that implementation, and the first source file to inspect.

FIRST-READ CONTEXT
[task-route/current]
selected=h32,p32; entry=e32; excluded=hx32,w32,a32,px32

[runtime/module-aliases.conf]
h32=svc-willow-4; hx32=svc-willow-legacy-4; w32=web-willow-4; a32=svc-ember-4

[runtime/package-aliases.conf]
p32=pkg-ember-4; px32=pkg-ember-v1-4

[runtime/file-aliases.conf]
e32=svc-willow-4/src/preview.js; ex32=svc-willow-legacy-4/src/preview.js; ew32=web-willow-4/src/preview.js; ea32=svc-ember-4/src/preview.js

[svc-willow-4/src/preview.js]
const policy = require("pkg-ember-4"); function formatPreview(input) { return policy.current(input); }

[pkg-ember-4/src/format.js]
exports.current = (input) => applyCurrentPreviewRule(input);

[svc-willow-legacy-4/src/preview.js]
const policy = require("pkg-ember-v1-4"); function formatPreview(input) { return policy.legacy(input); }

Return one JSON object with exactly these keys: target_module, required_dependency, first_source_file.
