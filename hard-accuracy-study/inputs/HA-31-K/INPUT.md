TASK
The current document preview formatting behavior must be updated. Before editing, identify the application module that is wired into the active runtime, the shared package used by that implementation, and the first source file to inspect.

FIRST-READ CONTEXT
[task-route/current]
selected=h31,p31; entry=e31; excluded=hx31,w31,a31,px31

[runtime/module-aliases.conf]
h31=svc-topaz-3; hx31=svc-topaz-legacy-3; w31=web-topaz-3; a31=svc-amber-3

[runtime/package-aliases.conf]
p31=pkg-amber-3; px31=pkg-amber-v1-3

[runtime/file-aliases.conf]
e31=svc-topaz-3/src/preview.js; ex31=svc-topaz-legacy-3/src/preview.js; ew31=web-topaz-3/src/preview.js; ea31=svc-amber-3/src/preview.js

[svc-topaz-3/src/preview.js]
const policy = require("pkg-amber-3"); function formatPreview(input) { return policy.current(input); }

[pkg-amber-3/src/format.js]
exports.current = (input) => applyCurrentPreviewRule(input);

[svc-topaz-legacy-3/src/preview.js]
const policy = require("pkg-amber-v1-3"); function formatPreview(input) { return policy.legacy(input); }

Return one JSON object with exactly these keys: target_module, required_dependency, first_source_file.
