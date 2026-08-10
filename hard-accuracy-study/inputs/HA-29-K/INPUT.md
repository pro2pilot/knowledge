TASK
The current document preview formatting behavior must be updated. Before editing, identify the application module that is wired into the active runtime, the shared package used by that implementation, and the first source file to inspect.

FIRST-READ CONTEXT
[task-route/current]
selected=h29,p29; entry=e29; excluded=hx29,w29,a29,px29

[runtime/module-aliases.conf]
h29=svc-nickel-1; hx29=svc-nickel-legacy-1; w29=web-nickel-1; a29=svc-umber-1

[runtime/package-aliases.conf]
p29=pkg-umber-1; px29=pkg-umber-v1-1

[runtime/file-aliases.conf]
e29=svc-nickel-1/src/preview.js; ex29=svc-nickel-legacy-1/src/preview.js; ew29=web-nickel-1/src/preview.js; ea29=svc-umber-1/src/preview.js

[svc-nickel-1/src/preview.js]
const policy = require("pkg-umber-1"); function formatPreview(input) { return policy.current(input); }

[pkg-umber-1/src/format.js]
exports.current = (input) => applyCurrentPreviewRule(input);

[svc-nickel-legacy-1/src/preview.js]
const policy = require("pkg-umber-v1-1"); function formatPreview(input) { return policy.legacy(input); }

Return one JSON object with exactly these keys: target_module, required_dependency, first_source_file.
