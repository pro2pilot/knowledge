TASK
The current document preview formatting behavior must be updated. Before editing, identify the application module that is wired into the active runtime, the shared package used by that implementation, and the first source file to inspect.

FIRST-READ CONTEXT
[task-route/current]
selected=h30,p30; entry=e30; excluded=hx30,w30,a30,px30

[runtime/module-aliases.conf]
h30=svc-quartz-2; hx30=svc-quartz-legacy-2; w30=web-quartz-2; a30=svc-xenon-2

[runtime/package-aliases.conf]
p30=pkg-xenon-2; px30=pkg-xenon-v1-2

[runtime/file-aliases.conf]
e30=svc-quartz-2/src/preview.js; ex30=svc-quartz-legacy-2/src/preview.js; ew30=web-quartz-2/src/preview.js; ea30=svc-xenon-2/src/preview.js

[svc-quartz-2/src/preview.js]
const policy = require("pkg-xenon-2"); function formatPreview(input) { return policy.current(input); }

[pkg-xenon-2/src/format.js]
exports.current = (input) => applyCurrentPreviewRule(input);

[svc-quartz-legacy-2/src/preview.js]
const policy = require("pkg-xenon-v1-2"); function formatPreview(input) { return policy.legacy(input); }

Return one JSON object with exactly these keys: target_module, required_dependency, first_source_file.
