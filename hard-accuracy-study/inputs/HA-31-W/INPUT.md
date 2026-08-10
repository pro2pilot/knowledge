TASK
The current document preview formatting behavior must be updated. Before editing, identify the application module that is wired into the active runtime, the shared package used by that implementation, and the first source file to inspect.

FIRST-READ CONTEXT
[runtime/module-aliases.conf]
h31=svc-topaz-3; hx31=svc-topaz-legacy-3; w31=web-topaz-3; a31=svc-amber-3

[runtime/package-aliases.conf]
p31=pkg-amber-3; px31=pkg-amber-v1-3

[runtime/file-aliases.conf]
e31=svc-topaz-3/src/preview.js; ex31=svc-topaz-legacy-3/src/preview.js; ew31=web-topaz-3/src/preview.js; ea31=svc-amber-3/src/preview.js

[svc-topaz-legacy-3/src/preview.js]
const policy = require("pkg-amber-v1-3"); function formatPreview(input) { return policy.legacy(input); }

[web-topaz-3/src/preview.js]
function formatPreview(input) { return renderOnly(input); }

[pkg-amber-3/src/format.js]
exports.current = (input) => applyCurrentPreviewRule(input);

[svc-topaz-3/src/preview.js]
const policy = require("pkg-amber-3"); function formatPreview(input) { return policy.current(input); }

[svc-amber-3/src/preview.js]
function formatPreview(input) { return auditOnly(input); }

[pkg-amber-v1-3/src/format.js]
exports.legacy = (input) => applyDeprecatedPreviewRule(input);

[notes/preview.md]
The previous implementation remains for rollback. UI and audit copies use similar names but are not runtime handlers.

[runtime/wiring.conf]
preview=handler:h31|policy:p31|entry:e31
preview-previous=handler:hx31|policy:px31|entry:ex31

Return one JSON object with exactly these keys: target_module, required_dependency, first_source_file.
