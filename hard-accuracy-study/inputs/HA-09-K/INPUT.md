TASK
The current invoice total rounding behavior must be updated. Before editing, identify the application module that is wired into the active runtime, the shared package used by that implementation, and the first source file to inspect.

FIRST-READ CONTEXT
[task-route/current]
selected=h09,p09; entry=e09; excluded=hx09,w09,a09,px09

[runtime/module-aliases.conf]
h09=svc-delta-1; hx09=svc-delta-legacy-1; w09=web-delta-1; a09=svc-kestrel-1

[runtime/package-aliases.conf]
p09=pkg-kestrel-1; px09=pkg-kestrel-v1-1

[runtime/file-aliases.conf]
e09=svc-delta-1/src/total.js; ex09=svc-delta-legacy-1/src/total.js; ew09=web-delta-1/src/total.js; ea09=svc-kestrel-1/src/total.js

[svc-delta-1/src/total.js]
const policy = require("pkg-kestrel-1"); function computeTotal(input) { return policy.current(input); }

[pkg-kestrel-1/src/rounding.js]
exports.current = (input) => applyCurrentPricingRule(input);

[svc-delta-legacy-1/src/total.js]
const policy = require("pkg-kestrel-v1-1"); function computeTotal(input) { return policy.legacy(input); }

Return one JSON object with exactly these keys: target_module, required_dependency, first_source_file.
