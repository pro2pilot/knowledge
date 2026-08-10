TASK
The current invoice total rounding behavior must be updated. Before editing, identify the application module that is wired into the active runtime, the shared package used by that implementation, and the first source file to inspect.

FIRST-READ CONTEXT
[task-route/current]
selected=h11,p11; entry=e11; excluded=hx11,w11,a11,px11

[runtime/module-aliases.conf]
h11=svc-juniper-3; hx11=svc-juniper-legacy-3; w11=web-juniper-3; a11=svc-quartz-3

[runtime/package-aliases.conf]
p11=pkg-quartz-3; px11=pkg-quartz-v1-3

[runtime/file-aliases.conf]
e11=svc-juniper-3/src/total.js; ex11=svc-juniper-legacy-3/src/total.js; ew11=web-juniper-3/src/total.js; ea11=svc-quartz-3/src/total.js

[svc-juniper-3/src/total.js]
const policy = require("pkg-quartz-3"); function computeTotal(input) { return policy.current(input); }

[pkg-quartz-3/src/rounding.js]
exports.current = (input) => applyCurrentPricingRule(input);

[svc-juniper-legacy-3/src/total.js]
const policy = require("pkg-quartz-v1-3"); function computeTotal(input) { return policy.legacy(input); }

Return one JSON object with exactly these keys: target_module, required_dependency, first_source_file.
