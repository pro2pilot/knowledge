TASK
The current invoice total rounding behavior must be updated. Before editing, identify the application module that is wired into the active runtime, the shared package used by that implementation, and the first source file to inspect.

FIRST-READ CONTEXT
[runtime/wiring.conf]
pricing=handler:h11|policy:p11|entry:e11
pricing-previous=handler:hx11|policy:px11|entry:ex11

[runtime/module-aliases.conf]
h11=svc-juniper-3; hx11=svc-juniper-legacy-3; w11=web-juniper-3; a11=svc-quartz-3

[runtime/package-aliases.conf]
p11=pkg-quartz-3; px11=pkg-quartz-v1-3

[runtime/file-aliases.conf]
e11=svc-juniper-3/src/total.js; ex11=svc-juniper-legacy-3/src/total.js; ew11=web-juniper-3/src/total.js; ea11=svc-quartz-3/src/total.js

[svc-juniper-legacy-3/src/total.js]
const policy = require("pkg-quartz-v1-3"); function computeTotal(input) { return policy.legacy(input); }

[web-juniper-3/src/total.js]
function computeTotal(input) { return renderOnly(input); }

[pkg-quartz-3/src/rounding.js]
exports.current = (input) => applyCurrentPricingRule(input);

[svc-juniper-3/src/total.js]
const policy = require("pkg-quartz-3"); function computeTotal(input) { return policy.current(input); }

[svc-quartz-3/src/total.js]
function computeTotal(input) { return auditOnly(input); }

[pkg-quartz-v1-3/src/rounding.js]
exports.legacy = (input) => applyDeprecatedPricingRule(input);

[notes/pricing.md]
The previous implementation remains for rollback. UI and audit copies use similar names but are not runtime handlers.

Return one JSON object with exactly these keys: target_module, required_dependency, first_source_file.
