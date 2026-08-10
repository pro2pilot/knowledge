TASK
The current invoice total rounding behavior must be updated. Before editing, identify the application module that is wired into the active runtime, the shared package used by that implementation, and the first source file to inspect.

FIRST-READ CONTEXT
[web-mango-4/src/total.js]
function computeTotal(input) { return renderOnly(input); }

[pkg-topaz-4/src/rounding.js]
exports.current = (input) => applyCurrentPricingRule(input);

[svc-mango-4/src/total.js]
const policy = require("pkg-topaz-4"); function computeTotal(input) { return policy.current(input); }

[svc-topaz-4/src/total.js]
function computeTotal(input) { return auditOnly(input); }

[pkg-topaz-v1-4/src/rounding.js]
exports.legacy = (input) => applyDeprecatedPricingRule(input);

[notes/pricing.md]
The previous implementation remains for rollback. UI and audit copies use similar names but are not runtime handlers.

[runtime/wiring.conf]
pricing=handler:h12|policy:p12|entry:e12
pricing-previous=handler:hx12|policy:px12|entry:ex12

[runtime/module-aliases.conf]
h12=svc-mango-4; hx12=svc-mango-legacy-4; w12=web-mango-4; a12=svc-topaz-4

[runtime/package-aliases.conf]
p12=pkg-topaz-4; px12=pkg-topaz-v1-4

[runtime/file-aliases.conf]
e12=svc-mango-4/src/total.js; ex12=svc-mango-legacy-4/src/total.js; ew12=web-mango-4/src/total.js; ea12=svc-topaz-4/src/total.js

[svc-mango-legacy-4/src/total.js]
const policy = require("pkg-topaz-v1-4"); function computeTotal(input) { return policy.legacy(input); }

Return one JSON object with exactly these keys: target_module, required_dependency, first_source_file.
