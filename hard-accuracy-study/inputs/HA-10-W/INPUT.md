TASK
The current invoice total rounding behavior must be updated. Before editing, identify the application module that is wired into the active runtime, the shared package used by that implementation, and the first source file to inspect.

FIRST-READ CONTEXT
[pkg-nickel-2/src/rounding.js]
exports.current = (input) => applyCurrentPricingRule(input);

[svc-garnet-2/src/total.js]
const policy = require("pkg-nickel-2"); function computeTotal(input) { return policy.current(input); }

[svc-nickel-2/src/total.js]
function computeTotal(input) { return auditOnly(input); }

[pkg-nickel-v1-2/src/rounding.js]
exports.legacy = (input) => applyDeprecatedPricingRule(input);

[notes/pricing.md]
The previous implementation remains for rollback. UI and audit copies use similar names but are not runtime handlers.

[runtime/wiring.conf]
pricing=handler:h10|policy:p10|entry:e10
pricing-previous=handler:hx10|policy:px10|entry:ex10

[runtime/module-aliases.conf]
h10=svc-garnet-2; hx10=svc-garnet-legacy-2; w10=web-garnet-2; a10=svc-nickel-2

[runtime/package-aliases.conf]
p10=pkg-nickel-2; px10=pkg-nickel-v1-2

[runtime/file-aliases.conf]
e10=svc-garnet-2/src/total.js; ex10=svc-garnet-legacy-2/src/total.js; ew10=web-garnet-2/src/total.js; ea10=svc-nickel-2/src/total.js

[svc-garnet-legacy-2/src/total.js]
const policy = require("pkg-nickel-v1-2"); function computeTotal(input) { return policy.legacy(input); }

[web-garnet-2/src/total.js]
function computeTotal(input) { return renderOnly(input); }

Return one JSON object with exactly these keys: target_module, required_dependency, first_source_file.
