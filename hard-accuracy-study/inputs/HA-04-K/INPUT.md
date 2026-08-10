TASK
The current retry classification behavior must be updated. Before editing, identify the application module that is wired into the active runtime, the shared package used by that implementation, and the first source file to inspect.

FIRST-READ CONTEXT
[task-route/current]
selected=h04,p04; entry=e04; excluded=hx04,w04,a04,px04

[runtime/module-aliases.conf]
h04=svc-nickel-4; hx04=svc-nickel-legacy-4; w04=web-nickel-4; a04=svc-umber-4

[runtime/package-aliases.conf]
p04=pkg-umber-4; px04=pkg-umber-v1-4

[runtime/file-aliases.conf]
e04=svc-nickel-4/src/classify.js; ex04=svc-nickel-legacy-4/src/classify.js; ew04=web-nickel-4/src/classify.js; ea04=svc-umber-4/src/classify.js

[svc-nickel-4/src/classify.js]
const policy = require("pkg-umber-4"); function classifyRetry(input) { return policy.current(input); }

[pkg-umber-4/src/backoff.js]
exports.current = (input) => applyCurrentRetryRule(input);

[svc-nickel-legacy-4/src/classify.js]
const policy = require("pkg-umber-v1-4"); function classifyRetry(input) { return policy.legacy(input); }

Return one JSON object with exactly these keys: target_module, required_dependency, first_source_file.
