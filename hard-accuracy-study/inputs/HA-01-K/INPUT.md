TASK
The current retry classification behavior must be updated. Before editing, identify the application module that is wired into the active runtime, the shared package used by that implementation, and the first source file to inspect.

FIRST-READ CONTEXT
[task-route/current]
selected=h01,p01; entry=e01; excluded=hx01,w01,a01,px01

[runtime/module-aliases.conf]
h01=svc-ember-1; hx01=svc-ember-legacy-1; w01=web-ember-1; a01=svc-lumen-1

[runtime/package-aliases.conf]
p01=pkg-lumen-1; px01=pkg-lumen-v1-1

[runtime/file-aliases.conf]
e01=svc-ember-1/src/classify.js; ex01=svc-ember-legacy-1/src/classify.js; ew01=web-ember-1/src/classify.js; ea01=svc-lumen-1/src/classify.js

[svc-ember-1/src/classify.js]
const policy = require("pkg-lumen-1"); function classifyRetry(input) { return policy.current(input); }

[pkg-lumen-1/src/backoff.js]
exports.current = (input) => applyCurrentRetryRule(input);

[svc-ember-legacy-1/src/classify.js]
const policy = require("pkg-lumen-v1-1"); function classifyRetry(input) { return policy.legacy(input); }

Return one JSON object with exactly these keys: target_module, required_dependency, first_source_file.
