TASK
The current retry classification behavior must be updated. Before editing, identify the application module that is wired into the active runtime, the shared package used by that implementation, and the first source file to inspect.

FIRST-READ CONTEXT
[web-ember-1/src/classify.js]
function classifyRetry(input) { return renderOnly(input); }

[pkg-lumen-1/src/backoff.js]
exports.current = (input) => applyCurrentRetryRule(input);

[svc-ember-1/src/classify.js]
const policy = require("pkg-lumen-1"); function classifyRetry(input) { return policy.current(input); }

[svc-lumen-1/src/classify.js]
function classifyRetry(input) { return auditOnly(input); }

[pkg-lumen-v1-1/src/backoff.js]
exports.legacy = (input) => applyDeprecatedRetryRule(input);

[notes/retry.md]
The previous implementation remains for rollback. UI and audit copies use similar names but are not runtime handlers.

[runtime/wiring.conf]
retry=handler:h01|policy:p01|entry:e01
retry-previous=handler:hx01|policy:px01|entry:ex01

[runtime/module-aliases.conf]
h01=svc-ember-1; hx01=svc-ember-legacy-1; w01=web-ember-1; a01=svc-lumen-1

[runtime/package-aliases.conf]
p01=pkg-lumen-1; px01=pkg-lumen-v1-1

[runtime/file-aliases.conf]
e01=svc-ember-1/src/classify.js; ex01=svc-ember-legacy-1/src/classify.js; ew01=web-ember-1/src/classify.js; ea01=svc-lumen-1/src/classify.js

[svc-ember-legacy-1/src/classify.js]
const policy = require("pkg-lumen-v1-1"); function classifyRetry(input) { return policy.legacy(input); }

Return one JSON object with exactly these keys: target_module, required_dependency, first_source_file.
