TASK
The current retry classification behavior must be updated. Before editing, identify the application module that is wired into the active runtime, the shared package used by that implementation, and the first source file to inspect.

FIRST-READ CONTEXT
[svc-kestrel-legacy-3/src/classify.js]
const policy = require("pkg-raven-v1-3"); function classifyRetry(input) { return policy.legacy(input); }

[web-kestrel-3/src/classify.js]
function classifyRetry(input) { return renderOnly(input); }

[pkg-raven-3/src/backoff.js]
exports.current = (input) => applyCurrentRetryRule(input);

[svc-kestrel-3/src/classify.js]
const policy = require("pkg-raven-3"); function classifyRetry(input) { return policy.current(input); }

[svc-raven-3/src/classify.js]
function classifyRetry(input) { return auditOnly(input); }

[pkg-raven-v1-3/src/backoff.js]
exports.legacy = (input) => applyDeprecatedRetryRule(input);

[notes/retry.md]
The previous implementation remains for rollback. UI and audit copies use similar names but are not runtime handlers.

[runtime/wiring.conf]
retry=handler:h03|policy:p03|entry:e03
retry-previous=handler:hx03|policy:px03|entry:ex03

[runtime/module-aliases.conf]
h03=svc-kestrel-3; hx03=svc-kestrel-legacy-3; w03=web-kestrel-3; a03=svc-raven-3

[runtime/package-aliases.conf]
p03=pkg-raven-3; px03=pkg-raven-v1-3

[runtime/file-aliases.conf]
e03=svc-kestrel-3/src/classify.js; ex03=svc-kestrel-legacy-3/src/classify.js; ew03=web-kestrel-3/src/classify.js; ea03=svc-raven-3/src/classify.js

Return one JSON object with exactly these keys: target_module, required_dependency, first_source_file.
