TASK
The current retry classification behavior must be updated. Before editing, identify the application module that is wired into the active runtime, the shared package used by that implementation, and the first source file to inspect.

FIRST-READ CONTEXT
[task-route/current]
selected=h02,p02; entry=e02; excluded=hx02,w02,a02,px02

[runtime/module-aliases.conf]
h02=svc-harbor-2; hx02=svc-harbor-legacy-2; w02=web-harbor-2; a02=svc-onyx-2

[runtime/package-aliases.conf]
p02=pkg-onyx-2; px02=pkg-onyx-v1-2

[runtime/file-aliases.conf]
e02=svc-harbor-2/src/classify.js; ex02=svc-harbor-legacy-2/src/classify.js; ew02=web-harbor-2/src/classify.js; ea02=svc-onyx-2/src/classify.js

[svc-harbor-2/src/classify.js]
const policy = require("pkg-onyx-2"); function classifyRetry(input) { return policy.current(input); }

[pkg-onyx-2/src/backoff.js]
exports.current = (input) => applyCurrentRetryRule(input);

[svc-harbor-legacy-2/src/classify.js]
const policy = require("pkg-onyx-v1-2"); function classifyRetry(input) { return policy.legacy(input); }

Return one JSON object with exactly these keys: target_module, required_dependency, first_source_file.
