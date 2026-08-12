---
name: kb-task
description: Run one meaningful engineering task through canonical task routing, one physical verification pass, and bounded Repair-on-touch.
---

1. Start with `node .knowledge/tools/agent-task.js begin --task="..." --scope-module=<id> --scope-path=<path> --json`.
2. Read the returned `route.first_read.content` before broad exploration.
3. Complete the engineering task and prepare physical tests.
4. Finish with the exact workflow ID, first-read SHA, source files and test argv.
5. Report primary work separately from Doctor, Task Readiness, repair and deferred debt.
