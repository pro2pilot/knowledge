---
description: Run a task through canonical .knowledge routing and bounded evidence reuse
agent: plan
---

Start a scoped task with `.knowledge/tools/agent-task.js begin`, read the exact
returned first-read body, complete the task, then call `agent-task.js finish`
with its SHA, source files and physical test argv. Do not claim provider token,
cost, speed or accuracy changes from the local routing estimate.
