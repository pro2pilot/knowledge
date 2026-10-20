---
description: Run a task through canonical .knowledge routing and bounded evidence reuse
agent: plan
---

Start a scoped task with `.knowledge/tools/agent-task.js begin`, read the exact
returned first-read body, complete the task, then call `agent-task.js finish`
with its SHA, source files and physical test argv. Do not claim provider token,
cost, speed or accuracy changes from the local routing estimate.

If task recording or a required `.knowledge` write is blocked, do not silently
skip it. Run `node .knowledge/tools/recording-blockers.js list` when available
and relay `chat_notice` in the user's preferred language, stating the blocked
item and reason. Mask secret values. Do not bypass a user write boundary that
excludes `.knowledge/`; report `blocked_by_user_scope` visibly in chat and the
final result. Say: “Если это не секрет, сообщите в чате или выберите действие
в Inspector”. This instruction cannot mechanically guarantee compliance by
every runner.
