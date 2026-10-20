## Final report after meaningful work

Use the committed result from `agent-task finish`. Report separately:

- primary verification outcome;
- task-route snapshot, selected modules and exact first-read acknowledgement;
- one routing estimate state: narrowing, overhead, neutral, or unavailable;
- Global Doctor before/after;
- Task Readiness before/after;
- native KVE/KVR IDs and exact repair status;
- deferred unrelated debt;
- release-flow result when requested;
- provider usage only when an actual provider receipt was supplied.

If `agent-task finish` returns `knowledge_maintenance.chat_notice`, relay it to
the user immediately in their preferred language, regardless of the primary
verification outcome. Report its maintenance status and `next_action`
separately from the engineering result. Do not imply an arbitrary runner
delivered the notice through a chat hook.

Never infer model accuracy from Doctor, tests or Task Readiness. Never describe
a local first-read estimate as provider-reported model-token or cost savings.

Do not silently omit a meaningful task or required state update when recording
is blocked. Report the specific blocked item and reason in the user's preferred
language. For secret-related blockers, identify the secret type or setting but
mask the value; never include raw secret material in chat, task evidence, or
the final report. When a user-specified write boundary excludes `.knowledge/`,
do not bypass it: surface `blocked_by_user_scope` visibly in chat and in the
final result. Tell the user: “Если это не секрет, сообщите в чате или выберите
действие в Inspector”. These instructions do not guarantee that an arbitrary
runner will record the blocker automatically.
