# Visible recording blockers

When `.knowledge` cannot record work, the agent must tell the user immediately
what record is blocked and why, in the user's preferred language. Do not reveal
a suspected secret. Use the returned masked `chat_notice`, translated when the
requested language has no built-in notice:

> Запись … заблокирована: значение распознано как возможный секрет. Если это
> не секрет, сообщите об этом в чате или выберите нужное действие в Inspector.

The local registry stores fingerprints, masked previews and decisions, not the
suspected values. A resolve request still requires a nonempty confirmation
reason of at most 500 characters, but the reason is checked for recognizable
credential text and is never persisted. The registry and Inspector expose only
the fixed reason code `user_confirmed_non_secret_repository_path`, including
for older records that contain a free-text reason. Listing an older registry
does not rewrite its on-disk contents. Inspector → **Blocked recording** lists
the records. The CLI offers the same operations:

```text
node .knowledge/tools/recording-blockers.js list --json
node .knowledge/tools/recording-blockers.js resolve --id=<RB-id> --scope=once --reason="Confirmed non-secret repository path" --confirmed=true --json
node .knowledge/tools/recording-blockers.js resolve --id=<RB-id> --scope=project --reason="Confirmed non-secret repository path" --confirmed=true --json
node .knowledge/tools/recording-blockers.js revoke --id=<EX-id> --confirmed=true --json
```

Only an explicitly confirmed, exact existing repository file path can be
reclassified. “Once” binds approval to one immutable task workflow; “Project”
binds it to that exact value and repository. Changed paths, another project,
another task's once approval, missing files, symlinks, secret-key fields and
arbitrary credential text do not match. Privacy masking remains strict even
after a path classification. A user confirmation in chat authorizes the agent
to apply the corresponding exact classification; it is not inferred from a
silence or a generic instruction to continue. Retry the unchanged finish
request after resolving a blocker; already completed native phases are reused.
Do not put secrets or private details in the confirmation reason; use a brief
non-secret explanation such as `Confirmed non-secret repository path`.

Use `--language=ru` with `agent-task begin` or a `language` field in the finish
request, or set `KNOWLEDGE_USER_LANGUAGE`. Without a configured preference,
the notice defaults to English and the agent translates it for the user.

A user scope restriction is a different blocker. With
`agent-task ... --knowledge-write-allowed=false`, the CLI returns
`blocked_by_user_scope` and writes no registry or workflow. Report it in chat;
this panel cannot broaden the user's permissions. If writes are forbidden,
do not create a blocker record in another state root to evade that restriction.

The bundled workflow exposes blocked recording and the agent instructions
require the chat notice. A runner that ignores these instructions or never
calls the workflow needs its own completion hook for a mechanical guarantee.
