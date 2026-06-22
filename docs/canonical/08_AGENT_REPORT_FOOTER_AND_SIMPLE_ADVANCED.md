# 08 — Agent report footer and Simple/Advanced mode

## Core decision

No chat inside Inspector.

Simple Mode is expressed through:

```txt
plain-language Inspector state
safe defaults
agent report footer
Restore Trust button when trust is incomplete
```

## Agent report footer

After work, connected agents should append a short `.knowledge` status block.

### Compact

```md
.knowledge: Trust needs recheck · ~1.2k system tokens · ~38% estimated context saved
```

### Full

```md
## .knowledge report

Knowledge trust: Needs recheck
Why: 2 stale modules, 1 missing evidence item
System context used: ~1,240 tokens
Estimated context saved: ~38%

Suggested next step:
Restore trust in knowledge

Open Inspector:
node .knowledge/inspector.js
```

## Settings

```txt
Agent report footer:
  Off
  Compact
  Full
  Only when trust is incomplete

Show token metrics:
  On / Off

Show restore action:
  On / Off

Show Open Inspector action:
  On / Off
```

## Token metrics

Use honest labels:

```txt
estimated system tokens used
estimated context saved
```

Do not claim exact savings unless runtime usage data is actually available.

Formula:

```txt
baseline_context_tokens = estimated raw/full-context tokens
actual_context_tokens = routing bundle + selected snippets actually used
saved_pct = 1 - actual_context_tokens / baseline_context_tokens
```

## Restore action in footer

If trust is incomplete:

```txt
Suggested action: Restore trust in knowledge
```

In VS Code, can be a command link.

In plain chat, include command fallback:

```bash
node .knowledge/tools/restore-trust.js --safe --json
```

## First-run onboarding

Onboarding happens in Inspector, not agent chat.

Flow:

```txt
1. Agent integration detected.
2. Inspector opens.
3. Setup wizard asks questions next to their setting controls.
4. Settings are written to policy files.
5. Setup card collapses after save.
6. Agents read stable settings later.
```

If an upgraded install has no saved onboarding completion marker, Inspector treats setup as still required and shows the same questions again. Completion is recorded by `first_run_onboarding_completed: true`.

After completion, Inspector keeps a collapsed `First-run setup` card. Clicking the card expands the same settings again.

Questions:

```txt
Use Simple or Advanced mode?
What can agents do without asking?
How should concurrent agents work?
Can agents merge?
What footer should agents add?
```

Simple Mode shows both `Restore Trust` and `Repair trust with an agent`. The second action copies a prompt for the packaged `kb-repair-trust` skill.

Do not ask:

```txt
Which agent to connect?
```

If the user just connected an agent, show:

```txt
Connected agent detected: Claude Code.
How should .knowledge work with this agent?
```

## Settings files

```txt
.knowledge/settings/operator-profile.json
.knowledge/settings/autonomy-policy.json
.knowledge/settings/agent-policy.json
.knowledge/settings/report-footer.json
```
