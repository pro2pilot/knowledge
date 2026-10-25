# Official .knowledge Templates

Official templates are optional project-type packs. They do not claim facts about your codebase. They add a conservative starting policy, wiki pages, critical-path suggestions, and repair items that an agent must verify against current code and tests.

Use:

```bash
node .knowledge/tools/apply-template.js --list
node .knowledge/tools/apply-template.js nextjs-saas
node .knowledge/tools/apply-template.js python-fastapi
```

Templates are safe-by-default: they seed review work, not authoritative evidence.
