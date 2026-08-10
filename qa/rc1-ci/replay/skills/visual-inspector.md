# Skill: Visual Inspector

Use this when the user wants a visual summary of `.knowledge` state or when preparing screenshots/GIFs for README or launch material.

Run:

```bash
node .knowledge/tools/build-visual-inspector.js
```

Open:

```txt
.knowledge/inspector/index.html
```

Review:

- trust buckets and quality score;
- module confidence and explanations;
- repair queue and stale items;
- critical/important files;
- wiki graph;
- applied templates;
- external-memory status.

Do not treat the inspector as source of truth. It is a read-only view over `.knowledge` artifacts. Current code and tests remain source of truth.
