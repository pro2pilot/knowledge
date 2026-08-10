kb-install-hooks
Run `node .knowledge/tools/install-git-hooks.js` from repo root.
What it does:
- installs post-commit, post-merge, and post-checkout hooks into `.git/hooks/`
- each hook triggers `.knowledge/tools/sync-tracked.js`

Use when you want maintenance to run automatically on git lifecycle events. Hooks are required for that automation path; if the repo is not initialized with git yet, run `node .knowledge/tools/init-git-repo.js` first.
