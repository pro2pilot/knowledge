# Release Artifact

> **Install note:** Do not use GitHub "Download ZIP" as the install package. Use the release asset only.

Use the official GitHub release asset named `knowledge-vX.Y.Z.zip`.
Maintainer packaging commands are source-checkout-only tools and are
intentionally not included in installed user `.knowledge` artifacts.

Expected artifact:

```bash
VERSION="$(node -p "require('./package.json').version")"
echo "dist/knowledge-v${VERSION}.zip"
```

Do not copy a source checkout into a repository as `.knowledge/`. The release artifact is the install artifact.
Do not leave a source checkout such as `knowledge-src/` beside `.knowledge/` in the target repository; agents may otherwise index the installer source as project code.

Artifact validation is source-only maintainer tooling. Installed user artifacts
do not include release validators, release gates, post-release asset tools, or
release policy files.

The artifact excludes source and runtime state, including:

- `.git/`
- `.github/`
- `node_modules/`
- `dist/`
- `maintenance/flow-logs/`
- runtime memory provider state
- `metrics/external_memory.json`
- generated `inspector/index.html`

The source checkout package and validator share a release policy. That policy
defines required public entries, forbidden paths/content, package-only
exclusions, and ZIP safety limits so packaging and validation do not drift
apart. Release gates remain source-only maintainer checks and are not shipped in
the user artifact.

Build the local Inspector after install/import:

```bash
node .knowledge/tools/build-visual-inspector.js
```

Mem0 OSS is the recommended optional memory backend. Pinecone remains an optional vector/cloud bridge. Claude MEM first-class bridge was removed and legacy artifacts are advisory-only migration data. Graphiti and Zep are not bundled in the free/core install asset.
