# Release Artifact

Use the zip produced by:

```bash
node tools/package-release.js
```

Expected artifact:

```txt
dist/knowledge-v3.2.0.zip
```

Do not copy a source checkout into a repository as `.knowledge/`. The release artifact is the install artifact.

Validate it with:

```bash
node tools/validate-release-artifact.js dist/knowledge-v3.2.0.zip --json
```

The artifact excludes source and runtime state, including:

- `.git/`
- `.github/`
- `node_modules/`
- `dist/`
- `maintenance/flow-logs/`
- runtime memory provider state
- `metrics/external_memory.json`
- generated `inspector/index.html`

Build the local Inspector after install/import:

```bash
node .knowledge/tools/build-visual-inspector.js
```

Mem0 OSS is the recommended optional memory backend. Pinecone remains an optional vector/cloud bridge. Claude MEM first-class bridge was removed and legacy artifacts are advisory-only migration data. Graphiti and Zep are Pro/Enterprise provider options.
