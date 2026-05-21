# Local Inspector

The inspector is optional. `.knowledge` works without it. It is a local read-only dashboard for understanding the current knowledge layer without opening raw JSON files.

## Build the static inspector

```bash
node .knowledge/tools/build-visual-inspector.js
```

Output:

```txt
.knowledge/inspector/index.html
.knowledge/inspector/data.json
.knowledge/inspector/status.json
```

Open `index.html` in a browser.

## What the local inspector includes

The bundled inspector is intentionally local, static, and read-only. It includes:

- improved wiki graph preview with typed-edge legend;
- global table filter;
- per-table filters for modules, repair queue, stale items, and critical files;
- clickable links to `.knowledge` artifacts and project files;
- better empty states with suggested commands;
- module-level explanations for low confidence / suspect trust;
- quick actions that copy common commands to the clipboard;
- external-memory/Pinecone status summary;
- applied-template summary.

## Scope

The bundled inspector is a local diagnostic view. It is designed to explain the current repository state, not to replace source-code review or project management tools.

It does not edit project files, change trust levels, or send data to external services.

## Why it is useful

### 1. Faster onboarding

Most users do not want to open raw JSON first. The inspector shows routing, trust, repair queue, wiki graph, templates, external memory, and project health in one page.

### 2. Better GitHub presentation

For a public repository, screenshots and GIFs matter. The inspector gives you a clean visual source for README screenshots, launch posts, and issue reports.

### 3. Debugging adoption

If someone says “the agent does not know where to start,” the inspector can quickly show whether routing bundle, doctor, search index, wiki lint, and modules are present.

## Recommended usage

```bash
node .knowledge/tools/flow.js release --no-color
node .knowledge/tools/build-visual-inspector.js
```

Then open:

```txt
.knowledge/inspector/index.html
```

## File links

The inspector uses relative links:

- `.knowledge` artifacts link inside `.knowledge/`;
- project files link relative to the repository root.

Some browsers may restrict local `file://` navigation. If links do not open, copy the path or use the local server mode if available.

## Local server mode

If the build includes `serve-inspector.js`, run:

```bash
node .knowledge/tools/serve-inspector.js
```

This is still local and read-only. It is useful when browser restrictions make file links inconvenient.
