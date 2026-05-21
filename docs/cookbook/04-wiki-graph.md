# Cookbook: Wiki Graph

Create small wiki pages with typed links:

```yaml
links:
  supports: []
  contradicts: []
  depends_on: []
  supersedes: []
  related: []
```

Then run:

```bash
node .knowledge/tools/build-wiki-graph.js
node .knowledge/tools/lint-wiki.js
```
