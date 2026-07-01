# Mem0 OSS Install Preview

Mem0 OSS is the recommended optional universal memory backend for `.knowledge` free/core.

Official install command verified on 2026-06-06:

```bash
pip install mem0ai==2.0.4
```

The `.knowledge` CLI does not run this command automatically. Use:

```bash
node .knowledge/tools/memory-provider.js setup mem0-oss --live --json
```

That is the recommended guided flow. It records or reuses the receipt, writes repo-local config, refreshes the cookbook recipe, runs explicit live health, and keeps Mem0 advisory-only.

Low-level receipt commands are still available:

```bash
node .knowledge/tools/memory-provider.js preview mem0-oss --json
node .knowledge/tools/memory-provider.js install mem0-oss --version mem0ai==2.0.4 --yes-i-reviewed-license --json
```

The second command records an approval receipt only. It does not install packages, create a network connection, or enable telemetry.

External memory remains advisory only. It cannot raise trust, overwrite curated `.knowledge` artifacts, or outrank current code/tests/evidence.
