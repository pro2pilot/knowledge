# GitHub Actions Templates

The templates in `.knowledge/github-action-templates/` are ready-to-copy workflow files. They are not active until you copy them into your repository’s `.github/workflows/` directory.

## Why they exist

They make `.knowledge` visible in normal GitHub workflows:

- every PR can run a knowledge health check;
- PRs can include a generated summary for reviewers;
- release branches can collect metrics and evaluation output;
- broken JSON, missing routing bundle, weak wiki lint, or doctor warnings become visible before merge.

## Templates

```txt
.knowledge/github-action-templates/knowledge-health.yml
.knowledge/github-action-templates/knowledge-pr-summary.yml
.knowledge/github-action-templates/knowledge-evaluation.yml
```

## How to enable

From the repository root:

```bash
mkdir -p .github/workflows
cp .knowledge/github-action-templates/*.yml .github/workflows/
```

Then commit the workflows.

## Recommended usage

Start with:

```txt
knowledge-health.yml
```

Add PR summaries only after the health workflow is stable:

```txt
knowledge-pr-summary.yml
```

Use evaluation workflow for release prep or benchmark runs:

```txt
knowledge-evaluation.yml
```

## What this gives you on GitHub

- visible “knowledge health” status;
- repeatable proof that `.knowledge` is not broken;
- PR-facing summaries for maintainers;
- metrics for README claims such as routing bundle size, doctor score, wiki graph size, and estimated context savings.
