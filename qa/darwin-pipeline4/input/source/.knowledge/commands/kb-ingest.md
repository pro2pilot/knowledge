kb-ingest
1. Ensure `.knowledge/` exists (run bootstrap first if needed).
2. Run `node .knowledge/tools/ingest-existing-project.js`.
3. This seeds an initial project-specific index, module registry, maps, freshness coverage, and trust report using shallow heuristics.
4. Review low-confidence or uncovered areas before relying on summaries.
