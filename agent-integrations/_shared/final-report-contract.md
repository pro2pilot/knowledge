## Final report after meaningful work

After meaningful work or before handoff, run:

`node .knowledge/tools/flow.js release`

Then report:

- doctor score/status;
- wiki lint score/status;
- suspect or low-confidence modules;
- repair queue items;
- routing bundle path;
- PR summary path;
- metrics path;
- estimated tokens saved and percent saved when `.knowledge/metrics/baseline.json` contains routing metrics;
- an explicit note when metrics are unavailable or were not regenerated in this run.
