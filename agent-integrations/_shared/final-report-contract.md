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
- exactly one routing-context estimate state according to `.knowledge/agent-integrations/_shared/metrics-reporting.md`;
- an explicit note when the estimate is unavailable, not comparable, stale, or was not regenerated in this run.

Never describe the local estimate as provider-reported model-token savings.
