# Protocol amendment 001 — inference backend substitution

Frozen before any successful model inference.

The preregistered GitHub Models run completed **0 of 48** calls because every request returned HTTP 410 with code `github_models_retirement_brownout`. No model output was observed and no endpoint result was available for analysis.

The primary endpoint, tasks, conditions, repetitions, ordering, task texts, contexts, output schema and hidden evaluator remain unchanged. The inference backend is replaced with the locally executed open model:

- Model repository: `Qwen/Qwen2.5-Coder-0.5B-Instruct`
- Framework: Hugging Face Transformers
- Execution: CPU on a GitHub-hosted Ubuntu runner
- Decoding: deterministic greedy (`do_sample=false`)
- Maximum new tokens: 128
- Resolved model revision is recorded by the runner in the evidence report.

Tokenizer input/output counts are exact for the tested local model but are not provider-billed tokens or API cost. The claim remains limited to controlled repository-navigation accuracy for this model and dataset.
