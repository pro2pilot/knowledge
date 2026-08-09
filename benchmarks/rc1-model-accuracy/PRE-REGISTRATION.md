# Frozen repository-navigation study — Pro2Pilot .knowledge 3.4.0 RC1

Frozen before the first model inference.

## Candidate

- Artifact: `knowledge-v3.4.0-rc1.zip`
- SHA-256: `7686150325c43ae18229793ec8721b49a85c89149c042b8f963202ab9bd1dc6f`
- Dataset SHA-256: `c82ecd442ffc0fec8ada459493368edabe72964b9ee4e3f45a8db754944b2f80`

## Question

Does the same model make more accurate repository-navigation decisions when shown the exact candidate-generated task-scoped first read instead of the canonical workspace-wide first-read context?

## Design

- Model: `openai/gpt-4.1-mini` through GitHub Models.
- Tasks: 12 pre-registered synthetic repository-navigation tasks.
- Conditions: canonical workspace-wide context vs exact candidate-generated task-scoped context.
- Repetitions: 2 per condition per task (48 total model calls).
- Temperature: 0.1.
- Order: deterministic SHA-derived interleaving.
- Identical system prompt, task text, output schema and evaluator across conditions.
- Only the repository context differs.
- Hidden deterministic evaluator; no worker receives expected answers.
- Infrastructure retries repeat the same request and are reported separately.

## Primary endpoint

Strict repository-navigation success requires all of: exact primary module; exact file-to-edit set; exact required dependency-file set; and no forbidden legacy or unrelated module selected.

## Secondary endpoints

Component accuracy; exact-file precision, recall and F1; forbidden-selection rate; provider-reported prompt and completion tokens, if returned; and latency.

## Claim boundary

A positive result supports only a narrow statement about repository-navigation accuracy on this controlled benchmark for this model. It does not establish general coding accuracy, universal model improvement, production error-rate reduction, or statistical significance beyond the registered sample.

Candidate local context estimates are separately labeled and are not provider usage. Provider token claims are allowed only from the API `usage` receipt.
