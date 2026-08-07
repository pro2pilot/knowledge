# Maintainer-only release preparation workflow

This file belongs to the maintainer source checkout. It is deliberately excluded
from the installed `.knowledge` runtime and must be rejected by the public agent
integration installer.

Use it only when preparing a release from the full source tree:

1. Verify the intended source commit, version metadata, working-tree status,
   active Git/GitHub identity, and release policy.
2. Classify every changed or untracked file before staging anything.
3. Run documentation, schema, syntax, privacy, packaging, and release-policy
   checks from source.
4. Build the versioned `knowledge-v<VERSION>.zip` with
   `node tools/package-release.js --json`; never use a GitHub-generated source
   archive as the install artifact.
5. Validate the exact physical ZIP, run every shipped self-test from separate
   clean extractions, perform the public upgrade path, and bind all evidence to
   the candidate SHA-256.
6. Do not push, tag, publish, deploy, or delete anything without the user's
   explicit approval for that exact action.

A green focused test is not a substitute for the full release gate. If the
candidate bytes or gate plan change, the candidate-bound gate and evidence must
be regenerated.
