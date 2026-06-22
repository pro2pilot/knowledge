# Codex Skill: Release Preparation Workflow

**Recommended skill file path in the repository:**

```txt
agent-integrations/codex/skills/release-preparation-workflow.md
```

**Purpose:** use this skill when the user wants to prepare, clean, verify, package, push, tag, or release a new version of a GitHub repository.

This is **not** an autopublish skill. It is a release-preparation and release-readiness workflow. The goal is to prevent accidental dirty releases, stale docs, wrong accounts, untracked junk, generated noise, inconsistent version metadata, and mismatched release assets.

---

## 0. Core rule

Do **not** push, tag, merge, delete, publish, rewrite history, or overwrite files unless the user explicitly approves that exact action.

If confidence is below 100%, stop and report blockers. “100% confidence” means:

- all required checks passed;
- every changed/untracked file has been classified;
- docs match reality;
- version metadata is consistent;
- release artifacts were built from the intended source;
- the GitHub account and Git author were verified;
- the user has a clear next command and understands where to run it.

---

## 1. Mental model

Never release directly from a messy work folder.

A safe release has four layers:

```txt
1. Source repository
   The actual project files.

2. Release-preparation workspace
   A separate folder with reports, inventory, QA logs, release notes, artifacts, and commands.

3. Git branch / PR
   The reviewed source changes that should be merged into main.

4. GitHub Release
   A tag plus versioned release assets, created only after main is clean and verified.
```

For `.knowledge`, the main asset is a curated install ZIP:

```txt
knowledge-v<VERSION>.zip
knowledge-v<VERSION>.zip.sha256
```

Do not use GitHub’s automatically generated source archive as the primary install artifact if the project has a dedicated release-packaging command.

---

## 2. Required inputs

Ask or infer these before doing release work:

```txt
REPO_FULL_NAME          Example: pro2pilot/knowledge
LOCAL_REPO_PATH         Example: C:\path\to\knowledge
BASE_BRANCH             Usually: main
WORK_BRANCH             Example: fix/install-git-policy
TARGET_VERSION          Example: 3.2.0
PREVIOUS_VERSION        Example: 3.1.9
EXPECTED_GH_ACCOUNT     GitHub username expected to push/release
EXPECTED_GIT_AUTHOR     Optional expected git user.name
EXPECTED_GIT_EMAIL      Optional expected git user.email
RELEASE_TITLE           Example: v3.2.0 — Universal final-report hardening
```

If `TARGET_VERSION` or `EXPECTED_GH_ACCOUNT` is missing, ask before continuing.

Derived values:

```txt
TAG=v<TARGET_VERSION>
RELEASE_WORKSPACE=../release-work/<repo-name>-v<TARGET_VERSION>
ARTIFACT=dist/knowledge-v<TARGET_VERSION>.zip
SHA=dist/knowledge-v<TARGET_VERSION>.zip.sha256
RELEASE_NOTES=.release-notes/v<TARGET_VERSION>.md
```

---

## 3. Create release-preparation workspace

Create a release workspace outside the source repository unless the user explicitly requests another location.

Recommended structure:

```txt
../release-work/<repo-name>-v<VERSION>/
  00-inputs.json
  01-git-preflight.md
  02-file-inventory.tsv
  03-change-map.md
  04-suspicious-content.md
  05-doc-consistency.md
  06-version-consistency.md
  07-qa-report.md
  08-release-notes.md
  09-github-commands.ps1
  10-post-release-verify.ps1
  artifacts/
    knowledge-v<VERSION>.zip
    knowledge-v<VERSION>.zip.sha256
  quarantine/
```

The release workspace is evidence and packaging support. It is not normally committed.

Write `00-inputs.json` with all user-provided inputs and inferred values.

---

## 4. Phase 1 — Git and account preflight

Run from the repository root:

```powershell
git rev-parse --show-toplevel
git remote -v
git branch --show-current
git status --short
git status --porcelain=v1 -b
git fetch origin --prune
git branch -vv
git config user.name
git config user.email
gh auth status --active
gh api user --jq .login
```

Check remote branch existence:

```powershell
git ls-remote --heads origin <WORK_BRANCH>
```

Write `01-git-preflight.md` with:

```txt
repo_root
current_branch
base_branch
work_branch
remote_urls
upstream_status
remote_branch_exists
working_tree_clean_or_dirty
git_author_name
git_author_email
active_gh_account
expected_gh_account
safe_to_pull
safe_to_push
```

Rules:

- If the working tree is dirty, do **not** run `git pull --ff-only`.
- If the branch has no upstream, do **not** run `git pull --ff-only`.
- `git fetch origin --prune` is safe for metadata refresh.
- If the active GitHub account does not match `EXPECTED_GH_ACCOUNT`, stop.
- If the Git author/email mismatch expected values, stop or ask.
- If the remote is not the expected repository, stop.
- If the current branch is not the expected work branch, stop or ask.

---

## 5. Phase 2 — Full file inventory

Run:

```powershell
git status --short
git diff --stat
git diff --name-status
git diff --cached --name-status
git ls-files --others --exclude-standard
git ls-files
```

Create `02-file-inventory.tsv` with these columns:

```txt
path	git_status	tracked_or_untracked	category	action	reason	commit_yes_no	needs_user_review
```

Allowed categories:

```txt
source_change
docs_change
release_metadata
test_change
tooling_change
generated_runtime
release_artifact
temporary_junk
agent_note
scratch_file
suspicious
unchanged
unknown
```

Rules:

- Every changed or untracked file must be classified.
- Unknown files block the release.
- Untracked files are not automatically bad, but they must be explained.
- Do not stage anything until file inventory is complete.
- If there are files that look like agent scratch notes, classify them explicitly.
- If there are generated/runtime artifacts, mark them as `commit_yes_no=no` unless team policy says otherwise.

---

## 6. Phase 3 — Suspicious content scan

Scan all changed text files and relevant docs/scripts for accidental notes, scratch text, stale claims, or junk.

Search for patterns like:

```txt
scratch
tmp
temporary
remove-later marker
delete me
agent note
working note
chatgpt
codex note
debug only
test junk
черновик
временное
заметка агента
мусор
удалить
потом поправить
```

Also inspect manually:

```txt
README.md
Quick-Start.md
RELEASE_NOTES.md
package.json
config.yaml
tools/*.js
docs/*.md
templates/**
agent-integrations/**
```

Create `04-suspicious-content.md`.

For each finding include:

```txt
file
line
excerpt
severity: info|warning|blocker
recommended_action
```

Rules:

- Do not delete suspicious content silently.
- If it is obvious untracked release-prep scratch, move to `quarantine/` only after user approval.
- If it is inside tracked source/docs, edit only when clearly accidental and explain the change.
- If uncertain, stop and ask.

---

## 7. Phase 4 — Change map against base branch and previous release

Compare against base branch:

```powershell
git diff --name-status origin/<BASE_BRANCH>...HEAD
git diff --stat origin/<BASE_BRANCH>...HEAD
```

If the working tree has uncommitted changes, also compare:

```powershell
git diff --name-status HEAD
git diff --stat HEAD
```

If previous release tag exists:

```powershell
git tag --list
git diff --name-status v<PREVIOUS_VERSION>...HEAD
git diff --stat v<PREVIOUS_VERSION>...HEAD
```

Create `03-change-map.md`.

It must answer:

```txt
What changed since main?
What changed since previous release?
Which changes are intentional?
Which files are new?
Which files were removed?
Which docs mention new files?
Which docs do not mention new files but should?
Which new commands exist?
Which README/Quick-Start sections need update?
Which changed files are not documented anywhere?
```

Rules:

- New user-facing commands must be documented.
- New install/update behavior must be reflected in README and Quick-Start.
- New release assets or packaging behavior must be reflected in release notes.
- Do not overclaim features that are not implemented.

---

## 8. Phase 5 — Version consistency

Check version in:

```txt
package.json
config.yaml
README.md
Quick-Start.md
RELEASE_NOTES.md
.release-notes/v<VERSION>.md
tools/build-routing-bundle.js
tools/check-updates.js
templates/official/*/template.json
all seed JSON files with schema_version/version
```

Run:

```powershell
node -e "console.log(require('./package.json').version)"
git grep -n "<PREVIOUS_VERSION>"
git grep -n "<TARGET_VERSION>"
git grep -n "schema_version"
git grep -n "version"
```

Create `06-version-consistency.md`.

Rules:

- `package.json` must equal `TARGET_VERSION`.
- `config.yaml` must equal `TARGET_VERSION` if it has a version field.
- Current schema/version markers must not accidentally remain `PREVIOUS_VERSION`.
- `PREVIOUS_VERSION` may remain in historical release notes only.
- Artifact name must be `knowledge-v<TARGET_VERSION>.zip` when releasing `.knowledge`.
- GitHub tag must be `v<TARGET_VERSION>`.
- If inconsistent, fix and rerun version checks.

---

## 9. Phase 6 — README / Quick-Start / docs reality check

Verify docs against actual repository behavior.

Check commands mentioned in README/Quick-Start exist:

```powershell
Test-Path tools/package-release.js
Test-Path tools/self-test-install-policy.js
Test-Path tools/install-check.js
Test-Path tools/update-system-files.js
Test-Path tools/git-policy.js
Test-Path tools/flow.js
Test-Path tools/install-agent-integrations.js
Test-Path tools/doctor.js
```

Check package scripts:

```powershell
node -e "const p=require('./package.json'); console.log(JSON.stringify(p.scripts,null,2))"
```

Create `05-doc-consistency.md`.

Must verify:

```txt
README claims match existing commands.
Quick-Start install/update steps match real commands.
Git policy docs match git-policy.js and .knowledge.gitignore template.
Release notes match actual diff.
No old feature claim remains false.
No new user-facing feature is undocumented.
No command path is wrong.
No archive/install instruction points users to GitHub source zip as the primary artifact when a curated artifact exists.
```

Stop if docs are stale or misleading.

---

## 10. Phase 7 — Safe cleanup plan

Do not run destructive cleanup first.

Run dry-run only:

```powershell
git clean -nd
git clean -ndX
```

Classify candidates:

```txt
safe_to_ignore
safe_to_quarantine
requires_user_confirmation
must_keep
unknown
```

If the user approves quarantine, move selected files into:

```txt
../release-work/<repo-name>-v<VERSION>/quarantine/
```

Do not run `git clean -fd` unless the user explicitly requests it after reviewing dry-run output.

After cleanup/quarantine, rerun:

```powershell
git status --short
```

Update `02-file-inventory.tsv`.

---

## 11. Phase 8 — Static QA

Run JS syntax check:

```powershell
Get-ChildItem tools -Filter *.js | ForEach-Object { node --check $_.FullName }
if (Test-Path tools/lib) {
  Get-ChildItem tools/lib -Filter *.js | ForEach-Object { node --check $_.FullName }
}
```

Run JSON parse check:

```powershell
Get-ChildItem -Recurse -Filter *.json |
  Where-Object { $_.FullName -notmatch '\\node_modules\\|\\dist\\|\\.git\\|release-work' } |
  ForEach-Object {
    node -e "JSON.parse(require('fs').readFileSync(process.argv[1],'utf8'))" $_.FullName
  }
```

Record results in `07-qa-report.md`.

Stop on any syntax or JSON parse error.

---

## 12. Phase 9 — Build release artifact

Run:

```powershell
node tools/package-release.js --json
```

Expected:

```txt
status: ok
version: TARGET_VERSION
artifact: dist/knowledge-v<TARGET_VERSION>.zip
warnings: []
errors: []
```

Copy artifact into release workspace:

```powershell
Copy-Item ".\dist\knowledge-v<TARGET_VERSION>.zip" "../release-work/<repo-name>-v<TARGET_VERSION>/artifacts/"
```

Create SHA256:

```powershell
Get-FileHash ".\dist\knowledge-v<TARGET_VERSION>.zip" -Algorithm SHA256 |
  ForEach-Object { "$($_.Hash.ToLower())  knowledge-v<TARGET_VERSION>.zip" } |
  Set-Content "../release-work/<repo-name>-v<TARGET_VERSION>/artifacts/knowledge-v<TARGET_VERSION>.zip.sha256" -NoNewline
```

Verify artifact invariants:

```txt
contains .knowledge/
contains .knowledge/Quick-Start.md
contains .knowledge/README.md
contains .knowledge/tools/flow.js
contains .knowledge/tools/install-check.js
contains .knowledge/.gitignore
does not contain .knowledge/.git/
does not contain .knowledge/.github/
does not contain dist/
does not contain runtime logs/events/locks/temp/backups
text files are LF-normalized if package-release claims that behavior
```

Record in `07-qa-report.md`.

---

## 13. Phase 10 — Self-test

Run:

```powershell
node tools/self-test-install-policy.js
```

Expected:

```txt
status: ok
tests_failed: 0
```

Record full output in `07-qa-report.md`.

---

## 14. Phase 11 — Fresh artifact smoke

Create temp smoke dir outside repo:

```powershell
$SmokeRoot = Join-Path $env:TEMP ("knowledge-release-smoke-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force $SmokeRoot | Out-Null
Copy-Item ".\dist\knowledge-v<TARGET_VERSION>.zip" $SmokeRoot
Set-Location $SmokeRoot
git init
Expand-Archive ".\knowledge-v<TARGET_VERSION>.zip" -DestinationPath .
```

Run:

```powershell
node .knowledge/tools/install-check.js --json
node .knowledge/tools/install-agent-integrations.js --runtime codex
node .knowledge/tools/flow.js import --no-color
node .knowledge/tools/flow.js release --no-color
git add . 2> git-add-stderr.txt
git status --short
```

Verify:

```txt
install-check ok/fresh
flow import ok
flow release ok
line-ending warning count = 0
staged runtime/generated count = 0
```

Forbidden staged patterns:

```txt
.knowledge/.lock
.knowledge/.runtime/
.knowledge/maintenance/flow-logs/
.knowledge/maintenance/events/
.knowledge/maintenance/sync_log.json
.knowledge/search/index.json
.knowledge/inspector/
.knowledge/maintenance/routing_bundle.json
.knowledge/maintenance/trust_report.json
.knowledge/maintenance/quality_report.json
.knowledge/maintenance/pr_summary.md
.knowledge/maps/wiki_graph.json
.knowledge/maps/file_criticality.json
.knowledge/metrics/baseline.json
```

Return to source repo.

---

## 15. Phase 12 — Bad install smoke

In a temp smoke repo unpacked from the artifact, create nested `.git`:

```powershell
New-Item -ItemType Directory -Force ".knowledge/.git" | Out-Null
node .knowledge/tools/install-check.js --json
node .knowledge/tools/install-check.js --fix --yes
```

Verify:

```txt
pre-fix failed/broken
issue nested_knowledge_git present
post-fix ok
.knowledge/.git removed or moved
install_check_report.json contains pre_fix, fixes_applied, post_fix
top-level status equals post_fix status
```

Record in `07-qa-report.md`.

---

## 16. Phase 13 — Existing update smoke

Create an old `.knowledge` fixture with custom project knowledge:

```txt
.knowledge/wiki/custom.md
.knowledge/modules/custom.json
.knowledge/evidence/custom.json
.knowledge/decisions.json
```

Run:

```powershell
node .knowledge/tools/update-system-files.js --from <new-knowledge-root> --dry-run
node .knowledge/tools/update-system-files.js --from <new-knowledge-root> --apply --yes
```

Verify:

```txt
custom wiki/modules/evidence/decisions preserved
system files updated
backup created
install-check passes
doctor passes
flow release passes
```

Record in `07-qa-report.md`.

---

## 17. Phase 14 — Release notes

Create or update:

```txt
RELEASE_NOTES.md
.release-notes/v<TARGET_VERSION>.md
../release-work/<repo-name>-v<TARGET_VERSION>/08-release-notes.md
```

Release notes should include:

```txt
Title
Summary
Added
Changed
Fixed
Upgrade note
QA
Assets
Known limitations
```

Rules:

- GitHub Release body describes this release, not the whole project history.
- `RELEASE_NOTES.md` may contain the historical changelog.
- Do not overclaim features.
- Mention only verified changes.
- Mention exact asset names.
- Do not mention internal agent or skill implementation details in public release notes unless the user explicitly asks for that. For example, do not list "Codex skill", "agent workflow skill", or similar internal packaging details as a release feature.
- When the user asks for text to paste into GitHub Release body, output one clean copy-ready Markdown document. Do not wrap the whole document in another fenced block if that would make nested code blocks awkward to copy or paste.

---

## 18. Phase 15 — Final staged-file audit

Before commit:

```powershell
git status --short
git diff --stat
git diff
```

Stage intentionally:

```powershell
git add <intended files only>
```

Then check staged content:

```powershell
git diff --cached --stat
git diff --cached --name-status
git diff --cached
```

Rules:

- Never stage `dist/`.
- Never stage release-work folder unless explicitly intended.
- Never stage quarantine.
- Never stage temporary smoke folders.
- Never stage generated runtime artifacts unless team policy says optional and user approves.
- Every staged file must appear in `02-file-inventory.tsv` with `commit_yes_no=yes`.

If staged set is wrong:

```powershell
git restore --staged <path>
```

---

## 19. Phase 16 — Final confidence gate

All must be true:

```txt
[ ] expected GitHub account verified
[ ] git author verified
[ ] all changed/untracked files classified
[ ] no unknown files remain
[ ] suspicious content scan clean or resolved
[ ] version consistency clean
[ ] README/Quick-Start/docs match actual behavior
[ ] static QA passed
[ ] JSON QA passed
[ ] package-release passed
[ ] artifact invariants passed
[ ] self-test passed
[ ] fresh artifact smoke passed
[ ] bad install smoke passed
[ ] existing update smoke passed
[ ] git add smoke clean
[ ] release workspace created
[ ] release notes created
[ ] final staged set reviewed
```

If any item fails, output blockers and do not provide push/tag/release command as ready.

---

## 20. Phase 17 — Output next commands only after success

If ready for branch commit and push, but no commit exists yet:

```powershell
git commit -m "<commit message>"
git push -u origin <WORK_BRANCH>
```

If branch already tracks remote:

```powershell
git push
```

If PR is needed:

```powershell
gh pr create `
  --repo <REPO_FULL_NAME> `
  --base <BASE_BRANCH> `
  --head <WORK_BRANCH> `
  --title "<PR title>" `
  --body-file "../release-work/<repo-name>-v<TARGET_VERSION>/PR_BODY.md"
```

Do not create tag/release until PR is merged into main.

---

## 21. Phase 18 — Post-merge GitHub Release commands

Only after the branch is merged into `main`:

```powershell
git checkout <BASE_BRANCH>
git pull --ff-only origin <BASE_BRANCH>
node -e "console.log(require('./package.json').version)"
node tools/package-release.js --json
node tools/self-test-install-policy.js
```

Create checksum:

```powershell
Get-FileHash ".\dist\knowledge-v<TARGET_VERSION>.zip" -Algorithm SHA256 |
  ForEach-Object { "$($_.Hash.ToLower())  knowledge-v<TARGET_VERSION>.zip" } |
  Set-Content ".\dist\knowledge-v<TARGET_VERSION>.zip.sha256" -NoNewline
```

Create annotated tag:

```powershell
git tag -a v<TARGET_VERSION> -m "v<TARGET_VERSION> - <release summary>"
git push origin v<TARGET_VERSION>
```

Create draft GitHub Release:

```powershell
gh release create v<TARGET_VERSION> `
  ".\dist\knowledge-v<TARGET_VERSION>.zip#knowledge-v<TARGET_VERSION>.zip" `
  ".\dist\knowledge-v<TARGET_VERSION>.zip.sha256#knowledge-v<TARGET_VERSION>.zip.sha256" `
  --repo <REPO_FULL_NAME> `
  --title "v<TARGET_VERSION> — <release title>" `
  --notes-file ".release-notes/v<TARGET_VERSION>.md" `
  --verify-tag `
  --draft
```

Verify draft:

```powershell
gh release view v<TARGET_VERSION> --repo <REPO_FULL_NAME> --json tagName,name,isDraft,isPrerelease,isLatest,assets
gh release view v<TARGET_VERSION> --repo <REPO_FULL_NAME> --web
```

Publish only after user approval:

```powershell
gh release edit v<TARGET_VERSION> --repo <REPO_FULL_NAME> --draft=false --latest
```

Post-release verify:

```powershell
$VerifyRoot = Join-Path $env:TEMP ("knowledge-release-verify-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force $VerifyRoot | Out-Null
Set-Location $VerifyRoot
gh release download v<TARGET_VERSION> --repo <REPO_FULL_NAME> --pattern "knowledge-v<TARGET_VERSION>.zip"
git init
Expand-Archive ".\knowledge-v<TARGET_VERSION>.zip" -DestinationPath .
node .knowledge/tools/install-check.js --json
node .knowledge/tools/install-agent-integrations.js --runtime codex
node .knowledge/tools/flow.js import --no-color
node .knowledge/tools/flow.js release --no-color
git add . 2> git-add-stderr.txt
git status --short
```

---

## 22. Required final report format

Always finish with:

```txt
Release readiness result: pass|blocked

Repository:
Target version:
Previous version:
Base branch:
Work branch:
Expected GitHub account:
Actual GitHub account:
Git author:
Release workspace:

Git state:
- upstream:
- remote branch exists:
- dirty files:
- untracked files:

File inventory summary:
- source changes:
- docs changes:
- release metadata:
- generated/runtime:
- junk/quarantined:
- suspicious:
- unknown:

Version consistency:
README/Quick-Start consistency:
QA:
- static:
- JSON:
- package-release:
- self-test:
- fresh artifact smoke:
- bad install smoke:
- existing update smoke:
- git add smoke:

Release assets:
- zip:
- sha256:
- notes file:

Changed files to commit:
path | action | reason

Files not to commit:
path | reason

Blockers:
1.
2.

If pass, next terminal command:
<exact PowerShell command block>
```

If confidence is below 100%, do not output push/tag/release commands as ready. Output blockers and exact next diagnostic or fix command instead.
