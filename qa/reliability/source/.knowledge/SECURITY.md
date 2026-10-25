# Security Policy

`.knowledge` is local-first and does not require external services by default.

## Reporting a vulnerability

Please do **not** open public GitHub issues for vulnerabilities, leaked secrets, or security-sensitive reports.

Contact:

```txt
github@pro2pilot.com
```

Include:

- affected version or commit;
- operating system and Node.js version;
- command that triggered the issue;
- minimal reproduction steps;
- whether any secrets or private repository data may have been exposed.

## Scope

In scope:

- unintended network calls;
- secret leakage in reports, logs, generated files, or inspector output;
- unsafe update-check behavior;
- unsafe handling of `.knowledge` runtime files;
- vulnerabilities in bundled tools.

Out of scope:

- vulnerabilities in third-party agents, models, or external tools;
- issues caused by deliberately enabling external services such as Pinecone Cloud;
- project-specific secrets committed by users outside `.knowledge`.

## External memory

External memory is optional and disabled by default. Retrieved external chunks must be treated as context, not source of truth.

## Update checks

Update checks are advisory-only, disabled by default, and query official GitHub Releases for `pro2pilot/knowledge`. They do not upload repository content and do not apply updates automatically.
