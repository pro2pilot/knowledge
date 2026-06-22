# 04 — Pro subscription spec

## Role

Pro is a paid subscription that unlocks additional capabilities inside the existing free Inspector.

No separate Pro app is required for V1 public release.

## Commercial decisions

```txt
Pricing: $19/mo + applicable tax per user
Trial: none
Billing: Stripe
Tax: Stripe Tax
Backend: Cloudflare-first
Storage: R2 for signed Pro extension bundles
License metadata: D1
Activations: 2 devices per user/seat
Offline grace: 7 days
User portal: not required in V1
Admin: minimal protected admin endpoint / CLI
Agency/client licenses: included in Team Pro
Enterprise offline: architecture-ready, implementation later
```

## Plans

### Free

```txt
$0
local Inspector
routing/evidence/trust/freshness/repair
basic PR review
basic agent activity
no cloud/login required
```

### Solo Pro

```txt
$19/mo + applicable tax
per user
2 activations
7-day offline grace
```

Unlocks:

```txt
PR Impact Pro
Repair Planner
Trust History
Snapshot Compare
Policy Packs basic
Advanced Reports
Memory Governance local
Advanced Restore Trust
Pro Snapshot Viewer
```

### Team Pro

```txt
per user / seat
2 activations per seat
agency/client workspaces included
```

Unlocks:

```txt
Team Dashboard
Repair Ownership
Team Repair Board
Team Merge Queue
Approvals
Shared Audit History
Client Workspaces
Provider Fleet Status
Shared Reports
```

### Enterprise later

```txt
offline license file
air-gapped manual Pro bundle install
SSO/RBAC
audit exports
private/VPC/self-host options
custom policy packs
support SLA
```

## License architecture

Correct:

```txt
Inspector → License API → D1/Stripe
```

Incorrect:

```txt
Inspector → D1 directly
```

Reason:

```txt
local UI is not trusted
DB credentials must not be shipped
license decisions require signed server response
```

## Activation flow

```txt
1. User installs free .knowledge.
2. User runs node .knowledge/inspector.js.
3. User opens Pro Preview.
4. User subscribes through Stripe Checkout.
5. Stripe webhook updates License API/D1.
6. User activates with email/license/GitHub.
7. License API returns signed entitlement token.
8. Inspector caches license locally.
9. Inspector downloads signed Pro extension from R2.
10. Inspector verifies hash/signature.
11. Pro features unlock in the same UI.
```

## Local license files

```txt
.knowledge/pro/license.json
.knowledge/pro/entitlements.json
.knowledge/pro/extensions/<version>/
```

## Entitlement token fields

```json
{
  "subject": "user_...",
  "email": "user@example.com",
  "github_id": "optional",
  "plan": "solo_pro",
  "entitlements": ["pro_base", "pr_impact_pro", "repair_planner"],
  "issued_at": "...",
  "expires_at": "...",
  "offline_grace_until": "...",
  "activation_id": "...",
  "machine_fingerprint_hash": "...",
  "signature": "..."
}
```

## Pro channels

```txt
stable
beta
internal
```

No nightly in V1.

## Manual Pro bundle install

Allowed if:

```txt
license valid
bundle signature valid
sha256 valid
version compatible
entitlement includes channel
```

Command:

```bash
node .knowledge/tools/pro-extension.js install-file ./pro-inspector-0.1.0.zip --json
```
