# 13 — License, attribution and embedding FAQ

> Not legal advice. Verify with counsel before changing license terms.

## Core license strategy

Recommended:

```txt
Free Core: Apache-2.0
Pro extension: commercial license
```

## Apache-2.0 obligations

If an app uses and redistributes Apache-2.0 `.knowledge`, it generally must:

```txt
include a copy of the Apache-2.0 license
retain copyright, patent, trademark and attribution notices
mark modified files
include NOTICE attribution if the Work includes a NOTICE file
```

Apache-2.0 permits redistribution with or without modifications when its conditions are met, including providing the license and retaining notices. The license also says it does not grant permission to use trade names, trademarks, service marks or product names except for reasonable description of origin and reproducing NOTICE. Source: https://www.apache.org/licenses/LICENSE-2.0

## Can we force “Powered by .knowledge”?

If Free Core is Apache-2.0, do not try to force a UI badge through the core license.

Better:

```txt
mandatory LICENSE/NOTICE compliance
optional Powered by .knowledge badge
integration gallery / co-marketing for apps that show badge
commercial attribution clause for Pro/SDK licenses
paid white-label option later
```

## NOTICE text suggestion

```txt
This product includes .knowledge by Pro2Pilot,
a repo-local routing, evidence, trust, freshness, repair and PR-review system for coding agents.
```

## Embedding FAQ

### Can another app use `.knowledge` under the hood?

Yes, if it follows the license and file/CLI/API contracts.

### Must they show the badge?

For Apache-2.0 Core, use NOTICE requirements and optional badge. Do not rely on mandatory UI attribution unless using a separate commercial license.

### Can Pro features require attribution?

Yes, under a separate Pro/commercial license.

### Can Pro offer white-label?

Yes. White-label can be a paid option.

### What should docs say?

```txt
.knowledge Core is Apache-2.0.
Please include LICENSE and NOTICE when redistributing.
Optional badge: Powered by .knowledge by Pro2Pilot.
```
