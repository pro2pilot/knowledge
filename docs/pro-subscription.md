# Pro Subscription Architecture

Pro is a subscription unlock inside the same free Inspector UI. It is not a separate required app for the V1 public free release.

Canonical V1 decisions:

- Solo Pro target: `$19/mo + applicable tax` per user.
- Billing and tax: Stripe + Stripe Tax.
- Backend: Cloudflare Workers, D1 metadata and R2 signed extension bundles.
- Activations: 2 devices per user/seat.
- Offline grace: 7 days.
- Public trial: none.
- Pro Inspector extension version: `0.1.0` private preview.

Free core includes Pro Preview, schemas, feature gates and Export Pro Snapshot. Closed Pro implementation code must live outside the free package.
