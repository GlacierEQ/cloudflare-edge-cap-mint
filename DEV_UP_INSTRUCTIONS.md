# Engineering Handoff — Edge Cap Mint

## Current phase

`PROOF_REPRODUCED` at the repository-local boundary.

The former generic Wave C scaffold promotion is revoked. The current implementation has self-verifying source proof from GitHub Actions and no leaf-local promotion secret.

## Preserve these invariants

1. The leaf consumes already-verified external authority claims and contains no reusable signing secret.
2. Principal and zone identity are inherited exactly.
3. Route, method, region, request budget, TTL, and delegation depth may only attenuate.
4. Route containment remains segment-aware.
5. Mint and request nonces remain replay-protected.
6. Capability digests bind every authorization claim and the parent digest.
7. Revocation fails closed for both use and further delegation.
8. Canonicalization rejects NaN/Inf, unsupported values, and non-string mapping keys.
9. `scripts/source_sha.py` remains the canonical self-verification implementation for the repository source tree.
10. No Cloudflare affiliation, proprietary-system equivalence, production deployment, or customer-impact claim may be introduced without independent evidence.

## Current proof surfaces

- `machine/implementation-proof.json` — source SHA `c7b84391e7668e34550dca0d9c2f94d82daf65e330acf1e8a28ea778025d9dcc`
- `machine/proof_receipt.json` — sanitized GitHub Actions receipt
- `machine/operability_receipt.json` — mint/delegate/use/revoke proof
- `machine/verification-matrix.json` — 14 domain adversarial controls
- `scripts/source_sha.py` — canonical source proof utility
- GitHub Actions run `31461779549`, artifact `9090034603`

## Remaining gates are external/deployment gates

- cryptographic external root-grant verification
- distributed nonce/usage/revocation storage
- production edge adapter and trusted clock policy
- external authenticated promotion authority
- canonical estate-position resolution

Do not represent those external boundaries as already deployed, and do not downgrade the proven mechanism back into a generic evaluator or scaffold.
