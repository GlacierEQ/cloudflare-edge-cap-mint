# Engineering Handoff — Edge Cap Mint

## Current phase

`IMPLEMENTED` until the current source-bound proof receipt is committed. The previous generic Wave C `PROMOTED` state is revoked.

## Preserve these invariants

1. The leaf consumes already-verified external authority claims and contains no reusable signing secret.
2. Principal and zone identity are inherited exactly.
3. Route, method, region, request budget, TTL, and delegation depth may only attenuate.
4. Route containment remains segment-aware.
5. Mint and request nonces remain replay-protected.
6. Capability digests bind every authorization claim and the parent digest.
7. Revocation fails closed for both use and further delegation.
8. Canonicalization rejects NaN/Inf, unsupported values, and non-string mapping keys.
9. No Cloudflare affiliation, proprietary-system equivalence, production deployment, or customer-impact claim may be introduced without independent evidence.

## Proof surfaces

- `tests/test_edge_cap_mint.py`
- `tests/test_adversarial.py`
- `scripts/operate.py`
- `machine/verification-matrix.json`
- `ARCHITECTURE.md`

## Remaining after repository-local proof

- cryptographic external root-grant verification
- distributed nonce/usage/revocation storage
- production edge adapter
- external promotion authority
- canonical estate-position resolution
