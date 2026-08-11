# Edge Cap Mint

Independent GlacierEQ portfolio exhibit aligned to **Cloudflare** operating themes.

> **Not affiliated.** This repository is not affiliated with, endorsed by, employed by, or deployed at Cloudflare.
> No proprietary access, production deployment, customer impact, or company partnership is claimed.

## Bottleneck

Globally distributed agents need fast edge-local actions without turning a long-lived credential into ambient authority.

**Brick wall:** A valid root identity is too broad. Edge work needs short-lived capabilities that can be narrowed by route, HTTP method, region, lifetime, request budget, and delegation depth—and must fail closed under replay, forgery, revocation, or scope expansion.

## Implemented mechanism

**Edge Cap Mint** is a deterministic capability-attenuation and edge-use admission engine.

A verified external authority grant can mint a narrower edge capability. A minted capability can delegate again only by **monotonically reducing** authority.

### Bound dimensions

- principal identity
- zone identity
- route prefix with segment-boundary semantics
- HTTP methods
- edge regions
- activation + expiry
- maximum request count
- delegation depth
- mint nonce
- per-request replay nonce
- parent capability digest

### Core invariants

1. The public leaf consumes an already-verified external grant; it does not contain a signing key.
2. A child route must remain inside its parent's route boundary.
3. Child methods and regions must be subsets of the parent.
4. Child request budgets cannot grow.
5. Child delegation depth cannot grow.
6. Child TTL is clipped to the parent expiry.
7. Mint nonces cannot be reused.
8. Request nonces cannot be replayed under the same capability.
9. Mutating any bound capability claim breaks its deterministic digest.
10. Revoked capabilities and descendants used as parents fail closed.
11. NaN/Inf and unsupported metadata types are rejected rather than coerced.

## Why this is technically interesting

The mechanism treats authorization as a **monotone lattice** rather than a boolean permission check. Every delegation step can only move downward in authority.

That gives the system a simple safety property: no child capability can obtain a route, method, region, request budget, lifetime, or delegation power that its parent did not already possess.

At use time, capability identity, request scope, replay state, revocation state, and consumption budget converge into one deterministic decision receipt.

See `ARCHITECTURE.md` for the expert design, threat model, attenuation law, receipt semantics, and deployment boundaries.

## Direct proof

`scripts/operate.py` demonstrates:

- external verified root grant → attenuated dispatch capability **ALLOW**
- in-scope POST at the allowed edge region → **ALLOW**
- stricter delegated GET-only child capability → **ALLOW**
- POST attempt through GET-only child → **REFUSE**
- explicit revoke → subsequent root-capability use **REFUSE**

## Surfaces

| Surface | Path |
|---|---|
| Core mechanism | `src/edge_cap_mint.py` |
| Direct operate flow | `scripts/operate.py` |
| Behavioral tests | `tests/test_edge_cap_mint.py` |
| Adversarial tests | `tests/test_adversarial.py` |
| Expert architecture | `ARCHITECTURE.md` |
| Machine architecture | `machine/architecture.json` |
| Verification matrix | `machine/verification-matrix.json` |
| Target contract | `machine/target-contract.json` |
| Excellence state | `machine/excellence-state.json` |
| Engineering handoff | `DEV_UP_INSTRUCTIONS.md` |

## Current state

The former Wave C scaffold promotion is revoked. The real mechanism is **IMPLEMENTED** and is being driven through current-source proof.

No local promotion secret or stale scaffold proof is retained.

## Non-claims

- No Cloudflare employment, endorsement, proprietary data, internal implementation equivalence, or production use
- No customer, traffic, latency, scale, or security-effectiveness claim beyond repository-local tests
- No production credential or promotion signing secret is embedded
- The `VerifiedAuthorityGrant` type models claims already authenticated by an external authority; this leaf does not provide that external cryptographic verification layer
