# Architecture — Edge Capability Mint

This is an independent GlacierEQ reference implementation aligned to edge-runtime security problems; it does not reproduce Cloudflare internals.

## Recruiter layer

Edge Cap Mint turns a broad, already-verified authority grant into narrowly bounded, short-lived capabilities for distributed agent work. Delegation can only make authority weaker.

## Master layer

### Attenuation law

For parent **P** and child **C**, minting requires `C.route ⊆ P.route`, `C.methods ⊆ P.methods`, `C.regions ⊆ P.regions`, `C.max_requests <= P.max_requests`, `C.not_after <= P.not_after`, and decreasing delegation depth. Principal and zone are inherited exactly.

The child digest binds all inherited and attenuated claims plus the parent digest, creating transitive provenance without a leaf-local secret.

### Mint pipeline

1. Normalize the already-verified external authority grant.
2. Reject an unknown issuer or missing external verification reference.
3. Validate parent activation and expiry.
4. Canonicalize route, methods, and regions.
5. Enforce path-segment route containment.
6. Enforce method and region subsets.
7. Enforce request-budget and delegation-depth attenuation.
8. Reject mint-nonce replay.
9. Clip child expiry to parent expiry.
10. Bind child claims and parent digest into SHA-256 receipts.

### Use pipeline

1. Recompute the capability digest.
2. Refuse claim tampering or revocation.
3. Enforce time, principal, zone, route, method, and region.
4. Reject request-nonce replay.
5. Enforce request-consumption budget.
6. Reject non-canonical metadata.
7. Emit a deterministic receipt and increment usage only on ALLOW.

### Route containment

String prefix checks are unsafe: `/api/agent` must not authorize `/api/agent-admin`. The implementation requires equality or `parent + "/"` segment containment.

### Threat model

| Threat | Control |
|---|---|
| leaf-local fake authority | exact external issuer + verification reference |
| child route expansion | segment-aware route subset |
| HTTP privilege expansion | method subset |
| geography expansion | region subset |
| quota amplification | request-budget attenuation |
| delegation amplification | depth attenuation |
| mint replay | one-time mint nonce |
| request replay | capability-bound request nonce |
| claim tampering | recomputed deterministic digest |
| stale authority | activation/expiry checks |
| compromised capability | explicit revocation |
| ambiguous metadata | canonical JSON, finite values only |

## Machine layer

`machine/architecture.json`, `machine/verification-matrix.json`, `machine/target-contract.json`, and `machine/excellence-state.json` mirror the mechanism. Current-source proof will bind `src/`, `scripts/`, and `tests/` bytes.

## Mesh layer

Productionization remains explicitly outside this public leaf: cryptographic root-grant verification, distributed nonce/usage accounting, global revocation propagation, trusted clock policy, transactional coupling to real edge side effects, environment adapters, and estate-level promotion/canonical-position authority.
