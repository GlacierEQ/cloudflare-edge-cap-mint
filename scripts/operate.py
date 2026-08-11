#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from edge_cap_mint import Decision, EdgeCapMint, EdgeRequest, MintSpec, VerifiedAuthorityGrant


def main() -> int:
    mint = EdgeCapMint()
    root = VerifiedAuthorityGrant(
        grant_id="authority-2026-08-10", issuer="external-edge-authority",
        verification_ref="kms://external/edge/root", principal_id="dispatch-agent",
        zone_id="portfolio-zone", route_prefix="/agent", methods=("GET", "POST"),
        regions=("hnl", "sfo"), issued_at=1000.0, not_after=1120.0,
        max_requests=5, max_delegation_depth=2,
    )
    root_mint = mint.mint(
        root,
        MintSpec("dispatch-cap", "/agent/tasks", ("GET", "POST"), ("hnl",), 60.0, 3, 1, "mint-root-001"),
        now=1010.0,
    )
    if root_mint.decision is not Decision.ALLOW or root_mint.capability is None:
        raise SystemExit("root capability mint failed")
    cap = root_mint.capability

    allowed_use = mint.authorize(
        cap,
        EdgeRequest("dispatch-agent", "portfolio-zone", "/agent/tasks/42", "POST", "hnl", "request-001", {"payload_bytes": 1024}),
        now=1020.0,
    )
    child_mint = mint.mint(
        cap,
        MintSpec("status-child", "/agent/tasks/status", ("GET",), ("hnl",), 20.0, 1, 0, "mint-child-001"),
        now=1021.0,
    )
    if child_mint.capability is None:
        raise SystemExit("child capability mint failed")
    expansion_refusal = mint.authorize(
        child_mint.capability,
        EdgeRequest("dispatch-agent", "portfolio-zone", "/agent/tasks/status", "POST", "hnl", "request-002"),
        now=1022.0,
    )
    revoke_digest = mint.revoke(cap)
    revoked_use = mint.authorize(
        cap,
        EdgeRequest("dispatch-agent", "portfolio-zone", "/agent/tasks/43", "GET", "hnl", "request-003"),
        now=1023.0,
    )
    result = {
        "status": "PASS",
        "root_mint": root_mint.as_dict(),
        "allowed_use": allowed_use.as_dict(),
        "child_mint": child_mint.as_dict(),
        "scope_expansion_refusal": expansion_refusal.as_dict(),
        "revoke_digest": revoke_digest,
        "revoked_use": revoked_use.as_dict(),
    }
    assert allowed_use.decision is Decision.ALLOW
    assert child_mint.decision is Decision.ALLOW
    assert expansion_refusal.decision is Decision.REFUSE
    assert revoked_use.decision is Decision.REFUSE
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
