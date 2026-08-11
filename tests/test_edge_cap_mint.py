from edge_cap_mint import (
    Decision,
    EdgeCapMint,
    EdgeRequest,
    MintSpec,
    VerifiedAuthorityGrant,
)


def grant(**overrides):
    data = dict(
        grant_id="root-1",
        issuer="external-edge-authority",
        verification_ref="kms://authority/root-1",
        principal_id="agent-7",
        zone_id="zone-a",
        route_prefix="/agent",
        methods=("GET", "POST"),
        regions=("hnl", "sfo"),
        issued_at=1000.0,
        not_after=1100.0,
        max_requests=5,
        max_delegation_depth=2,
    )
    data.update(overrides)
    return VerifiedAuthorityGrant(**data)


def spec(**overrides):
    data = dict(
        capability_id="cap-1",
        route_prefix="/agent/tasks",
        methods=("GET", "POST"),
        regions=("hnl",),
        ttl_seconds=60.0,
        max_requests=3,
        delegation_remaining=1,
        mint_nonce="mint-1",
    )
    data.update(overrides)
    return MintSpec(**data)


def minted(mint: EdgeCapMint | None = None):
    mint = mint or EdgeCapMint()
    receipt = mint.mint(grant(), spec(), now=1010.0)
    assert receipt.decision is Decision.ALLOW
    assert receipt.capability is not None
    return mint, receipt.capability


def test_root_grant_mints_attenuated_capability():
    mint = EdgeCapMint()
    receipt = mint.mint(grant(), spec(), now=1010.0)
    assert receipt.decision is Decision.ALLOW
    cap = receipt.capability
    assert cap is not None
    assert cap.route_prefix == "/agent/tasks"
    assert cap.regions == ("hnl",)
    assert cap.not_after == 1070.0
    assert cap.parent_digest
    assert len(cap.digest) == 64


def test_authorize_in_scope_request_and_increment_budget():
    mint, cap = minted()
    out = mint.authorize(
        cap,
        EdgeRequest("agent-7", "zone-a", "/agent/tasks/42", "POST", "hnl", "req-1", {"bytes": 512}),
        now=1020.0,
    )
    assert out.decision is Decision.ALLOW
    assert out.usage_after == 1


def test_child_delegation_is_stricter_than_parent_capability():
    mint, cap = minted()
    child = mint.mint(
        cap,
        spec(
            capability_id="cap-child",
            route_prefix="/agent/tasks/status",
            methods=("GET",),
            regions=("hnl",),
            ttl_seconds=20.0,
            max_requests=1,
            delegation_remaining=0,
            mint_nonce="mint-child",
        ),
        now=1020.0,
    )
    assert child.decision is Decision.ALLOW
    assert child.capability is not None
    assert child.capability.parent_digest == cap.digest
    assert child.capability.delegation_remaining == 0


def test_revoke_blocks_future_use():
    mint, cap = minted()
    receipt = mint.revoke(cap)
    assert len(receipt) == 64
    out = mint.authorize(
        cap,
        EdgeRequest("agent-7", "zone-a", "/agent/tasks", "GET", "hnl", "req-revoked"),
        now=1020.0,
    )
    assert out.decision is Decision.REFUSE
    assert "capability_revoked" in out.reasons


def test_request_budget_is_enforced():
    mint = EdgeCapMint()
    root = grant(max_requests=1)
    cap = mint.mint(root, spec(max_requests=1), now=1010.0).capability
    assert cap is not None
    first = mint.authorize(cap, EdgeRequest("agent-7", "zone-a", "/agent/tasks", "GET", "hnl", "r1"), now=1020.0)
    second = mint.authorize(cap, EdgeRequest("agent-7", "zone-a", "/agent/tasks", "GET", "hnl", "r2"), now=1021.0)
    assert first.decision is Decision.ALLOW
    assert second.decision is Decision.REFUSE
    assert "request_budget_exhausted" in second.reasons


def test_receipt_digest_changes_with_request_inputs():
    m1, cap1 = minted()
    a = m1.authorize(cap1, EdgeRequest("agent-7", "zone-a", "/agent/tasks/1", "GET", "hnl", "ra"), now=1020.0)
    m2, cap2 = minted()
    b = m2.authorize(cap2, EdgeRequest("agent-7", "zone-a", "/agent/tasks/2", "GET", "hnl", "rb"), now=1020.0)
    assert a.digest != b.digest


def test_parent_expiry_caps_child_ttl():
    mint = EdgeCapMint()
    cap = mint.mint(grant(not_after=1030.0), spec(ttl_seconds=100.0), now=1010.0).capability
    assert cap is not None
    assert cap.not_after == 1030.0


def test_route_boundary_does_not_confuse_prefix_strings():
    mint, cap = minted()
    out = mint.authorize(
        cap,
        EdgeRequest("agent-7", "zone-a", "/agent/tasksmith", "GET", "hnl", "boundary"),
        now=1020.0,
    )
    assert out.decision is Decision.REFUSE
    assert "route_out_of_scope" in out.reasons
