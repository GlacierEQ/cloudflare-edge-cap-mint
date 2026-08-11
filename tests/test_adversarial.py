from dataclasses import replace

from edge_cap_mint import Decision, EdgeCapMint, EdgeRequest, MintSpec, VerifiedAuthorityGrant


def root(**overrides):
    data = dict(
        grant_id="g", issuer="external-edge-authority", verification_ref="kms://authority/g",
        principal_id="p", zone_id="z", route_prefix="/api", methods=("GET", "POST"),
        regions=("hnl", "sfo"), issued_at=10.0, not_after=100.0,
        max_requests=4, max_delegation_depth=1,
    )
    data.update(overrides)
    return VerifiedAuthorityGrant(**data)


def spec(**overrides):
    data = dict(
        capability_id="c", route_prefix="/api/agent", methods=("GET",), regions=("hnl",),
        ttl_seconds=30.0, max_requests=2, delegation_remaining=0, mint_nonce="m",
    )
    data.update(overrides)
    return MintSpec(**data)


def cap():
    mint = EdgeCapMint()
    c = mint.mint(root(), spec(), now=20.0).capability
    assert c is not None
    return mint, c


def test_wrong_external_issuer_refuses_mint():
    out = EdgeCapMint().mint(root(issuer="leaf-local"), spec(), now=20.0)
    assert out.decision is Decision.REFUSE
    assert "issuer_not_external" in out.reasons


def test_route_scope_expansion_refuses_mint():
    out = EdgeCapMint().mint(root(), spec(route_prefix="/admin"), now=20.0)
    assert out.decision is Decision.REFUSE
    assert "route_scope_expansion" in out.reasons


def test_method_scope_expansion_refuses_mint():
    out = EdgeCapMint().mint(root(), spec(methods=("DELETE",)), now=20.0)
    assert out.decision is Decision.REFUSE
    assert "method_scope_expansion" in out.reasons


def test_region_scope_expansion_refuses_mint():
    out = EdgeCapMint().mint(root(), spec(regions=("lhr",)), now=20.0)
    assert out.decision is Decision.REFUSE
    assert "region_scope_expansion" in out.reasons


def test_request_budget_expansion_refuses_mint():
    out = EdgeCapMint().mint(root(max_requests=1), spec(max_requests=2), now=20.0)
    assert out.decision is Decision.REFUSE
    assert "request_budget_expansion" in out.reasons


def test_delegation_expansion_refuses_mint():
    out = EdgeCapMint().mint(root(max_delegation_depth=0), spec(delegation_remaining=1), now=20.0)
    assert out.decision is Decision.REFUSE
    assert "delegation_scope_expansion" in out.reasons


def test_mint_nonce_replay_refuses_second_capability():
    mint = EdgeCapMint()
    first = mint.mint(root(), spec(), now=20.0)
    second = mint.mint(root(), spec(capability_id="c2"), now=21.0)
    assert first.decision is Decision.ALLOW
    assert second.decision is Decision.REFUSE
    assert "mint_nonce_replay" in second.reasons


def test_request_nonce_replay_refuses_second_use():
    mint, c = cap()
    req = EdgeRequest("p", "z", "/api/agent", "GET", "hnl", "same")
    assert mint.authorize(c, req, now=30.0).decision is Decision.ALLOW
    second = mint.authorize(c, req, now=31.0)
    assert second.decision is Decision.REFUSE
    assert "request_nonce_replay" in second.reasons


def test_principal_zone_method_region_and_route_are_independently_bound():
    cases = [
        (EdgeRequest("other", "z", "/api/agent", "GET", "hnl", "n1"), "principal_mismatch"),
        (EdgeRequest("p", "other", "/api/agent", "GET", "hnl", "n2"), "zone_mismatch"),
        (EdgeRequest("p", "z", "/api/agent", "POST", "hnl", "n3"), "method_out_of_scope"),
        (EdgeRequest("p", "z", "/api/agent", "GET", "sfo", "n4"), "region_out_of_scope"),
        (EdgeRequest("p", "z", "/api/admin", "GET", "hnl", "n5"), "route_out_of_scope"),
    ]
    for request, reason in cases:
        mint, c = cap()
        out = mint.authorize(c, request, now=30.0)
        assert out.decision is Decision.REFUSE
        assert reason in out.reasons


def test_expired_and_future_capabilities_fail_closed():
    mint, c = cap()
    assert "capability_not_active" in mint.authorize(
        c, EdgeRequest("p", "z", "/api/agent", "GET", "hnl", "early"), now=19.0
    ).reasons
    assert "capability_expired" in mint.authorize(
        c, EdgeRequest("p", "z", "/api/agent", "GET", "hnl", "late"), now=60.0
    ).reasons


def test_forged_capability_claims_break_digest_binding():
    mint, c = cap()
    forged = replace(c, route_prefix="/")
    out = mint.authorize(forged, EdgeRequest("p", "z", "/anything", "GET", "hnl", "forged"), now=30.0)
    assert out.decision is Decision.REFUSE
    assert "capability_digest_mismatch" in out.reasons


def test_non_finite_metadata_refuses_use():
    mint, c = cap()
    out = mint.authorize(
        c, EdgeRequest("p", "z", "/api/agent", "GET", "hnl", "nan", {"score": float("nan")}), now=30.0
    )
    assert out.decision is Decision.REFUSE
    assert "non_finite_number" in out.reasons


def test_unsupported_metadata_type_refuses_use():
    mint, c = cap()
    out = mint.authorize(
        c, EdgeRequest("p", "z", "/api/agent", "GET", "hnl", "set", {"x": {1, 2}}), now=30.0
    )
    assert out.decision is Decision.REFUSE
    assert any(r.startswith("unsupported_canonical_type") for r in out.reasons)


def test_delegated_child_cannot_re_expand_parent_method():
    mint = EdgeCapMint()
    parent = mint.mint(
        root(methods=("GET", "POST"), max_delegation_depth=2),
        spec(methods=("GET",), delegation_remaining=1), now=20.0,
    ).capability
    assert parent is not None
    child = mint.mint(
        parent,
        spec(capability_id="child", route_prefix="/api/agent", methods=("POST",), regions=("hnl",),
             ttl_seconds=10, max_requests=1, delegation_remaining=0, mint_nonce="child-nonce"),
        now=21.0,
    )
    assert child.decision is Decision.REFUSE
    assert "method_scope_expansion" in child.reasons
