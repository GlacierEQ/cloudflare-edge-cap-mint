"""Deterministic Edge Capability Mint.

Independent GlacierEQ reference implementation. No Cloudflare affiliation or
claim of equivalence to Cloudflare internal authorization machinery.

The public leaf consumes already-verified external authority claims; it does not
contain a signing key or mint promotion authority.
"""
from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping


EXTERNAL_ISSUER = "external-edge-authority"
_ALLOWED_METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"})


class Decision(str, Enum):
    ALLOW = "ALLOW"
    REFUSE = "REFUSE"


class CapabilityError(ValueError):
    """Raised when an object cannot be represented canonically."""


def _canonical(value: Any) -> Any:
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise CapabilityError("non_finite_number")
        return value
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Mapping):
        out: dict[str, Any] = {}
        for key in sorted(value):
            if not isinstance(key, str):
                raise CapabilityError("mapping_key_not_string")
            out[key] = _canonical(value[key])
        return out
    if isinstance(value, (list, tuple)):
        return [_canonical(v) for v in value]
    raise CapabilityError(f"unsupported_canonical_type:{type(value).__name__}")


def _digest(value: Any) -> str:
    payload = json.dumps(
        _canonical(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _clean_path(path: str) -> str:
    if not isinstance(path, str) or not path.startswith("/") or "?" in path or "#" in path:
        raise CapabilityError("route_invalid")
    if "//" in path or "/../" in f"{path}/" or "/./" in f"{path}/":
        raise CapabilityError("route_invalid")
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")
    return path


def _within_route(child: str, parent: str) -> bool:
    child = _clean_path(child)
    parent = _clean_path(parent)
    if parent == "/":
        return True
    return child == parent or child.startswith(parent + "/")


def _normalize_methods(methods: tuple[str, ...]) -> tuple[str, ...]:
    normalized = tuple(sorted({str(m).upper() for m in methods}))
    if not normalized or any(m not in _ALLOWED_METHODS for m in normalized):
        raise CapabilityError("method_invalid")
    return normalized


def _normalize_regions(regions: tuple[str, ...]) -> tuple[str, ...]:
    normalized = tuple(sorted({str(r).strip().lower() for r in regions if str(r).strip()}))
    if not normalized:
        raise CapabilityError("region_scope_empty")
    return normalized


def _finite_number(value: float, name: str, *, positive: bool = False) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)):
        raise CapabilityError(f"{name}_invalid")
    out = float(value)
    if positive and out <= 0:
        raise CapabilityError(f"{name}_non_positive")
    return out


@dataclass(frozen=True)
class VerifiedAuthorityGrant:
    grant_id: str
    issuer: str
    verification_ref: str
    principal_id: str
    zone_id: str
    route_prefix: str
    methods: tuple[str, ...]
    regions: tuple[str, ...]
    issued_at: float
    not_after: float
    max_requests: int
    max_delegation_depth: int

    def normalized(self) -> "VerifiedAuthorityGrant":
        if not self.grant_id.strip():
            raise CapabilityError("grant_id_missing")
        if self.issuer != EXTERNAL_ISSUER:
            raise CapabilityError("issuer_not_external")
        if not self.verification_ref.strip():
            raise CapabilityError("verification_ref_missing")
        if not self.principal_id.strip():
            raise CapabilityError("principal_id_missing")
        if not self.zone_id.strip():
            raise CapabilityError("zone_id_missing")
        issued = _finite_number(self.issued_at, "issued_at")
        expiry = _finite_number(self.not_after, "not_after")
        if expiry <= issued:
            raise CapabilityError("grant_window_invalid")
        if isinstance(self.max_requests, bool) or self.max_requests <= 0:
            raise CapabilityError("max_requests_non_positive")
        if isinstance(self.max_delegation_depth, bool) or self.max_delegation_depth < 0:
            raise CapabilityError("delegation_depth_invalid")
        return VerifiedAuthorityGrant(
            grant_id=self.grant_id.strip(), issuer=self.issuer,
            verification_ref=self.verification_ref.strip(),
            principal_id=self.principal_id.strip(), zone_id=self.zone_id.strip(),
            route_prefix=_clean_path(self.route_prefix), methods=_normalize_methods(self.methods),
            regions=_normalize_regions(self.regions), issued_at=issued, not_after=expiry,
            max_requests=int(self.max_requests), max_delegation_depth=int(self.max_delegation_depth),
        )


@dataclass(frozen=True)
class MintSpec:
    capability_id: str
    route_prefix: str
    methods: tuple[str, ...]
    regions: tuple[str, ...]
    ttl_seconds: float
    max_requests: int
    delegation_remaining: int
    mint_nonce: str


@dataclass(frozen=True)
class EdgeCapability:
    capability_id: str
    issuer: str
    authority_ref: str
    principal_id: str
    zone_id: str
    route_prefix: str
    methods: tuple[str, ...]
    regions: tuple[str, ...]
    issued_at: float
    not_after: float
    max_requests: int
    delegation_remaining: int
    mint_nonce: str
    parent_digest: str
    digest: str

    def claims(self) -> dict[str, Any]:
        return {
            "capability_id": self.capability_id, "issuer": self.issuer,
            "authority_ref": self.authority_ref, "principal_id": self.principal_id,
            "zone_id": self.zone_id, "route_prefix": self.route_prefix,
            "methods": list(self.methods), "regions": list(self.regions),
            "issued_at": self.issued_at, "not_after": self.not_after,
            "max_requests": self.max_requests, "delegation_remaining": self.delegation_remaining,
            "mint_nonce": self.mint_nonce, "parent_digest": self.parent_digest,
        }


@dataclass(frozen=True)
class EdgeRequest:
    principal_id: str
    zone_id: str
    route: str
    method: str
    region: str
    request_nonce: str
    metadata: Mapping[str, Any] | None = None


@dataclass(frozen=True)
class MintReceipt:
    decision: Decision
    reasons: tuple[str, ...]
    digest: str
    capability: EdgeCapability | None

    def as_dict(self) -> dict[str, Any]:
        return {"decision": self.decision.value, "reasons": list(self.reasons), "digest": self.digest,
                "capability": None if self.capability is None else {**self.capability.claims(), "digest": self.capability.digest}}


@dataclass(frozen=True)
class UseReceipt:
    decision: Decision
    reasons: tuple[str, ...]
    digest: str
    capability_digest: str
    usage_after: int

    def as_dict(self) -> dict[str, Any]:
        return {"decision": self.decision.value, "reasons": list(self.reasons), "digest": self.digest,
                "capability_digest": self.capability_digest, "usage_after": self.usage_after}


class EdgeCapMint:
    """Capability attenuation and edge-use admission reference mechanism."""

    def __init__(self) -> None:
        self._used_mint_nonces: set[str] = set()
        self._used_request_nonces: set[tuple[str, str]] = set()
        self._usage: dict[str, int] = {}
        self._revoked: set[str] = set()

    @staticmethod
    def _parent_claims(parent: VerifiedAuthorityGrant | EdgeCapability) -> dict[str, Any]:
        if isinstance(parent, VerifiedAuthorityGrant):
            p = parent.normalized()
            return {"kind": "verified_grant", "id": p.grant_id, "issuer": p.issuer,
                    "authority_ref": p.verification_ref, "principal_id": p.principal_id,
                    "zone_id": p.zone_id, "route_prefix": p.route_prefix, "methods": p.methods,
                    "regions": p.regions, "issued_at": p.issued_at, "not_after": p.not_after,
                    "max_requests": p.max_requests, "delegation_remaining": p.max_delegation_depth,
                    "digest": _digest({"grant_id": p.grant_id, "issuer": p.issuer,
                    "verification_ref": p.verification_ref, "principal_id": p.principal_id,
                    "zone_id": p.zone_id, "route_prefix": p.route_prefix, "methods": p.methods,
                    "regions": p.regions, "issued_at": p.issued_at, "not_after": p.not_after,
                    "max_requests": p.max_requests, "max_delegation_depth": p.max_delegation_depth})}
        return {"kind": "capability", "id": parent.capability_id, "issuer": parent.issuer,
                "authority_ref": parent.authority_ref, "principal_id": parent.principal_id,
                "zone_id": parent.zone_id, "route_prefix": parent.route_prefix, "methods": parent.methods,
                "regions": parent.regions, "issued_at": parent.issued_at, "not_after": parent.not_after,
                "max_requests": parent.max_requests, "delegation_remaining": parent.delegation_remaining,
                "digest": parent.digest}

    def mint(self, parent: VerifiedAuthorityGrant | EdgeCapability, spec: MintSpec, *, now: float) -> MintReceipt:
        reasons: list[str] = []
        try:
            now = _finite_number(now, "now")
            p = self._parent_claims(parent)
            cap_id = spec.capability_id.strip()
            if not cap_id: reasons.append("capability_id_missing")
            route = _clean_path(spec.route_prefix)
            methods = _normalize_methods(spec.methods)
            regions = _normalize_regions(spec.regions)
            ttl = _finite_number(spec.ttl_seconds, "ttl_seconds", positive=True)
            if isinstance(spec.max_requests, bool) or spec.max_requests <= 0: reasons.append("max_requests_non_positive")
            if isinstance(spec.delegation_remaining, bool) or spec.delegation_remaining < 0: reasons.append("delegation_remaining_invalid")
            nonce = spec.mint_nonce.strip()
            if not nonce: reasons.append("mint_nonce_missing")
            if now < p["issued_at"]: reasons.append("parent_not_active")
            if now > p["not_after"]: reasons.append("parent_expired")
            if p["kind"] == "capability":
                if p["id"] in self._revoked or p["digest"] in self._revoked: reasons.append("parent_revoked")
                if p["delegation_remaining"] <= 0: reasons.append("delegation_exhausted")
            if not _within_route(route, p["route_prefix"]): reasons.append("route_scope_expansion")
            if not set(methods).issubset(set(p["methods"])): reasons.append("method_scope_expansion")
            if not set(regions).issubset(set(p["regions"])): reasons.append("region_scope_expansion")
            if spec.max_requests > p["max_requests"]: reasons.append("request_budget_expansion")
            max_child_delegation = p["delegation_remaining"] - 1 if p["kind"] == "capability" else p["delegation_remaining"]
            if spec.delegation_remaining > max_child_delegation: reasons.append("delegation_scope_expansion")
            if nonce in self._used_mint_nonces: reasons.append("mint_nonce_replay")
            not_after = min(now + ttl, p["not_after"])
            if not_after <= now: reasons.append("ttl_outside_parent_window")
            attempted = {"parent_digest": p["digest"], "capability_id": cap_id,
                         "principal_id": p["principal_id"], "zone_id": p["zone_id"],
                         "route_prefix": route, "methods": methods, "regions": regions,
                         "issued_at": now, "not_after": not_after, "max_requests": spec.max_requests,
                         "delegation_remaining": spec.delegation_remaining, "mint_nonce": nonce}
        except CapabilityError as exc:
            reasons.append(str(exc)); p = {"digest": "invalid-parent"}
            attempted = {"error": str(exc), "spec": {"capability_id": spec.capability_id,
                         "route_prefix": spec.route_prefix, "methods": spec.methods, "regions": spec.regions,
                         "ttl_seconds": spec.ttl_seconds, "max_requests": spec.max_requests,
                         "delegation_remaining": spec.delegation_remaining, "mint_nonce": spec.mint_nonce}}
        if reasons:
            body = {"decision": Decision.REFUSE.value, "reasons": sorted(set(reasons)), "attempt": attempted}
            return MintReceipt(Decision.REFUSE, tuple(sorted(set(reasons))), _digest(body), None)
        cap_claims = {**attempted, "issuer": EXTERNAL_ISSUER, "authority_ref": p["authority_ref"]}
        cap_digest = _digest(cap_claims)
        cap = EdgeCapability(capability_id=attempted["capability_id"], issuer=EXTERNAL_ISSUER,
            authority_ref=p["authority_ref"], principal_id=attempted["principal_id"], zone_id=attempted["zone_id"],
            route_prefix=attempted["route_prefix"], methods=attempted["methods"], regions=attempted["regions"],
            issued_at=attempted["issued_at"], not_after=attempted["not_after"], max_requests=attempted["max_requests"],
            delegation_remaining=attempted["delegation_remaining"], mint_nonce=attempted["mint_nonce"],
            parent_digest=p["digest"], digest=cap_digest)
        self._used_mint_nonces.add(spec.mint_nonce.strip())
        return MintReceipt(Decision.ALLOW, ("capability_attenuated",),
                           _digest({"decision": "ALLOW", "capability_digest": cap_digest, "parent_digest": p["digest"]}), cap)

    def revoke(self, capability: EdgeCapability) -> str:
        self._revoked.add(capability.capability_id); self._revoked.add(capability.digest)
        return _digest({"event": "revoke", "capability_id": capability.capability_id, "digest": capability.digest})

    def authorize(self, capability: EdgeCapability, request: EdgeRequest, *, now: float) -> UseReceipt:
        reasons: list[str] = []
        try:
            now = _finite_number(now, "now"); route = _clean_path(request.route); method = str(request.method).upper()
            if method not in _ALLOWED_METHODS: reasons.append("method_invalid")
            region = request.region.strip().lower()
            if not region: reasons.append("region_missing")
            nonce = request.request_nonce.strip()
            if not nonce: reasons.append("request_nonce_missing")
            canonical_metadata = _canonical(request.metadata or {})
            if capability.issuer != EXTERNAL_ISSUER: reasons.append("capability_issuer_invalid")
            if _digest(capability.claims()) != capability.digest: reasons.append("capability_digest_mismatch")
            if capability.capability_id in self._revoked or capability.digest in self._revoked: reasons.append("capability_revoked")
            if now < capability.issued_at: reasons.append("capability_not_active")
            if now > capability.not_after: reasons.append("capability_expired")
            if request.principal_id != capability.principal_id: reasons.append("principal_mismatch")
            if request.zone_id != capability.zone_id: reasons.append("zone_mismatch")
            if not _within_route(route, capability.route_prefix): reasons.append("route_out_of_scope")
            if method not in capability.methods: reasons.append("method_out_of_scope")
            if region not in capability.regions: reasons.append("region_out_of_scope")
            nonce_key = (capability.digest, nonce)
            if nonce_key in self._used_request_nonces: reasons.append("request_nonce_replay")
            usage_before = self._usage.get(capability.digest, 0)
            if usage_before >= capability.max_requests: reasons.append("request_budget_exhausted")
        except CapabilityError as exc:
            reasons.append(str(exc)); route = request.route; method = str(request.method).upper(); region = request.region
            nonce = request.request_nonce; usage_before = self._usage.get(capability.digest, 0)
            nonce_key = (capability.digest, str(nonce)); canonical_metadata = {"canonicalization_error": str(exc)}
        decision = Decision.REFUSE if reasons else Decision.ALLOW; usage_after = usage_before
        if decision is Decision.ALLOW:
            self._used_request_nonces.add(nonce_key); usage_after = usage_before + 1; self._usage[capability.digest] = usage_after
        body = {"decision": decision.value, "reasons": sorted(set(reasons)) if reasons else ["capability_use_allowed"],
                "capability_digest": capability.digest, "principal_id": request.principal_id, "zone_id": request.zone_id,
                "route": route, "method": method, "region": region, "request_nonce": nonce,
                "metadata": canonical_metadata, "usage_before": usage_before, "usage_after": usage_after}
        return UseReceipt(decision, tuple(body["reasons"]), _digest(body), capability.digest, usage_after)


Mechanism = EdgeCapMint
