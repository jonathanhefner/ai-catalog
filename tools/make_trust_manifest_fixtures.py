#!/usr/bin/env python3
"""Regenerate the Trust Manifest signature conformance fixtures.

Writes one JSON file per case into
``specification/conformance/trust-manifest-signatures/cases``. Every key is
derived from a fixed seed string, so the output is reproducible and the
private keys are test material only; they must never sign anything real.

The generator uses only the Python standard library, sharing the JCS and
P-256 arithmetic in ``tools/verify_trust_manifest_fixtures.py``.

Usage:
    python3 tools/make_trust_manifest_fixtures.py
"""

from __future__ import annotations

import copy
import hashlib
import json
import sys
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS_DIR))

from verify_trust_manifest_fixtures import (  # noqa: E402
    CASES_DIR,
    G,
    MANIFEST_TYP,
    N,
    b64url,
    digest_of,
    jcs,
    point_mul,
    signature_payload,
)

ISSUED_AT = "2026-10-01T00:00:00Z"
EXPIRES_AT = "2026-12-31T00:00:00Z"
VERIFY_AT = "2026-10-06T12:00:00Z"
POLICY_URLS_KEY = "https://ai-catalog.org/extensions/policy-urls"

PUBLISHER = "did:web:publisher.example"
ASSESSOR = "did:web:assessor.example"
OTHER = "did:web:other.example"


# --- test keys (derived from seed strings; TEST MATERIAL ONLY) ---------------


def test_key(seed: str) -> tuple[int, tuple[int, int]]:
    d = int.from_bytes(hashlib.sha256(f"ai-catalog fixture key: {seed}".encode()).digest(), "big") % N
    return d, point_mul(d, G)


def public_jwk(point: tuple[int, int]) -> dict:
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": b64url(point[0].to_bytes(32, "big")),
        "y": b64url(point[1].to_bytes(32, "big")),
        "use": "sig",
        "alg": "ES256",
    }


def es256_sign(d: int, signing_input: bytes) -> bytes:
    """Deterministic ECDSA P-256 signature in the JWS ``r || s`` form."""
    digest = hashlib.sha256(signing_input).digest()
    e = int.from_bytes(digest, "big")
    k = int.from_bytes(hashlib.sha256(d.to_bytes(32, "big") + digest).digest(), "big") % N or 1
    r = point_mul(k, G)[0] % N
    s = pow(k, -1, N) * (e + r * d) % N
    if s > N // 2:
        s = N - s
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


KEYS = {
    "publisher-release": test_key("publisher.example release"),
    "publisher-auth": test_key("publisher.example authentication"),
    "assessor-assessment": test_key("assessor.example assessment"),
    "other-key-1": test_key("other.example key 1"),
}


def did_document(did: str, assertion: dict[str, str], authentication: dict[str, str] | None = None,
                 controllers: dict[str, str] | None = None) -> dict:
    """``assertion`` and ``authentication`` map fragment -> KEYS name."""
    controllers = controllers or {}
    methods = []
    for fragment, key_name in {**assertion, **(authentication or {})}.items():
        methods.append({
            "id": f"{did}#{fragment}",
            "type": "JsonWebKey2020",
            "controller": controllers.get(fragment, did),
            "publicKeyJwk": public_jwk(KEYS[key_name][1]),
        })
    doc = {
        "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/jws-2020/v1"],
        "id": did,
        "verificationMethod": methods,
        "assertionMethod": [f"{did}#{fragment}" for fragment in assertion],
    }
    if authentication:
        doc["authentication"] = [f"{did}#{fragment}" for fragment in authentication]
    return doc


DID_DOCUMENTS = {
    PUBLISHER: did_document(PUBLISHER, {"release-key": "publisher-release"},
                            {"auth-key": "publisher-auth"}),
    ASSESSOR: did_document(ASSESSOR, {"assessment-key": "assessor-assessment"}),
    OTHER: did_document(OTHER, {"key-1": "other-key-1"}),
}


# --- signing -------------------------------------------------------------------


def sign_manifest(manifest: dict, key_name: str, kid: str, *, typ: str = MANIFEST_TYP) -> dict:
    """Return a copy of ``manifest`` with ``signature.jws`` filled in."""
    signed = copy.deepcopy(manifest)
    signed["signature"].pop("jws", None)
    header = b64url(jcs({"alg": "ES256", "kid": kid, "typ": typ}))
    signing_input = f"{header}.{b64url(signature_payload({**signed, 'signature': {**signed['signature'], 'jws': ''}}))}"
    raw = es256_sign(KEYS[key_name][0], signing_input.encode("ascii"))
    signed["signature"]["jws"] = f"{header}..{b64url(raw)}"
    return signed


# --- base catalog ----------------------------------------------------------------

SERVER_CARD = {
    "name": "publisher.example/demo",
    "version": "1.2.0",
    "title": "Demo MCP Server",
    "description": "Fixture server card. Numbers are integers only so that the JCS subset applies.",
    "remotes": [{"type": "streamable-http", "url": "https://mcp.publisher.example/demo"}],
    "_meta": {"publisher.example/tool-count": 2},
}
CARD_DIGEST = digest_of("sha256", jcs(SERVER_CARD))

AGENT_CARD_URL = "https://publisher.example/finance.json"
AGENT_CARD_TEXT = '{"name":"Finance Agent","url":"https://agents.publisher.example/finance","version":"2.0.1"}'
AGENT_CARD_DIGEST = digest_of("sha256", AGENT_CARD_TEXT.encode("utf-8"))

ATTACKER_URL = "https://mirror.other.example/finance.json"
ATTACKER_TEXT = '{"name":"Finance Agent","url":"https://agents.other.example/finance","version":"2.0.1"}'
ATTACKER_DIGEST = digest_of("sha256", ATTACKER_TEXT.encode("utf-8"))

POLICY_URLS = {
    "privacyPolicyUrl": "https://publisher.example/legal/privacy",
    "termsOfServiceUrl": "https://publisher.example/legal/terms",
}
POLICY_URLS_DIGEST = digest_of("sha256", jcs(POLICY_URLS))

MCP_ENTRY_ID = "urn:air:publisher.example:mcp:demo"
MCP_TYPE = "application/mcp-server-card+json"
AGENT_ENTRY_ID = "urn:air:publisher.example:agent:finance"
AGENT_TYPE = "application/a2a-agent-card+json"


def signature_object(signer: str, profile: str = "did-web-v1", issued_at: str = ISSUED_AT,
                     expires_at: str | None = EXPIRES_AT) -> dict:
    signature = {"signer": signer, "profile": profile, "issuedAt": issued_at}
    if expires_at:
        signature["expiresAt"] = expires_at
    return signature


def publisher_manifest(entry_id: str, entry_type: str, *, digest: str | None, url: str | None = None,
                       version: str | None = None, signer: str = PUBLISHER, contributor: str | None = None,
                       profile: str = "did-web-v1", issued_at: str = ISSUED_AT,
                       expires_at: str | None = EXPIRES_AT) -> dict:
    subject = {"identifier": entry_id, "type": entry_type}
    if digest:
        subject["digest"] = digest
    if url:
        subject["url"] = url
    if version:
        subject["version"] = version
    return {
        "contributor": contributor or signer,
        "subject": subject,
        "provenance": [{"relation": "publishedFrom", "sourceId": "https://github.com/publisher-example/demo"}],
        "signature": signature_object(signer, profile, issued_at, expires_at),
    }


def assessor_manifest(entry_id: str, entry_type: str, *, digest: str, contributor: str = ASSESSOR,
                      extension_digests: dict | None = None, extra: dict | None = None) -> dict:
    subject = {"identifier": entry_id, "type": entry_type, "digest": digest}
    if extension_digests:
        subject["extensionDigests"] = extension_digests
    manifest = {
        "contributor": contributor,
        "subject": subject,
        "trustSchema": {"identifier": "https://assessor.example/schema/safety", "version": "1"},
        "attestations": [{
            "type": "com.assessor.scan-report",
            "uri": "https://assessor.example/reports/publisher-example-demo.json",
            "digest": "sha256:0b5e3a7d1c2f4e6a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a",
            "size": 4096,
        }],
        "extensions": {
            "com.assessor.toolManifest": {
                "profile": "com.assessor.mcp-tool-definition.v1",
                "toolManifestDigest": "sha256:4f2a5d6e7c8b9a0f1e2d3c4b5a69788796a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1",
            },
        },
        "signature": signature_object(ASSESSOR),
    }
    if extra:
        manifest.update(extra)
    return manifest


def mcp_entry(manifests: list[dict], *, version: str | None = None) -> dict:
    entry = {
        "identifier": MCP_ENTRY_ID,
        "type": MCP_TYPE,
        "data": SERVER_CARD,
        "digest": CARD_DIGEST,
        "updatedAt": "2026-10-01T00:00:00Z",
        "publisher": {"identifier": PUBLISHER, "displayName": "Publisher Example"},
        "extensions": {POLICY_URLS_KEY: POLICY_URLS},
        "trustManifests": manifests,
    }
    if version:
        entry["version"] = version
    return entry


def agent_entry(manifests: list[dict], *, url: str = AGENT_CARD_URL, digest: str | None = AGENT_CARD_DIGEST) -> dict:
    entry = {
        "identifier": AGENT_ENTRY_ID,
        "type": AGENT_TYPE,
        "url": url,
        "updatedAt": "2026-10-01T00:00:00Z",
        "trustManifests": manifests,
    }
    if digest:
        entry["digest"] = digest
    return entry


def catalog(entries: list[dict]) -> dict:
    return {
        "specVersion": "1.0",
        "host": {"displayName": "Fixture Registry", "identifier": "did:web:registry.example"},
        "entries": entries,
    }


def reversed_members(value):
    """Reverse object member order recursively. JCS makes member order
    irrelevant; array order is left alone because it is significant."""
    if isinstance(value, dict):
        return {k: reversed_members(v) for k, v in reversed(list(value.items()))}
    return value


def case(case_id: str, title: str, spec: list[str], entries: list[dict], expect: list[dict], *,
         verify_at: str = VERIFY_AT, resources: dict | None = None, note: str | None = None) -> dict:
    fixture = {
        "id": case_id,
        "title": title,
        "spec": spec,
        "verifyAt": verify_at,
        "didDocuments": DID_DOCUMENTS,
        "catalog": catalog(entries),
        "expect": expect,
    }
    if note:
        fixture["note"] = note
    if resources:
        fixture["resources"] = resources
    return fixture


def build_cases() -> list[dict]:
    cases = []
    release_kid = f"{PUBLISHER}#release-key"
    assess_kid = f"{ASSESSOR}#assessment-key"

    signed_pub_mcp = sign_manifest(publisher_manifest(MCP_ENTRY_ID, MCP_TYPE, digest=CARD_DIGEST),
                                   "publisher-release", release_kid)
    signed_assessor = sign_manifest(
        assessor_manifest(MCP_ENTRY_ID, MCP_TYPE, digest=CARD_DIGEST,
                          extension_digests={POLICY_URLS_KEY: POLICY_URLS_DIGEST},
                          extra={"x-fixture-note": "unrecognized member; it stays in the signed payload"}),
        "assessor-assessment", assess_kid)
    signed_pub_agent = sign_manifest(
        publisher_manifest(AGENT_ENTRY_ID, AGENT_TYPE, digest=AGENT_CARD_DIGEST, url=AGENT_CARD_URL),
        "publisher-release", release_kid)
    resources = {AGENT_CARD_URL: AGENT_CARD_TEXT}

    # 00 positive control: everything reordered, both manifests still verify.
    cases.append(case(
        "00-positive-control-reordered",
        "Reordered members and reordered manifests still verify",
        ["Signed Payload and JWS Construction", "Independent Contributions and Updates",
         "Entry Release Coverage", "Extension Digest Verification"],
        [reversed_members(mcp_entry([signed_assessor, signed_pub_mcp])),
         reversed_members(agent_entry([signed_pub_agent]))],
        [
            {"entry": 0, "manifest": 0, "accepted": True,
             "extensions": {POLICY_URLS_KEY: "matched"},
             "premise": {"jwsVerifiesWith": assess_kid}},
            {"entry": 0, "manifest": 1, "accepted": True, "premise": {"jwsVerifiesWith": release_kid}},
            {"entry": 1, "manifest": 0, "accepted": True, "premise": {"jwsVerifiesWith": release_kid}},
        ],
        resources=resources,
        note="Members of every object were written in reverse order after signing and the "
             "trustManifests array was reversed. The assessor manifest carries an unrecognized "
             "member that remains part of its payload, and it authenticates the policy-urls "
             "entry extension through subject.extensionDigests.",
    ))

    # 01 contributor and signer must be byte-equal.
    for suffix, contributor in (("case-variant", "did:web:Assessor.example"),
                                ("trailing-dot", "did:web:assessor.example.")):
        manifest = sign_manifest(assessor_manifest(MCP_ENTRY_ID, MCP_TYPE, digest=CARD_DIGEST,
                                                   contributor=contributor),
                                 "assessor-assessment", assess_kid)
        cases.append(case(
            f"01-contributor-{suffix}",
            f"contributor {contributor!r} is not the signer; no URI normalization",
            ["Contributor Identity", "Entry Release Coverage"],
            [mcp_entry([manifest])],
            [{"entry": 0, "manifest": 0, "accepted": False, "code": "contributor-signer-mismatch",
              "premise": {"jwsVerifiesWith": assess_kid}}],
            note="The JWS is valid over the manifest as published (the variant contributor is in "
                 "the payload), so only the exact signer-to-contributor comparison rejects it.",
        ))

    # 02 kid authorized for authentication only.
    manifest = sign_manifest(publisher_manifest(MCP_ENTRY_ID, MCP_TYPE, digest=CARD_DIGEST),
                             "publisher-auth", f"{PUBLISHER}#auth-key")
    cases.append(case(
        "02-kid-authentication-only",
        "kid listed under authentication but not assertionMethod is rejected",
        ["DID Document Resolution and Key Selection"],
        [mcp_entry([manifest])],
        [{"entry": 0, "manifest": 0, "accepted": False, "code": "key-not-authorized-by-assertionMethod",
          "premise": {"jwsVerifiesWith": f"{PUBLISHER}#auth-key"}}],
    ))

    # 03 signer A, key from DID B.
    manifest = sign_manifest(assessor_manifest(MCP_ENTRY_ID, MCP_TYPE, digest=CARD_DIGEST),
                             "other-key-1", f"{OTHER}#key-1")
    cases.append(case(
        "03-kid-under-other-did",
        "signer did:web:assessor.example with kid under did:web:other.example whose key verifies",
        ["JWS Algorithm and Key Requirements", "DID Document Resolution and Key Selection"],
        [mcp_entry([manifest])],
        [{"entry": 0, "manifest": 0, "accepted": False, "code": "kid-not-under-signer",
          "premise": {"jwsVerifiesWith": f"{OTHER}#key-1"}}],
        note="A verifier that resolved the kid's DID instead of the signer's would find a key "
             "that verifies the JWS. The kid must be rejected before any resolution.",
    ))
    delegated_doc = copy.deepcopy(DID_DOCUMENTS)
    delegated_doc[ASSESSOR] = did_document(ASSESSOR, {"assessment-key": "assessor-assessment",
                                                      "delegated-key": "other-key-1"},
                                           controllers={"delegated-key": OTHER})
    manifest = sign_manifest(assessor_manifest(MCP_ENTRY_ID, MCP_TYPE, digest=CARD_DIGEST),
                             "other-key-1", f"{ASSESSOR}#delegated-key")
    fixture = case(
        "03-controller-other-did",
        "kid under the signer, listed in assertionMethod, but controlled by another DID",
        ["DID Document Resolution and Key Selection"],
        [mcp_entry([manifest])],
        [{"entry": 0, "manifest": 0, "accepted": False, "code": "verification-method-controller-mismatch",
          "premise": {"jwsVerifiesWith": f"{ASSESSOR}#delegated-key"}}],
    )
    fixture["didDocuments"] = delegated_doc
    cases.append(fixture)

    # 04 time.
    cases.append(case(
        "04-expired-endorsement",
        "A valid signature verified at or after expiresAt is not an endorsement",
        ["Signature Acceptance and Time"],
        [mcp_entry([signed_pub_mcp])],
        [{"entry": 0, "manifest": 0, "accepted": False, "code": "expired",
          "premise": {"jwsVerifiesWith": release_kid}}],
        verify_at="2027-01-15T00:00:00Z",
    ))
    manifest = sign_manifest(publisher_manifest(MCP_ENTRY_ID, MCP_TYPE, digest=CARD_DIGEST,
                                                expires_at="2026-09-01T00:00:00Z"),
                             "publisher-release", release_kid)
    cases.append(case(
        "04-expires-before-issued",
        "expiresAt earlier than issuedAt is structurally invalid even with a valid JWS",
        ["Signature Object"],
        [mcp_entry([manifest])],
        [{"entry": 0, "manifest": 0, "accepted": False, "code": "expiresAt-not-after-issuedAt",
          "premise": {"jwsVerifiesWith": release_kid}}],
    ))
    cases.append(case(
        "04-not-yet-valid",
        "An endorsement is not accepted before its issuedAt",
        ["Signature Acceptance and Time"],
        [mcp_entry([signed_pub_mcp])],
        [{"entry": 0, "manifest": 0, "accepted": False, "code": "not-yet-valid",
          "premise": {"jwsVerifiesWith": release_kid}}],
        verify_at="2026-09-30T23:59:59Z",
    ))

    # 05 release coverage after operator edits.
    cases.append(case(
        "05-version-added-after-signing",
        "Operator adds entry.version after an unversioned subject was signed",
        ["Entry Release Coverage", "Subject Object"],
        [mcp_entry([signed_assessor], version="1.2.0")],
        [{"entry": 0, "manifest": 0, "accepted": False, "code": "version-coverage-failed",
          "premise": {"jwsVerifiesWith": assess_kid}}],
        note="The manifest signature still verifies; it is unacceptable for this entry because "
             "subject.version is absent while entry.version is present.",
    ))
    swapped = copy.deepcopy(signed_pub_agent)
    swapped["subject"]["digest"] = ATTACKER_DIGEST
    swapped["subject"]["url"] = ATTACKER_URL
    cases.append(case(
        "05-digest-and-url-swapped",
        "Operator swaps entry url and digest and rewrites the signed subject to match",
        ["Signed Payload and JWS Construction", "Entry Release Coverage"],
        [agent_entry([swapped], url=ATTACKER_URL, digest=ATTACKER_DIGEST)],
        [{"entry": 0, "manifest": 0, "accepted": False, "code": "signature-invalid"}],
        resources={ATTACKER_URL: ATTACKER_TEXT},
        note="Subject and entry agree and the attacker's bytes match the new digest, but the "
             "subject is inside the signed payload, so the JWS no longer verifies.",
    ))
    url_only = sign_manifest(publisher_manifest(AGENT_ENTRY_ID, AGENT_TYPE, digest=None, url=AGENT_CARD_URL),
                             "publisher-release", release_kid)
    cases.append(case(
        "05-url-binding-moved-to-mirror",
        "URL-only binding: entry.url changed to a mirror without reissuing the manifest",
        ["Entry Release Coverage", "Subject Object"],
        [agent_entry([url_only], url=ATTACKER_URL, digest=None)],
        [{"entry": 0, "manifest": 0, "accepted": False, "code": "url-coverage-failed",
          "premise": {"jwsVerifiesWith": release_kid}}],
        resources={ATTACKER_URL: AGENT_CARD_TEXT},
    ))

    # 06 profile selection.
    relabelled = copy.deepcopy(signed_pub_mcp)
    relabelled["signature"]["profile"] = "https://example.org/profiles/did-web-v1"
    cases.append(case(
        "06-profile-relabelled-same-jws",
        "Same jws with profile relabelled: unsupported profile, no fallback",
        ["Profile Selection", "Signed Payload and JWS Construction"],
        [mcp_entry([relabelled])],
        [{"entry": 0, "manifest": 0, "accepted": False, "code": "unsupported-profile"}],
        note="profile is inside the signed payload, so the JWS would also fail; the fixture "
             "pins that profile selection rejects first and that no fallback to did-web-v1 occurs.",
    ))
    manifest = sign_manifest(publisher_manifest(MCP_ENTRY_ID, MCP_TYPE, digest=CARD_DIGEST,
                                                profile="https://example.org/profiles/did-web-v1"),
                             "publisher-release", release_kid)
    cases.append(case(
        "06-unknown-profile-resigned",
        "Unknown profile URI freshly signed by an otherwise valid did:web key must not fall back",
        ["Profile Selection"],
        [mcp_entry([manifest])],
        [{"entry": 0, "manifest": 0, "accepted": False, "code": "unsupported-profile",
          "premise": {"jwsVerifiesWith": release_kid}}],
        note="Applying did-web-v1 rules here would succeed. A consumer that does not implement "
             "the named profile must not infer one from signer or header.",
    ))
    manifest = sign_manifest(publisher_manifest(MCP_ENTRY_ID, MCP_TYPE, digest=CARD_DIGEST,
                                                profile="DID-WEB-V1"),
                             "publisher-release", release_kid)
    cases.append(case(
        "06-profile-case-variant",
        "profile identifiers are compared case-sensitively",
        ["Profile Selection"],
        [mcp_entry([manifest])],
        [{"entry": 0, "manifest": 0, "accepted": False, "code": "unsupported-profile",
          "premise": {"jwsVerifiesWith": release_kid}}],
    ))
    return cases


def main() -> int:
    CASES_DIR.mkdir(parents=True, exist_ok=True)
    for stale in CASES_DIR.glob("*.json"):
        stale.unlink()
    cases = build_cases()
    for fixture in cases:
        path = CASES_DIR / f"{fixture['id']}.json"
        path.write_text(json.dumps(fixture, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"wrote {path.relative_to(CASES_DIR.parent.parent.parent)}")
    print(f"{len(cases)} fixtures")
    return 0


if __name__ == "__main__":
    sys.exit(main())
