#!/usr/bin/env python3
"""Run the Trust Manifest signature conformance fixtures.

Each fixture under ``specification/conformance/trust-manifest-signatures/cases``
holds one catalog, the DID documents a verifier would resolve, the instant at
which verification happens, and the outcome the specification requires. This
script applies the Signature Object, ``did:web`` Signer Profile, and Entry
Release Coverage rules from ``specification/ai-catalog.md`` to every signed
Trust Manifest named by the fixture and compares the outcome with the
expectation.

It is a fixture checker, not a production verifier: it never fetches anything,
it only reads the DID documents and artifact bytes carried by the fixture, and
it depends on nothing outside the Python standard library (ES256 verification
and the JCS subset the fixtures use are implemented below). Rejections carry
stable codes so a fixture can pin which rule rejected a manifest.

Usage:
    python3 tools/verify_trust_manifest_fixtures.py            # run all cases
    python3 tools/verify_trust_manifest_fixtures.py --verbose  # show every outcome
    python3 tools/verify_trust_manifest_fixtures.py path/to/case.json ...
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CASES_DIR = REPO_ROOT / "specification/conformance/trust-manifest-signatures/cases"

DID_WEB_PROFILE = "did-web-v1"
MANIFEST_TYP = "ai-catalog-trust-manifest+jws"
DIGEST_ALGORITHMS = {"sha256": hashlib.sha256, "sha384": hashlib.sha384, "sha512": hashlib.sha512}

# Root did:web DID: lowercase ASCII domain labels, no port, no path, no trailing dot.
ROOT_DID_WEB_RE = re.compile(r"^did:web:(?!-)[a-z0-9-]+(?:\.(?!-)[a-z0-9-]+)*$")


# --- JCS (RFC 8785) for the value subset the fixtures use ---------------------


class JCSError(ValueError):
    pass


def _jcs_string(value: str) -> str:
    out = ['"']
    for ch in value:
        code = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif code < 0x20:
            out.append(f"\\u{code:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def jcs(value) -> bytes:
    """Serialize ``value`` as RFC 8785 canonical JSON (UTF-8 bytes).

    Numbers are limited to integers that round-trip as IEEE 754 doubles. The
    fixtures contain no fractional numbers, so the ES6 number-to-string
    algorithm is not needed here.
    """
    return _jcs(value).encode("utf-8")


def _jcs(value) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        if abs(value) > 2**53:
            raise JCSError(f"integer {value} does not round-trip as a double")
        return str(value)
    if isinstance(value, float):
        raise JCSError("fixture checker does not serialize non-integer numbers")
    if isinstance(value, str):
        return _jcs_string(value)
    if isinstance(value, list):
        return "[" + ",".join(_jcs(v) for v in value) + "]"
    if isinstance(value, dict):
        # RFC 8785 sorts member names by UTF-16 code units.
        items = sorted(value.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return "{" + ",".join(_jcs_string(k) + ":" + _jcs(v) for k, v in items) + "}"
    raise JCSError(f"unsupported JSON value type {type(value).__name__}")


# --- ES256 (ECDSA over P-256 with SHA-256), RFC 7518 section 3.4 ------------

P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
G = (
    0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
)


def on_curve(point) -> bool:
    x, y = point
    return 0 <= x < P and 0 <= y < P and (y * y - (x * x * x + A * x + B)) % P == 0


def point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1 + A) * pow(2 * y1, -1, P) % P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def point_mul(k: int, point):
    result = None
    addend = point
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result


def es256_verify(public_point, signature: bytes, signing_input: bytes) -> bool:
    """Verify a JWS ES256 signature (``r || s``, 64 bytes) over ``signing_input``."""
    if len(signature) != 64 or not on_curve(public_point):
        return False
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    if not (1 <= r < N and 1 <= s < N):
        return False
    e = int.from_bytes(hashlib.sha256(signing_input).digest(), "big")
    w = pow(s, -1, N)
    point = point_add(point_mul((e * w) % N, G), point_mul((r * w) % N, public_point))
    return point is not None and point[0] % N == r


# --- helpers -----------------------------------------------------------------


def b64url_decode(text: str) -> bytes:
    if not re.fullmatch(r"[A-Za-z0-9_-]*", text):
        raise ValueError("not base64url")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def parse_instant(text) -> datetime:
    if not isinstance(text, str):
        raise ValueError("timestamp is not a string")
    value = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if value.tzinfo is None:
        raise ValueError(f"timestamp has no offset: {text!r}")
    return value.astimezone(timezone.utc)


def digest_of(algorithm: str, data: bytes) -> str:
    return f"{algorithm}:{DIGEST_ALGORITHMS[algorithm](data).hexdigest()}"


def split_digest(value):
    if not isinstance(value, str) or ":" not in value:
        return None, None
    algorithm, hex_value = value.split(":", 1)
    if algorithm not in DIGEST_ALGORITHMS or not re.fullmatch(r"[0-9a-f]+", hex_value):
        return None, None
    return algorithm, hex_value


def jwk_point(jwk: dict):
    point = (int.from_bytes(b64url_decode(jwk["x"]), "big"),
             int.from_bytes(b64url_decode(jwk["y"]), "big"))
    if not on_curve(point):
        raise ValueError("coordinates are not on P-256")
    return point


@dataclass
class ManifestResult:
    accepted: bool = False
    codes: list[str] = field(default_factory=list)
    extensions: dict[str, str] = field(default_factory=dict)

    def fail(self, code: str) -> None:
        if code not in self.codes:
            self.codes.append(code)


# --- verification ------------------------------------------------------------


def signature_payload(manifest: dict) -> bytes:
    """Signed Payload and JWS Construction: omit only the manifest's own
    ``signature.jws`` and ``additionalSignatures``; keep everything else."""
    payload = {k: v for k, v in manifest.items() if k != "additionalSignatures"}
    payload["signature"] = {k: v for k, v in manifest["signature"].items() if k != "jws"}
    return jcs(payload)


def select_assertion_key(did_doc: dict, signer: str, kid: str, result: ManifestResult):
    """DID Document Resolution and Key Selection. Returns a P-256 point or None."""
    if did_doc.get("id") != signer:
        result.fail("did-document-id-mismatch")
        return None

    def absolute(ref: str) -> str:
        return signer + ref if ref.startswith("#") else ref

    methods = {}
    for vm in did_doc.get("verificationMethod") or []:
        if isinstance(vm, dict) and isinstance(vm.get("id"), str):
            methods[absolute(vm["id"])] = vm
    authorized = []
    for item in did_doc.get("assertionMethod") or []:
        if isinstance(item, str) and absolute(item) in methods:
            authorized.append(methods[absolute(item)])
        elif isinstance(item, dict) and isinstance(item.get("id"), str):
            authorized.append(item)
    selected = [vm for vm in authorized if absolute(vm["id"]) == kid]
    if len(selected) != 1:
        result.fail("key-not-authorized-by-assertionMethod")
        return None
    vm = selected[0]
    if vm.get("controller") != signer:
        result.fail("verification-method-controller-mismatch")
        return None
    jwk = vm.get("publicKeyJwk")
    if not isinstance(jwk, dict) or jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        result.fail("jwk-not-p256")
        return None
    if "d" in jwk:
        result.fail("jwk-contains-private-material")
        return None
    if jwk.get("alg", "ES256") != "ES256" or jwk.get("use", "sig") != "sig":
        result.fail("jwk-alg-or-use-mismatch")
        return None
    if "key_ops" in jwk and "verify" not in (jwk.get("key_ops") or []):
        result.fail("jwk-key-ops-forbid-verify")
        return None
    try:
        return jwk_point(jwk)
    except (KeyError, ValueError, TypeError):
        result.fail("jwk-coordinates-invalid")
        return None


def verify_signer_did_web(manifest: dict, did_documents: dict, verify_at: datetime,
                          result: ManifestResult) -> bool:
    """Signature Object, Signature Acceptance and Time, did:web Signer Profile."""
    signature = manifest.get("signature")
    if not isinstance(signature, dict):
        result.fail("signature-not-object")
        return False
    for member in ("signer", "profile", "issuedAt", "jws"):
        if not isinstance(signature.get(member), str) or not signature[member]:
            result.fail(f"signature-missing-{member}")
            return False
    if "subject" not in manifest:
        result.fail("signed-manifest-without-subject")
        return False

    # Profile Selection: exact, case-sensitive match; no inference, no fallback.
    if signature["profile"] != DID_WEB_PROFILE:
        result.fail("unsupported-profile")
        return False

    signer = signature["signer"]
    if signer != manifest.get("contributor"):
        result.fail("contributor-signer-mismatch")
    if not ROOT_DID_WEB_RE.match(signer):
        result.fail("signer-not-root-did-web")
        return False

    # Timestamps are compared as instants, not strings.
    try:
        issued_at = parse_instant(signature["issuedAt"])
        expires_at = parse_instant(signature["expiresAt"]) if "expiresAt" in signature else None
    except ValueError:
        result.fail("timestamp-invalid")
        return False
    if expires_at is not None and expires_at <= issued_at:
        result.fail("expiresAt-not-after-issuedAt")
        return False
    if verify_at < issued_at:
        result.fail("not-yet-valid")
    if expires_at is not None and verify_at >= expires_at:
        result.fail("expired")

    # Detached compact serialization: header..signature
    parts = signature["jws"].split(".")
    if len(parts) != 3 or parts[1] != "":
        result.fail("jws-not-detached-compact")
        return False
    try:
        header = json.loads(b64url_decode(parts[0]))
        raw_signature = b64url_decode(parts[2])
    except (ValueError, UnicodeDecodeError):
        result.fail("jws-segments-invalid")
        return False
    if not isinstance(header, dict):
        result.fail("jws-header-not-object")
        return False
    if header.get("typ") != MANIFEST_TYP:
        result.fail("jws-typ-mismatch")
    if header.get("alg") != "ES256":
        result.fail("jws-alg-not-es256")
        return False
    if "b64" in header:
        result.fail("jws-b64-present")
    if any(name in header for name in ("jku", "jwk", "x5u", "x5c")):
        result.fail("jws-key-source-header-present")
    if header.get("crit"):
        result.fail("jws-unsupported-crit")

    # kid MUST be exactly signer + "#" + non-empty fragment, with no path or query.
    kid = header.get("kid")
    if (not isinstance(kid, str) or not kid.startswith(signer + "#")
            or len(kid) == len(signer) + 1 or "/" in kid[len(signer):]
            or "?" in kid[len(signer):]):
        result.fail("kid-not-under-signer")
        return False

    did_doc = did_documents.get(signer)
    if did_doc is None:
        result.fail("did-resolution-failed")
        return False
    point = select_assertion_key(did_doc, signer, kid, result)
    if point is None:
        return False

    signing_input = f"{parts[0]}.{b64url(signature_payload(manifest))}".encode("ascii")
    if not es256_verify(point, raw_signature, signing_input):
        result.fail("signature-invalid")
        return False
    return not result.codes


def verify_release_coverage(entry: dict, manifest: dict, resources: dict,
                            result: ManifestResult) -> None:
    """Entry Release Coverage and Extension Digest Verification."""
    subject = manifest.get("subject")
    if not isinstance(subject, dict):
        result.fail("subject-missing")
        return
    if subject.get("identifier") != entry.get("identifier"):
        result.fail("subject-identifier-mismatch")
    if subject.get("type") != entry.get("type"):
        result.fail("subject-type-mismatch")
    if ("version" in subject) != ("version" in entry) or subject.get("version") != entry.get("version"):
        result.fail("version-coverage-failed")

    has_digest, has_url = "digest" in subject, "url" in subject
    if not has_digest and not has_url:
        result.fail("subject-without-binding")
    if has_digest != ("digest" in entry) or subject.get("digest") != entry.get("digest"):
        result.fail("digest-coverage-failed")
    elif has_digest:
        algorithm, _ = split_digest(subject["digest"])
        if algorithm is None:
            result.fail("digest-format-invalid")
        else:
            if "data" in entry:
                try:
                    artifact = jcs(entry["data"])
                except JCSError:
                    artifact = None
            else:
                text = resources.get(entry.get("url"))
                artifact = text.encode("utf-8") if isinstance(text, str) else None
            if artifact is None:
                result.fail("artifact-unavailable")
            elif digest_of(algorithm, artifact) != subject["digest"]:
                result.fail("artifact-digest-mismatch")
    if has_url:
        url = subject["url"]
        if not isinstance(url, str) or not url.startswith("https://"):
            result.fail("subject-url-not-https")
        if url != entry.get("url"):
            result.fail("url-coverage-failed")

    # Extension Digest Verification is independent for each selected extension.
    selected = subject.get("extensionDigests") or {}
    entry_extensions = entry.get("extensions") or {}
    for key, declared in selected.items():
        algorithm, _ = split_digest(declared)
        if key not in entry_extensions or algorithm is None:
            result.extensions[key] = "failed"
            continue
        try:
            computed = digest_of(algorithm, jcs(entry_extensions[key]))
        except JCSError:
            result.extensions[key] = "failed"
            continue
        result.extensions[key] = "matched" if computed == declared else "failed"


def verify_manifest(entry: dict, manifest: dict, did_documents: dict, resources: dict,
                    verify_at: datetime) -> ManifestResult:
    result = ManifestResult()
    if not isinstance(manifest.get("contributor"), str):
        result.fail("contributor-missing")
    if "signature" not in manifest:
        result.fail("unsigned")
        return result
    if verify_signer_did_web(manifest, did_documents, verify_at, result):
        verify_release_coverage(entry, manifest, resources, result)
    result.accepted = not result.codes
    return result


def jws_verifies_with(manifest: dict, did_documents: dict, method_id: str) -> bool:
    """Diagnostic only: does the raw JWS verify under the named verification
    method when every authorization rule is ignored? Fixtures use this to prove
    a premise such as "the signature is cryptographically valid"."""
    signature = manifest.get("signature") or {}
    parts = str(signature.get("jws", "")).split(".")
    if len(parts) != 3:
        return False
    did = method_id.split("#", 1)[0]
    for vm in (did_documents.get(did) or {}).get("verificationMethod") or []:
        vm_id = vm.get("id", "")
        if (did + vm_id if vm_id.startswith("#") else vm_id) != method_id:
            continue
        try:
            point = jwk_point(vm.get("publicKeyJwk") or {})
            signing_input = f"{parts[0]}.{b64url(signature_payload(manifest))}".encode("ascii")
            return es256_verify(point, b64url_decode(parts[2]), signing_input)
        except (KeyError, ValueError, TypeError):
            return False
    return False


# --- fixture runner ------------------------------------------------------------


def load_strict(path: Path) -> dict:
    """Parse JSON, rejecting duplicate member names as the JCS input rules require."""

    def no_duplicates(pairs):
        keys = [k for k, _ in pairs]
        if len(keys) != len(set(keys)):
            raise ValueError(f"duplicate member names in {path.name}")
        return dict(pairs)

    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=no_duplicates)


def run_case(path: Path, verbose: bool) -> bool:
    case = load_strict(path)
    verify_at = parse_instant(case["verifyAt"])
    did_documents = case.get("didDocuments") or {}
    resources = case.get("resources") or {}
    catalog = case["catalog"]
    ok = True
    lines = []
    for expectation in case["expect"]:
        entry = catalog["entries"][expectation["entry"]]
        manifest = entry["trustManifests"][expectation["manifest"]]
        result = verify_manifest(entry, manifest, did_documents, resources, verify_at)
        problems = []
        if result.accepted != expectation["accepted"]:
            problems.append(f"accepted={result.accepted} expected {expectation['accepted']}")
        if "code" in expectation and expectation["code"] not in result.codes:
            problems.append(f"code {expectation['code']!r} not in {result.codes}")
        for key, state in (expectation.get("extensions") or {}).items():
            if result.extensions.get(key) != state:
                problems.append(f"extension {key!r}: {result.extensions.get(key)} expected {state}")
        premise = expectation.get("premise") or {}
        if "jwsVerifiesWith" in premise:
            if not jws_verifies_with(manifest, did_documents, premise["jwsVerifiesWith"]):
                problems.append(f"premise failed: JWS does not verify with {premise['jwsVerifiesWith']}")
        tag = f"entries[{expectation['entry']}].trustManifests[{expectation['manifest']}]"
        if problems:
            ok = False
            lines.append(f"    {tag}: " + "; ".join(problems))
        elif verbose:
            outcome = "accepted" if result.accepted else "rejected: " + ", ".join(result.codes)
            lines.append(f"    {tag}: {outcome}")
    print(f"[{'PASS' if ok else 'FAIL'}] {case['id']}: {case['title']}")
    for line in lines:
        print(line)
    return ok


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("cases", nargs="*", type=Path, help="fixture files (default: all)")
    parser.add_argument("--verbose", action="store_true", help="print every manifest outcome")
    args = parser.parse_args(argv)
    paths = args.cases or sorted(CASES_DIR.glob("*.json"))
    if not paths:
        print(f"no fixtures found under {CASES_DIR}", file=sys.stderr)
        return 2
    results = [run_case(path, args.verbose) for path in paths]
    print(f"{sum(results)}/{len(results)} fixtures behave as specified")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
