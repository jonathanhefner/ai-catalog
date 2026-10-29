# Trust Manifest signature fixtures

Conformance fixtures for the signed Trust Manifest rules in
[`specification/ai-catalog.md`](../../ai-catalog.md) as merged in #117
(ADR-0028 and ADR-0029): Contributor Identity, the Subject Object, the
Signature Object, Profile Selection, Signed Payload and JWS Construction,
Signature Acceptance and Time, the `did:web` Signer Profile, Entry Release
Coverage, and Verifying Artifact Integrity.

Each file under `cases/` is one self-contained scenario:

| Member | Meaning |
| --- | --- |
| `catalog` | A complete AI Catalog containing the manifests under test |
| `didDocuments` | The DID documents a verifier would resolve for each `signer` (keyed by DID; nothing is fetched) |
| `resources` | Artifact bytes for `url` entries, keyed by URL, so digest checks run offline |
| `verifyAt` | The instant at which verification happens |
| `spec` | The specification section titles the case exercises |
| `expect` | Per manifest: whether it is an acceptable endorsement of its entry, the rejection code when it is not, and a premise the fixture relies on |
| `note` | Why the case is shaped the way it is |

`premise.jwsVerifiesWith` names a verification method whose key verifies the
raw JWS when every authorization rule is ignored. It documents that the
rejection is a rule, not a broken signature. For example, in
`03-kid-under-other-did` the JWS verifies under `did:web:other.example#key-1`;
the manifest is still rejected because the `kid` is not under the signer.

The rejection codes are this checker's labels, not names defined by the
specification. A verifier passes a case when it accepts or rejects the same
manifests for the same rule.

## Cases

| Case | Rule | Outcome |
| --- | --- | --- |
| `00-positive-control-reordered` | Signed Payload and JWS Construction; Independent Contributions and Updates; Subject Object | Members written in reverse order, a reversed `trustManifests` array, an unrecognized manifest member kept in the payload, an `additionalSignatures` member added after signing (excluded from the payload), and a URL entry moved to a mirror serving identical bytes; all three manifests verify |
| `01-contributor-case-variant` | Contributor Identity | `contributor` differs from `signer` only by case; rejected, no URI normalization |
| `01-contributor-trailing-dot` | Contributor Identity | `contributor` has a trailing root dot; rejected |
| `02-kid-authentication-only` | DID Document Resolution and Key Selection | `kid` listed in `verificationMethod` and `authentication` only; rejected |
| `03-kid-under-other-did` | JWS Algorithm and Key Requirements | `signer` A, `kid` under DID B whose key verifies; rejected before resolution |
| `03-controller-other-did` | DID Document Resolution and Key Selection | `kid` under A and in A's `assertionMethod`, but `controller` is B; rejected |
| `04-expired-endorsement` | Signature Acceptance and Time | Valid JWS verified after `expiresAt`; not an endorsement |
| `04-expires-before-issued` | Signature Object | `expiresAt` earlier than `issuedAt`; structurally invalid |
| `04-not-yet-valid` | Signature Acceptance and Time | Verified a month before `issuedAt`; not accepted |
| `05-version-added-after-signing` | Entry Release Coverage; Subject Object | Operator adds `entry.version` after an unversioned subject was signed; coverage fails while the JWS still verifies |
| `05-subject-digest-rewritten` | Signed Payload and JWS Construction; Entry Release Coverage | Operator replaces `url` and `digest` and rewrites `subject.digest` to match; the signature fails |
| `05-entry-digest-removed` | Subject Object; Entry Release Coverage | Operator drops `entry.digest`; coverage fails while the JWS still verifies |
| `05-mirror-serves-different-bytes` | Entry Release Coverage; Verifying Artifact Integrity | `entry.url` moved to a mirror whose bytes differ; artifact verification fails |
| `06-profile-relabelled-same-jws` | Profile Selection | Same `jws`, `profile` relabelled to an unknown URI; unsupported, no fallback |
| `06-unknown-profile-resigned` | Profile Selection | Freshly signed under an unknown profile URI by a key that would pass `did-web-v1`; must not fall back |
| `06-profile-case-variant` | Profile Selection | `DID-WEB-V1`; profile identifiers are case-sensitive |
| `07-catalog-typ-on-manifest` | Signed Payload and JWS Construction | Manifest JWS carries the catalog `typ` (`ai-catalog+jws`); rejected |

## Time

The specification permits a small clock-skew tolerance. The checker applies
none, and every case keeps `verifyAt` days away from `issuedAt` and
`expiresAt`, so a verifier with any reasonable tolerance reaches the same result.

## Running

```
python3 tools/verify_trust_manifest_fixtures.py --verbose
```

The checker uses only the Python standard library. It implements the subset of
JCS the fixtures need (no fractional numbers) and ES256 verification over
P-256, so it runs anywhere `python3` does. It is a fixture checker, not a
production verifier.

## Regenerating

```
python3 tools/make_trust_manifest_fixtures.py
```

Keys are derived from fixed seed strings so the output is reproducible. They
are test material only.
