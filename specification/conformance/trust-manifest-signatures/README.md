# Trust Manifest signature fixtures

Conformance fixtures for the signed Trust Manifest rules in
[`specification/ai-catalog.md`](../../ai-catalog.md): the Signature Object,
Profile Selection, Signed Payload and JWS Construction, Signature Acceptance
and Time, the `did:web` Signer Profile, and Entry Release Coverage.

Each file under `cases/` is one self-contained scenario:

| Member | Meaning |
| --- | --- |
| `catalog` | A complete AI Catalog containing the manifests under test |
| `didDocuments` | The DID documents a verifier would resolve for each `signer` (keyed by DID; nothing is fetched) |
| `resources` | Artifact bytes for `url` entries, keyed by URL, so digest checks run offline |
| `verifyAt` | The instant at which verification happens |
| `spec` | The specification section titles the case exercises |
| `expect` | Per manifest: whether it is an acceptable endorsement of its entry, the rejection code when it is not, the state of each selected entry extension, and a premise the fixture relies on |
| `note` | Why the case is shaped the way it is |

`premise.jwsVerifiesWith` names a verification method whose key verifies the
raw JWS when every authorization rule is ignored. It documents that the
rejection is a rule, not a broken signature. For example, in
`03-kid-under-other-did` the JWS verifies under `did:web:other.example#key-1`;
the manifest is still rejected because the `kid` is not under the signer.

## Cases

| Case | Rule | Outcome |
| --- | --- | --- |
| `00-positive-control-reordered` | Signed Payload and JWS Construction; Independent Contributions and Updates; Extension Digest Verification | Object members written in reverse order and a reversed `trustManifests` array still verify; an unrecognized manifest member stays in the payload; the assessor authenticates the policy-urls extension |
| `01-contributor-case-variant` | Contributor Identity | `contributor` differs from `signer` only by case; rejected, no URI normalization |
| `01-contributor-trailing-dot` | Contributor Identity | `contributor` has a trailing root dot; rejected |
| `02-kid-authentication-only` | DID Document Resolution and Key Selection | `kid` listed in `verificationMethod` and `authentication` only; rejected |
| `03-kid-under-other-did` | JWS Algorithm and Key Requirements | `signer` A, `kid` under DID B whose key verifies; rejected before resolution |
| `03-controller-other-did` | DID Document Resolution and Key Selection | `kid` under A and in A's `assertionMethod`, but `controller` is B; rejected |
| `04-expired-endorsement` | Signature Acceptance and Time | Valid JWS verified after `expiresAt`; not an endorsement |
| `04-expires-before-issued` | Signature Object | `expiresAt` earlier than `issuedAt`; structurally invalid |
| `04-not-yet-valid` | Signature Acceptance and Time | Verified before `issuedAt`; not accepted |
| `05-version-added-after-signing` | Entry Release Coverage | Operator adds `entry.version` after an unversioned subject was signed; coverage fails while the JWS still verifies |
| `05-digest-and-url-swapped` | Signed Payload and JWS Construction; Entry Release Coverage | Operator replaces `url` and `digest` and rewrites the subject to match; the signature fails |
| `05-url-binding-moved-to-mirror` | Entry Release Coverage | URL-only binding; `entry.url` moved to a mirror without reissuing; coverage fails |
| `06-profile-relabelled-same-jws` | Profile Selection | Same `jws`, `profile` relabelled to an unknown URI; unsupported, no fallback |
| `06-unknown-profile-resigned` | Profile Selection | Freshly signed under an unknown profile URI by a key that would pass `did-web-v1`; must not fall back |
| `06-profile-case-variant` | Profile Selection | `DID-WEB-V1`; profile identifiers are case-sensitive |

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
