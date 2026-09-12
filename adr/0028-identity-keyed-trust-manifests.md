# ADR-0028: Identity-Keyed Trust Manifests and Selective Signatures

**Status:** Proposed

**Date:** 2026-09-12

## Context

The single signed Trust Manifest combines artifact binding, issuer identity,
signing metadata, and trust evidence in one object. That makes every claim in
an entry's manifest appear to come from one issuer and requires repeated entry
fields in `subject` solely to bring them inside the signed payload.

Catalog operators, assessors, and federated registries can contribute useful
trust evidence about the same artifact. They need to preserve the publisher's
claims while adding their own. A signature should identify both its signer and
the particular values endorsed, without making every contributor the publisher
or granting a contributor control over another contributor's claims.

ADR-0025 established release and representation binding. ADR-0027 established
an interoperable initial `did:web` profile and separated issuer authentication
from trustworthiness. Those security requirements remain useful; their original
single-manifest representation is not required to preserve them.

## Decision

### One current trust bundle per contributor

Replace `entry.trustManifest` with `entry.trustManifests`, a map from identity
URIs to slim Trust Manifest objects. Each manifest may contain `trustSchema`,
`attestations`, `provenance`, and `extensions`. Attestations and provenance
remain arrays: the ordinary contribution is a whole manifest, so individual
records need no newly minted map keys.

The map key attributes a bundle to an identity. It does not authenticate that
attribution. An authenticated endorsement by that identity establishes its
claims; a signature by another party can endorse the bundle but does not prove
that the named contributor authored it.

The map contains one current bundle per identity, not an append-only claim
history. A contributor updates its bundle and signs the updated value.
When choosing between available signed updates, consumers can use the most
recent valid contributor endorsement under their freshness policy. Signed
issuance times remain issuer assertions, not trusted clocks or proof that a
newer update does not exist. This model does not automatically merge different
versions of the same contributor's bundle.

### Shared artifact metadata

Move the served artifact digest to `entry.digest`. Move `privacyPolicyUrl`
and `termsOfServiceUrl` to the entry because they describe the artifact's
applicable policies rather than an individual contributor's trust assessment.
Keep `trustSchema` with each contributor's trust evidence.

Remove the duplicated `subject`: signatures select `entry.identifier`,
`entry.type`, `entry.digest`, and `entry.version` when present directly.
A version that needs an entry signature is represented by `entry.version`;
there is no longer a second version location inside a manifest. Artifact URL
binding remains optional so that digest-bound artifacts can use mirrors.

### One signature mechanism

Entries, Host Info, and the catalog root may carry `signatures` arrays. Remove
the singular root `signature` and the Host Trust Manifest. Each signature
object contains:

- `paths`: arrays of string keys relative to the containing object;
- `issuedAt` and optional `expiresAt`;
- `jws`: a detached JWS.

The reconstructed payload binds the selected paths and values, sorted by path,
together with issuance/expiration metadata and the defined signing context.
JCS canonicalizes that payload. Sorting makes path-list order immaterial;
binding paths as well as values prevents moving an endorsement to a different
field with an equal value. Key arrays avoid JSON Pointer escaping for URL keys.
Signature-object timestamps are explicitly included in the payload rather than
introduced as custom JWS header parameters.

A typical entry endorsement selects one entire identity-keyed manifest plus
the shared artifact release and representation fields. This keeps each
contributor's arrays and extension values independently editable without
invalidating another contributor's endorsement. More selective endorsements
remain possible under the normative coverage rules.

Host signatures endorse selected Host Info fields directly. Catalog signatures
can endorse catalog metadata or a complete snapshot under the corresponding
coverage rules. A signature over selected root fields does not imply approval
of every entry or the complete collection. A snapshot signature that covers
entries also covers their nested signatures; changing those values changes the
snapshot.

### Signer authentication and claim authority

Retain the initial root `did:web`, ES256, and assertion-authorized P-256 JWK
verification mechanism from ADR-0027. Apply identity authentication to
contributors as well as publishers. A publisher endorsement additionally
requires the authenticated identity to match the publisher domain in the signed
`urn:air` identifier. A valid signature by a different contributor can establish
that contributor's endorsement without establishing publisher authorization.

The key reference and algorithm remain protected JWS metadata. Remove
`identity`, `identityType`, and `signature` from the manifest itself. Profiles
can later define other identity mechanisms, including mechanisms with different
key discovery and authorization procedures; this change does not claim to
implement them.

Consumers distinguish signed-field integrity, authenticated contributor
attribution, publisher authorization, and whether the evidence is sufficient
for their own trust policy. Native attestation and provenance verification
remains governed by those evidence formats.

## Consequences

- Independent contributors can add evidence without replacing publisher claims
  or requiring a shared signature over every contributor's content.
- Artifact binding and timestamps remain authenticated, with no duplicated
  subject or custom timestamp headers.
- Contributor identities provide established map keys. Attestation and
  provenance authors need not allocate additional federated record identifiers.
- A signature cannot be transferred to a different release or manifest key:
  the required entry fields and selected paths are authenticated together.
- Existing singular-manifest and singular-signature documents require migration.
  This is a proposed v1 schema replacement, not a second compatibility format.
- Expiration and latest-observed endorsement selection do not prevent replay of
  an older, still-valid catalog. Strong freshness still requires trusted current
  information or consumer state.

## Alternatives Considered

### Flatten all trust fields directly onto the entry

This removes the manifest wrapper and supports independent field signatures,
but individual attestation and provenance contributions then need stable record
keys to avoid array-index paths. Choosing and preserving additional namespaced
record identifiers burdens ordinary authors. Identity-keyed bundles supply a
natural contribution boundary, retain familiar evidence arrays, and allow each
contributor to describe its own trust framework.

### Retain one manifest and add multiple signatures inside it

Multiple signatures can endorse a shared bundle, but do not separate different
contributors' evidence. Adding a record would change the bundle endorsed by
existing signatures. Selecting individual records reintroduces the stable-key
problem without a corresponding benefit for the common whole-bundle case.

### Keep duplicated subjects for independently portable manifests

A separate signed subject permits a manifest to carry a version that the entry
omits. The version is nevertheless already inside the catalog entry's nested
structure. Requiring it at `entry.version` provides one location and preserves
release binding through direct selection. The accepted portability boundary is
an entry and the selected values needed to verify its endorsements.
