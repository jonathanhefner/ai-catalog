# ADR-0028: Identity-Keyed Trust Manifests and Selective Signatures

**Status:** Proposed

**Date:** 2026-09-12

## Context

An entry currently has one Trust Manifest containing contributor identity,
trust evidence, and a signature. A publisher, an assessor, and a catalog
operator may each have claims to contribute about the same artifact. They
need separate places to publish and update those claims.

The existing signature covers the entire manifest. To authenticate artifact
fields stored outside it, the manifest repeats them in a `subject` object.
Other entry metadata can also warrant an endorsement, such as an extension
or a policy URL. Letting signatures select entry fields directly gives these
endorsements a common format.

## Decision

### Group claims by contributor

Replace `entry.trustManifest` with `entry.trustManifests`, a map from
contributor identity URIs to Trust Manifest objects. Each entry has at most
one manifest per contributor identity. Each manifest can contain
`trustSchema`, `attestations`, `provenance`, and `extensions`.

For example, the publisher can provide source provenance under
`trustManifests["did:web:publisher.example"]`, while an assessor provides audit
references under `trustManifests["did:web:assessor.example"]`. The assessor can
update its manifest without invalidating a publisher signature that covers
only the publisher's manifest and the shared artifact fields.

### Place fields according to what they describe

Artifact fields describe the shared artifact. Manifest fields contain a
particular contributor's claims. Signature fields describe an endorsement.

| Existing location | Proposed location |
| --- | --- |
| `trustManifest.identity` | Key in `entry.trustManifests` |
| `trustManifest.identityType` | Removed; the signer profile determines how to interpret the identity URI |
| `trustManifest.trustSchema` | Each contributor's manifest |
| `trustManifest.attestations` | Each contributor's manifest, as an array |
| `trustManifest.provenance` | Each contributor's manifest, as an array |
| `trustManifest.extensions` | Each contributor's manifest |
| `trustManifest.privacyPolicyUrl` | `entry.privacyPolicyUrl` |
| `trustManifest.termsOfServiceUrl` | `entry.termsOfServiceUrl` |
| `trustManifest.subject.digest` | `entry.digest` |
| `trustManifest.subject.identifier`, `.version`, `.type`, `.url` | Select the corresponding entry fields directly; remove the duplicated `subject` |
| `trustManifest.signature`, `.issuedAt`, `.expiresAt` | Each object in `entry.signatures`, with `signature` renamed to `jws` |
| Catalog root `signature` | Objects in the root `signatures` array |

### Sign selected fields

Entries, Host Info, and the catalog root can each carry a `signatures` array.
Each signature object contains `paths`, `issuedAt`, optional `expiresAt`, and
`jws`.

Each path is an array of exact object member names, starting at the object
containing the signature array. For example,
`["extensions", "https://example.com/metadata"]` selects one entry extension.
Arrays are selected as whole values.

The signer collects each selected path and its value into a pair, sorts those
pairs by path, and adds the endorsement timestamps and a context identifying
the object kind and signing format version. This collected data is the
**payload**: the data over which the signature is computed. JCS gives it a
deterministic JSON encoding, and JWS supplies the cryptographic signature.
The detached JWS stored in `jws` omits the payload; the verifier constructs
that same payload from the selected fields and signature metadata.

Including both paths and values authenticates which fields the signer
endorses. Sorting the pairs lets authors reorder the path list without
changing the signature. The timestamps are authenticated along with the
selected fields.

To endorse claims about an artifact release, a signature selects the claims
and the entry's `identifier`, `type`, `digest`, and `version` when present.
The consumer checks both the signature and the artifact content against that
digest. A typical assessor signature selects the assessor's entire manifest
and those entry fields. The signature then establishes which artifact and
version the assessor's claims describe. Selecting `url` additionally endorses
a location; leaving it unselected permits mirrors serving identical bytes.

The [specification](../specification/ai-catalog.md#signature-object) defines
payload construction, verification, and required field coverage.

### Authenticate contributors and establish publisher authority

Extend the existing `did:web` verification mechanism to authenticate
independent contributors as well as publishers. Publisher authorization
additionally requires the authenticated identity to match the publisher
domain in the entry's signed `urn:air` identifier.

A manifest's identity key attributes its claims to a contributor. Accepting
those claims as that contributor's assertions requires a signature
authenticated as that identity. For example, a catalog operator can endorse
an assessor's manifest, but the operator's signature alone does not establish
that the assessor made those claims.

Additional profiles can define other identity mechanisms and their key
discovery and authorization procedures. The consumer decides whether an
authenticated contributor's evidence satisfies its trust policy. Referenced
attestation and provenance documents are verified according to their formats.

### Publish and select updates

A contributor updates its manifest and signs the updated value. Two registries
may retrieve that manifest at different times and consequently hold different
signed versions. When a consumer encounters both for the same artifact
release, it can prefer the manifest covered in full by that contributor's most
recent acceptable signature, comparing `issuedAt` timestamps. A later signature
from another entity does not identify an update by the contributor.

### Sign host metadata and catalog snapshots

A Host Info signature selects fields of that Host Info object. A root signature
selects catalog fields: for example, selecting only `host` endorses the host
metadata and leaves `entries` unsigned by that signature. A consumer accepting
a complete catalog snapshot must check that the signature covers every
root member except the root's own `signatures` array.

Selecting the entire `entries` array includes the signatures within each
entry. Adding an entry signature therefore requires regenerating any catalog
signature covering that array, even when the artifact and other metadata are
unchanged. Adding a root co-signature does not change the snapshot.

## Consequences

- Contributors can independently publish and update their trust metadata.
- Consumers can determine which entry fields each signer endorsed.
- Shared artifact fields have one location and can be covered by several
  signatures from different signers.
- Existing singular-manifest and singular-signature documents require migration
  to the new structure.
- Consumers requiring protection against replay of older, still-valid
  endorsements need trusted current information or previously observed state.
