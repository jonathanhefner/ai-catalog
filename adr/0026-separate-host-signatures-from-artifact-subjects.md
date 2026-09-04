# ADR-0026: Separate Host Signatures from Artifact Subjects

**Status:** Proposed

**Date:** 2026-09-04

## Context

A Trust Manifest may appear on either a Catalog Entry or a Host Info object.
The two placements make different statements. An entry Trust Manifest carries
claims about an AI artifact. A Host Trust Manifest carries claims about the
catalog operator.

Host Trust Manifests predate the `subject` object. Their signatures originally
covered the manifest's own identity and trust claims. ADR-0019 later introduced
`subject` to stop an attacker from retaining a valid entry Trust Manifest while
substituting the artifact referenced by its Catalog Entry. Its decision
requires `signature`, `subject`, and `issuedAt` on each relied-upon entry.

The corresponding specification text generalized that requirement to every
signed Trust Manifest, including one on Host Info. But an artifact Subject
requires a media type and digest tied to `entry.type`, `entry.url`, or
`entry.data`. Host Info has none of those fields, and the specification does not
identify any Host bytes that a consumer could hash. As a result, the required
Host Subject has no defined value or verification procedure.

The catalog document is already a separate protected object. Its top-level
signature or content-addressed distribution provides catalog-level integrity,
including the surrounding Host Info object. Treating those bytes as the Host
Trust Manifest's Subject would duplicate that mechanism and create a
self-reference because the manifest is embedded in the catalog.

## Decision

Define two contextual signature profiles while retaining the shared Trust
Manifest data model:

- A signed Trust Manifest on a Catalog Entry MUST include `subject` and
  `issuedAt`. The Subject binds the signed claims to the entry's artifact.
- A Host Trust Manifest MUST NOT include `subject`. When signed, it MUST include
  `issuedAt`; its signature covers the identity and trust claims inside the
  manifest itself.
- A signed Host Trust Manifest requires `host.identifier`, and that value MUST
  exactly equal `host.trustManifest.identity`. Consumers MUST reject a missing
  or mismatched identifier.
- Consumers relying on a signed Host Trust Manifest MUST verify its signature
  and anchor its identity or key as the expected catalog host. Equality between
  two values supplied by the catalog proves internal consistency, not
  authenticity.
- A Host Trust Manifest signature does not cover the surrounding Host Info
  object, catalog document, or a running service. Those concerns use
  catalog-level integrity or a separately defined runtime identity mechanism.

This decision narrows the generic subject language in ADR-0019 and ADR-0020 to
the entry context for which artifact binding was designed. It does not change
entry subject semantics, define signing-key selection, or introduce delegated
Host signing. A future delegated-signing profile would need to represent the
relationship between the Host identity and a distinct signer explicitly.

## Consequences

- Every signed Trust Manifest has a defined verification target: an entry
  manifest binds an artifact, while a Host manifest signs its own claims.
- Host manifests no longer need invented media types or digests that consumers
  cannot verify.
- The existing shared Trust Manifest object remains sufficient. Placement
  constraints are expressed normatively because CDDL cannot express which
  parent object contains a value.
- Signed Host manifests duplicate `host.identifier` as `identity`. This
  deliberate equality binds the signed claims to the Host principal named by
  the surrounding object.
- Signing a Host Trust Manifest does not protect unsigned fields in Host Info or
  the rest of the catalog.

## Alternatives Considered

### Define the catalog document as the Host Subject

Rejected. The top-level catalog signature already protects those bytes, and an
embedded Host manifest digesting its containing catalog creates a circular
representation unless additional exclusion and canonicalization rules are
invented.

### Define Host Info as the Host Subject

Rejected. This also requires new canonicalization and exclusion rules because
Host Info contains the Trust Manifest itself. It would obscure rather than
clarify the boundary between Host claims and catalog integrity.

### Define a running service as the Host Subject

Rejected. A live service has no stable artifact media type or content digest.
Connection-time service or workload authentication requires a separate runtime
identity profile.

### Forbid signed Host Trust Manifests

Rejected. Signing the Host manifest's own claims is coherent and preserves the
original Host trust-metadata capability without adding a new data model.
