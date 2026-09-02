# ADR-0025: Define Trust Roles and Verification Profiles

## Status

Proposed

## Date

2026-09-02

## Context

The specification assigns several roles to `TrustManifest.identity`. It calls
the value the artifact's primary subject identifier and the workload principal,
and it uses the value to obtain the manifest signer's key. The signing text
separately refers to the publisher's key and describes verification as a
publisher commitment. These roles can coincide, but the specification does not
define when they do or how they relate when they do not.

The Key Resolution procedure also places DID, HTTPS, SPIFFE, and DNS identifiers
behind one URI-to-public-key abstraction. Some of these mechanisms define ways
to obtain verification material, but none of their URI schemes by itself
defines the complete application verification procedure: the claim being made,
the authorized signer, independently trusted inputs, exact key selection, and
credential lifecycle.

For example, the SPIFFE Workload API gives a calling workload credentials to
which it is entitled. It does not resolve an arbitrary remote SPIFFE ID to a
leaf certificate. Fixing that sentence alone would leave the role and
authorization questions unresolved for all mechanisms.

## Decision

Trust Manifest verification will be defined by explicit roles and named
verification profiles. An identity URI scheme alone does not define a role,
authorization relationship, or complete verification procedure.

This ADR establishes constraints for subsequent schema and verification
changes. It does not select a proof mechanism or change the schema.

### Distinguish the essential roles

The trust model distinguishes:

| Concept | Meaning |
|---|---|
| Statement issuer | Principal represented as making a claim |
| Proof signer | Principal or credential holder that creates the cryptographic proof |
| Protected subject | Artifact, catalog, host, or other object about which the claim is made |
| Runtime workload | Running software participating in a deployment |
| Verification policy | Relying-party expectations, authorization rules, trust anchors, and evaluation context |

One principal MAY occupy several roles. That does not make the roles
equivalent. When the statement issuer and proof signer differ, the applicable
profile MUST define how the signer is authorized to act for the issuer.

A signed statement consists of the protected content and a cryptographic proof
over its exact serialization. Expected issuers, trust anchors, authorization
policy, and evaluation time are verifier inputs; values supplied by the signer
cannot make themselves trusted.

For signed entry Trust Manifests, the protected content binds the claim to an
exact artifact representation by media type and digest, as required by
ADR-0019. Profiles define any additional claims and protected fields. Catalog
signatures and signed Host Trust Manifests have different subjects and therefore
require their own profile semantics.

This ADR applies to cryptographic verification of signed content. It does not
change ADR-0020's allowance for unsigned Trust Manifests carrying advisory
metadata or independently verifiable evidence.

### Assign identities explicit roles

Each normative signing context MUST state what its identity denotes and how
that identity relates to the statement issuer, proof signer, protected subject,
and any runtime workload.

Identifiers MAY be aliases only when they identify the same subject. When they
identify distinct but related principals, the relationship must instead be
expressed as authorization or another role-labelled relationship. DID and
SPIFFE URI schemes do not, by themselves, determine whether two identifiers
refer to the same subject.

This decision does not require a separate `runtimeIdentity` field. A single
field can remain sufficient where a profile assigns it one unambiguous role.
Field design follows the signing contexts and profiles retained for version 1.

### Define complete verification profiles

A profile is specific to a claim and signing context, proof mechanism, and
verification moment. Each normative profile MUST define:

1. the relying-party decision and the role of each identity;
1. the issuer, subject, claims, and exact protected content;
1. how the profile and version are selected and protected against cross-profile
   substitution;
1. the proof signer and any authority to act for the statement issuer;
1. independently expected identities, policy, and trust anchors;
1. how exact verification material is resolved or presented, selected, and
   bound to the declared identity;
1. permitted algorithms and verification relationships;
1. validity, freshness, rotation, revocation, and required failure behavior.

A consumer MUST NOT describe an identity as cryptographically verified merely
because its URI is valid or its scheme is recognized.

### Require a complete version 1 profile set

The generic Key Resolution procedure will be replaced by named profiles.

Before release, every normative signing context retained in version 1—including
entry Trust Manifests, Host Trust Manifests, and catalog signatures—MUST either
have a complete verification profile or be deferred from normative verification.
Likewise, an identity or proof mechanism MUST NOT be listed as normatively
verifiable until its profile defines complete verifier behavior.

## Consequences

- The current `identity` semantics and Key Resolution procedure require
  follow-up changes before release.
- Schema changes will follow the selected signing contexts and profiles rather
  than precede them.
- A publisher, delegated signer, and runtime workload may use different
  identities, or one principal may occupy those roles under an explicit profile.
- Some currently listed signing contexts or identity mechanisms may be deferred
  from normative version 1 verification.

## Alternatives Considered

Patching only the SPIFFE resolution text was rejected because the other
mechanisms still lack explicit role and authorization semantics.

Adding `runtimeIdentity` immediately was deferred. Publisher and workload
identities often differ, but a workload can also issue a statement; field design
must follow the signing contexts selected for version 1.

## References

- [SPIFFE Workload API](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md)
- [ADR-0019: Trust Manifest artifact binding](0019-trust-manifest-artifact-binding.md)
- [ADR-0020: Substantive Trust Manifest](0020-substantive-trust-manifest.md)
