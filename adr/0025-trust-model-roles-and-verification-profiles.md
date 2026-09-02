# ADR-0025: Define Trust-Model Roles and Verification Profiles

## Status

Proposed

## Date

2026-09-02

## Context

The AI Catalog separates an entry's stable discovery identifier from the
cryptographic identity carried by its optional Trust Manifest. This lets a
`urn:air` name remain stable while keys, deployments, and identity systems
change.

The Trust Manifest does not yet give `identity` one consistent role. The
specification variously treats it as the artifact subject, workload principal,
key-resolution input, and publisher identity. These roles can coincide, but
they need not: a publisher can use a delegated signer, another organization can
operate the deployment, many workloads can serve one logical service, and a DID
controller need not be the DID subject.

The verification procedure also treats DID, HTTPS, SPIFFE, and DNS identifiers
as inputs to one URI-to-public-key resolver. They have different credential
delivery, authorization, trust-anchor, and lifecycle models. In particular,
the SPIFFE Workload API gives a calling workload its own X.509-SVIDs and private
keys; it does not resolve an arbitrary remote SPIFFE ID to a leaf certificate.
`did:web` resolves to a current DID document that can publish verification
material, but resolution alone does not decide which key is authorized for a
claim or how rotation affects old signatures.

Local fixes cannot supply the missing actor-and-claim model. Version 1 needs a
small, predictive trust core against which later fields and identity mechanisms
can be evaluated.

## Decision

Trust verification will be defined in terms of an explicit claim, protected
subject, actor roles, verifier policy, and named verification profile. A URI
scheme alone does not imply any of those things or a key-resolution algorithm.

This ADR establishes architectural constraints for subsequent schema and
verification PRs. It does not itself change the schema.

### 1. Distinguish actors and protected objects

The trust model will distinguish at least these concepts:

| Concept | Meaning |
|---|---|
| Relying party | Consumer making a trust or authorization decision |
| Catalog curator | Entity that selects entries and issues the catalog's listing claim |
| Catalog host | Distributor or mirror that serves catalog bytes |
| Namespace authority | Entity authorized to assign or delegate names under a `urn:air` publisher domain |
| Publisher | Entity that makes an artifact-release claim |
| Statement issuer | Principal represented as making a particular claim |
| Proof signer | Principal or credential holder represented by the verification material used to create a proof |
| Identity or credential authority | Principal that controls verification relationships or issues identity credentials |
| Deployment owner | Entity that authorizes a deployment of a logical service |
| Runtime workload | Running software participating in a deployment |
| Authenticated peer | Workload, proxy, or gateway authenticated in a live interaction |
| Attester | First or third party that issues an evidence claim |
| Catalog representation | Exact serialized catalog content protected by a catalog proof |
| Catalog entry | Curator-authored record associating discovery metadata with an artifact or release |
| Logical artifact | Stable artifact named by `CatalogEntry.identifier` |
| Artifact release | Publication or version realization of a logical artifact associated with one or more representations |
| Artifact-release statement | Publisher or authorized issuer's claim binding a release to its metadata and representations |
| Artifact representation | Exact artifact bytes identified by media type and digest |
| Logical service | Service described by an artifact and realized by deployments |
| Deployment | Environment-specific realization of a logical service |
| Runtime endpoint | Network location through which a deployment is accessed |
| Verification policy | Independently configured expectations, authorization rules, trust anchors, freshness rules, and evaluation context |

One entity MAY occupy several roles. That does not make the roles equivalent.
A release does not by itself imply that a version is unique or immutable; each
profile must define any such rule it needs.

The important relationships include:

```text
catalog curator  --issues listing claim-->  catalog entry
catalog host     --serves---------------->  catalog bytes
namespace authority --authorizes-------->  names or publisher namespace
publisher        --issues---------------->  artifact-release statement
statement issuer --authorizes------------>  proof signer, when they differ
deployment owner --authorizes------------>  deployment of logical service
deployment       --uses------------------>  workloads and endpoints
identity authority --authorizes/issues--->  verification material
```

### 2. Separate statement, proof, evidence, and verifier context

A signed statement has this conceptual form, independent of eventual JSON field
names:

```text
statement:
  protected profile type and version + issuer + subject + claims
  + asserted time, validity, and context + optional evidence references

proof:
  cryptographic binding over the exact serialized statement

verification:
  profile(statement, proof, expected claim and issuer,
          independent policy and trust anchors, evaluation time and state)
```

Trust anchors and expected issuers are verifier inputs, not signer-selected
content. A claimed issuer, key, anchor, or time inside a statement cannot make
itself trusted. Embedded or referenced evidence is a separate evidence object,
which may contain statements, and must be verified according to its own format
and profile; authenticating a reference proves only that the manifest issuer
made that reference.

As established by ADR-0020, a Trust Manifest MAY be unsigned when it carries
attestations, provenance, or a trust schema. Such a manifest is an evidence
or advisory-metadata container, not itself a signed statement. By itself it has
no authenticated manifest issuer or subject binding. Another authenticated
envelope can bind the container only to the extent defined by that envelope's
profile.

### 3. Define the relying-party decision

Every normative verification procedure MUST identify the decision it supports.
Success for one decision MUST NOT be described as proving another. In
particular:

- domain alignment proves namespace consistency, not publisher authorization;
- a valid proof establishes access to the proof key, not issuer authorization or
  trustworthiness without the profile's identity, delegation, status, policy,
  and anchor checks;
- authenticating a manifest's evidence reference does not authenticate the
  evidence issuer or validate the evidence claim;
- digest verification authenticates bytes, not a runtime endpoint;
- SPIFFE peer authentication establishes the identity under which the peer
  authenticated, not deployment ownership; and
- runtime authentication does not establish which artifact bytes are deployed
  without a separate measurement or binding.

The core normative version 1 trust decision is whether an independently
expected and authorized issuer made an artifact-release claim binding a logical
artifact and release metadata to exact representation bytes. Catalog curation
and signing, evidence verification, and runtime authentication are separate
decisions and require separate profiles.

### 4. Use role-labelled relationships, not aliases

Identifiers MAY be aliases only when they identify the same subject. Related
but distinct entities MUST use role-labelled relationships. For example, a
publisher DID usually authorizes or operates a deployment whose workloads use
SPIFFE IDs; the organization and workloads are not thereby the same subject.
An `alsoKnownAs` mechanism cannot represent this relationship by itself.

### 5. Define complete verification profiles

A profile is specific to a claim or role, proof mechanism, and verification
moment. `did:web artifact-release issuer` and `SPIFFE runtime peer` are distinct
profiles even though both use identity URIs.

Each normative profile MUST define:

1. a protected profile type and version, signature-domain separation, exact
   serialization, and proof input;
1. the issuer, subject, claims, and security-relevant protected values;
1. the proof signer and any authorization to act for the issuer;
1. independently expected identities, policy, trust anchors, and evaluation
   context;
1. how exact verification material is resolved or presented and bound to the
   declared identity;
1. verification relationships, key selection, and algorithm constraints;
1. validity, freshness, rotation, revocation, rollback, and historical behavior;
1. replay and cross-profile substitution prevention;
1. verification moment and required failure behavior; and
1. positive and negative interoperability vectors.

The core format MAY carry identities for which no core profile exists. A
consumer MUST NOT call such an identity cryptographically verified merely
because its URI is valid or its scheme is recognized.

### 6. Apply the model to `did:web` and SPIFFE

A `did:web` artifact-release profile must independently expect an exact DID or
key, or apply an explicit policy authorizing a constrained DID namespace. A
bare domain does not authorize every path-based DID beneath it. The profile
must pin or restate the required `did:web` resolution behavior, apply current
HTTPS service-identity validation, select an exact verification method with a
protected `kid`, require an appropriate relationship such as
`assertionMethod`, and define algorithms and current-state rotation behavior.
Durable historical validation additionally requires authenticated historical
identity and key state and trustworthy evidence binding the signature to a time
or identity-state version; a signer-provided `issuedAt` provides neither
independently.

A SPIFFE X.509-SVID signed-statement profile uses presented credentials, not
arbitrary Workload API resolution. It must define how the leaf SVID and chain
accompany the proof; independently anchor the binding between the expected
trust-domain name and bundle; perform full X.509-SVID validation with the bundle
for that trust domain; define KeyUsage and ExtendedKeyUsage compatibility for
statement signing; and define validity and rotation across replicas. Federation
parameters must be configured and anchored rather than inferred from a
trust-domain name or bundle.

A separate SPIFFE runtime-peer profile validates an SVID presented in a live
protocol interaction. It authenticates the peer under a SPIFFE ID. Deployment
authorization, the service exposed through proxies or gateways, and deployed
artifact bytes require separate policy or evidence.

### 7. Keep the version 1 profile set small

The first artifact-release profile MUST protect the logical identifier, version
semantics when present, media type, and digest. A location-bound variant MUST
also protect the retrieval URL. Profiles need not sign arbitrary discovery or
presentation metadata merely because a consumer might use it for filtering.

Version 1 SHOULD standardize the smallest proof mechanism set for which the
working group can provide complete algorithms, failure behavior, test vectors,
and implementation evidence. `did:web`, HTTPS JWKS, Sigstore, and SPIFFE remain
candidates until specified end to end. Other mechanisms SHOULD be marked
experimental or deferred instead of being accepted through a generic resolver.

## Consequences

- The current `identity` field and generic Key Resolution section remain under
  review until follow-up PRs assign unambiguous semantics and profiles.
- A field such as `runtimeIdentity`, multiple identities, and publisher-domain
  alignment will be evaluated against explicit claims and roles rather than as
  isolated fixes.
- Some listed identity mechanisms may be deferred from normative version 1
  verification while remaining available to extensions.
- Implementations gain predictable verification outcomes and failure modes
  instead of inferring security semantics from URI schemes.

## Alternatives Considered

### Patch only the SPIFFE resolution text

Rejected. SPIFFE exposes the immediate error, but issuer authorization, DID key
selection, catalog signing, evidence verification, and historical validation
depend on the same missing role-and-profile model.

### Add `runtimeIdentity` immediately

Deferred. A durable publisher and a runtime workload often have distinct
identities, but a workload can also issue a short-lived statement. Field design
must follow the supported claims and verification moments.

### Represent publisher and workload identities as aliases

Rejected as a general solution. They usually denote distinct entities connected
by authorization or operational relationships, not two names for one subject.

### Keep an open scheme list with implementation-defined verification

Rejected for normative trust decisions. Conforming consumers must not reach
different security conclusions because essential verifier behavior is absent.

## Follow-up Work

1. Decide issuer, publisher, namespace-authority, and delegation semantics for
   the core artifact-release claim.
1. Define the artifact-release statement schema and protected values.
1. Select and specify one complete version 1 proof profile with test vectors.
1. Address catalog curation, hosting, and signing as a separate trust decision.
1. Decide whether runtime identity belongs in the core, an extension, or
   protocol-native metadata.

## References

- [SPIFFE Workload API](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md)
- [SPIFFE ID](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md)
- [SPIFFE Trust Domain and Bundle](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Trust_Domain_and_Bundle.md)
- [SPIFFE X.509-SVID](https://github.com/spiffe/spiffe/blob/main/standards/X509-SVID.md)
- [SPIFFE Federation](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Federation.md)
- [W3C Decentralized Identifiers 1.0](https://www.w3.org/TR/did-core/)
- [W3C DID Resolution](https://www.w3.org/TR/did-resolution/)
- [`did:web` Method Specification (Community Group Draft)](https://w3c-ccg.github.io/did-method-web/)
- [RFC 9525: Service Identity in TLS](https://www.rfc-editor.org/rfc/rfc9525)
- [JSON Web Signature](https://www.rfc-editor.org/rfc/rfc7515)
- [AI Catalog Trust Manifest threat model](../specification/trust-manifest-threat-model.md)
- [ADR-0019: Trust Manifest artifact binding](0019-trust-manifest-artifact-binding.md)
- [ADR-0020: Substantive Trust Manifest](0020-substantive-trust-manifest.md)
