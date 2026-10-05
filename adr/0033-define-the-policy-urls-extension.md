# ADR-0033: Define the Policy URLs Extension

**Status:** Proposed

**Date:** 2026-10-05

## Context

Privacy-policy and terms-of-service URLs describe policies governing an
artifact. They have a common display purpose, but they are not themselves
artifact-integrity evidence. Keeping them on the entry provides one place
to find them when an entry contains several contributors' Trust Manifests.
[ADR-0032](0032-bind-entry-extensions-through-digests.md) supplies optional
authentication of entry extensions.

## Decision

Replace the core entry fields `privacyPolicyUrl` and `termsOfServiceUrl`
with one official entry extension:

```json
{
  "extensions": {
    "https://ai-catalog.org/extensions/policy-urls": {
      "privacyPolicyUrl": "https://example.com/privacy",
      "termsOfServiceUrl": "https://example.com/terms"
    }
  }
}
```

Both members are optional strings containing URLs, retaining the existing
fields' URL requirements and meanings. These are the policies governing
the artifact, not the catalog operator's own service policies.

Either a publisher or catalog operator may populate the extension. A Trust
Manifest MAY authenticate its complete value through `subject.extensionDigests`;
no profile currently defined by this specification requires that coverage.

## Rationale

An official extension provides a predictable location for common metadata
without giving policy links a special signing mechanism. Optional coverage
allows catalog enrichment while preserving a contributor's ability to
authenticate the links it supplies or adopts.

## Consequences

- Consumers must read the official extension instead of the former core
  entry fields.
- A verified artifact endorsement may coexist with policy links that the
  publisher has not authenticated. Matching extension coverage establishes
  attribution to its signer; publisher attribution additionally requires
  the publisher-authority checks.
- Changing either URL changes the extension's digest. A mismatch affects
  this extension's authenticated coverage, not other matching bindings.
- Signing a URL authenticates the reference, not the contents of a policy
  document that can change at that URL.
