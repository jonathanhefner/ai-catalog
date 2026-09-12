# Signature conformance vectors

Run the informative, dependency-free harness from the repository root with
Node.js 22 or later:

```sh
node --test tools/check_signatures.mjs
```

`entry-signature.json` contains a fixed test-only P-256 public JWK, a catalog
entry, UTF-8 artifact content, its SHA-256 digest, a detached compact ES256 JWS,
and the exact expected JCS payload string. A second signature covers the same
entry without its optional version. No private key or live DID resolution is
needed. These are fixed verification vectors: repeated verification produces
the same result; generating a fresh ECDSA signature need not reproduce the
same signature bytes.

The entry uses `trustManifests` keyed by contributor identity. Both evidence
collections remain arrays. The `signatures` name inside an opaque extension
is deliberately ordinary extension data: retaining it checks that payload
construction never recursively strips similarly named members. Actual catalog
Signature objects are permitted only on entries, Host Info, and the root.

The harness verifies real ECDSA signatures using Node's built-in crypto API and
the JOSE IEEE-P1363 signature encoding. It reconstructs the base64url-encoded
payload in the JWS signing input. It tests ordering independence, path/value
binding, stable contributor keys, unselected additions, selected-array and
nested-signature changes, missing/overlapping paths, domain separation,
authenticated timestamps, expiration, release coverage, and artifact bytes.

The unsigned-version test deliberately demonstrates that successful signature
verification alone is insufficient: inserting an unselected version leaves the
cryptographic signature valid but fails the required release-coverage check.

This is not a production verification library or a complete profile verifier.
The trusted public key is supplied by the fixture; DID resolution, issuer/key
authorization, publisher-domain matching, network retrieval, replay policy,
schema validation, and resource limits are outside this harness. The small
canonicalizer operates on already-parsed I-JSON values; production parsers must
reject duplicate object names before parsing discards them. Timestamp parsing
only exercises ordinary RFC 3339 instants used in these vectors and is not a
complete RFC 3339 validator (notably, leap-second handling is omitted). Header
parsing likewise assumes the well-formed JSON fixture rather than implementing
a hardened JOSE parser. Unknown critical headers are rejected because this
fixture profile uses none.
