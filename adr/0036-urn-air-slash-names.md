# ADR-0036: Separate Publisher, Name, and Kind in `urn:air` Identifiers

**Status:** Proposed

**Date:** 2026-11-06

**Related:** [Issue #59](https://github.com/Agent-Card/ai-catalog/issues/59),
[ADR-0015](0015-agent-identifier-naming.md),
[ADR-0016](0016-displayname-optional.md)

## Context

ADR-0015 uses colons for both publisher boundaries and namespace segments.
Issue #59 introduces an optional conceptual kind suffix. Reusing colons for
both namespaces and an optional kind would make those components ambiguous.
[PR #137](https://github.com/Agent-Card/ai-catalog/pull/137) proposes a
semicolon suffix while retaining colon-separated namespaces.

## Decision

Propose the following format, where square brackets indicate an optional suffix:

```text
urn:air:{publisher}:{name}[:{kind}]
```

The publisher assigns the name, which can include slash-separated namespace
segments. For example:

```text
urn:air:acme.com:weather
urn:air:acme.com:finance/payments/weather
urn:air:acme.com:finance/payments/weather:mcp
```

Colons separate the publisher, name, and optional kind. Slashes separate
namespace segments within the name. The kind is part of the identifier;
identifiers that differ only in kind are different identifiers, with no
relationship between those artifacts implied by the spelling. Kind values
remain unspecified and do not replace the entry's media type.

The display-name fallback uses the final slash-separated name segment,
excluding kind. Publisher-domain extraction and the `identifier` plus
`version` uniqueness key retain their existing rules.

## Rationale

Each principal concept has its own colon-separated component, regardless of
namespace depth. Slash-separated namespaces use familiar notation, and the
optional kind is distinguishable without counting namespace segments.
[RFC 8141 §2.2](https://www.rfc-editor.org/rfc/rfc8141.html#section-2.2)
explicitly permits slashes in the namespace-specific string to encapsulate
hierarchical names.

The format also avoids the unquoted semicolon's command-separator behavior
in Bash. Quoting remains good practice when passing identifiers to a shell.

## Consequences

- Names use `/` for namespace boundaries and reserve literal `:` for component
  boundaries.
- Examples and authoring guidance use the same format throughout.
- Consumers deriving a display name ignore kind rather than displaying it
  as the artifact's name.
