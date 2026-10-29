# 0001. Identity wire contract

Date: 2026-10-25
Status: accepted

## Context

Maestro and the change plane share one JSON vocabulary for who is acting (`Principal`), which session they are acting through (`SessionRef`), and what a node-bound attestation says (`Attestation`, `SessionKey`, `SessionEnd`). Each surface used to invent its own spelling. The verifier lives in a later crate; this crate is the wire grammar and the canonical byte sequence a signature covers.

The fleet architecture requires a versioned JSON Schema, generated Python and TypeScript bindings, a shared conformance corpus, and a written list of rules that JSON Schema draft 2020-12 cannot express.

## Decision

1. `CONTRACT_VERSION` is `1`. `Attestation`, `SessionKey` and `SessionEnd` carry `"version": 1`. A missing, non-integer, or different version is refused.
2. `NodeId` is 1 to 64 ASCII alphanumeric bytes (`^[A-Za-z0-9]{1,64}$`). This is the same bound Cuenca uses for a Tailscale stable node id.
3. `Principal` is closed over six `kind` values: `owner`, `owner_device`, `agent`, `runner_job`, `service`, `unverified`. The `kind` field is a claim, not proof. `unverified` cannot carry a `session` key, even as an extra field.
4. `Surface`, `HarnessId` and `EndReason` are open on the wire: unknown tokens stay in `Other`. There is no `claude` alias of `claude-code`. The T3 token is `t3`. A known token passed as `Other` is stored as the known variant. Each enum is `#[non_exhaustive]` and its `Other` arm holds a distinct token type (`SurfaceToken`, `HarnessToken`, `EndReasonToken`) whose constructor is crate-private, so a token parsed for one enum cannot be placed in another. `parse` is the public constructor: it refuses a token that would not deserialize, and it stores a known token as the named variant. `Other("t3")` and `T3` therefore compare equal after construction, and both spellings on the wire are the named variant.
5. A wire token (`Surface`, `HarnessId`, `EndReason`, service `name`) is 1 to 64 ASCII bytes matching `^[a-z0-9][a-z0-9-]*$`, with no `--`.
6. `Attestation` and `SessionKey` require `node == session.node`, `expires_at > issued_at`, and `expires_at - issued_at <= 3_600_000` (one hour). Subtraction uses `checked_sub`.
7. `Attestation` scope tokens are sorted and deduplicated. A duplicate token in input is rejected.
8. Unknown object keys are kept in `Extra` and re-emitted on serialize. A reserved field name in `Extra` is rejected.
9. `Extra` values are null, bool, string, array, object, or an integer in `i64::MIN..=u64::MAX`. Floating-point numbers and nesting deeper than 32 levels are rejected.
10. `serde_json::Value` collapses duplicate object keys to the last copy. Deserializing any record in this crate uses a map visitor that rejects a repeated key before `Value` is built.
11. `Attestation::canonical_bytes` and `SessionEnd::canonical_bytes` emit UTF-8 JSON with no whitespace, object keys sorted by UTF-16 code units (RFC 8785 §3.2.3), `scope` already sorted, and every `Extra` map included.
12. Fields are private. A constructed value cannot widen its expiry or attach a session after the fact.
13. A scope token is 1 to 64 bytes. Its first byte is `[a-z0-9]`. Its remaining bytes are `[a-z0-9._-]`. It must not contain `..`.
14. An opaque id is 1 to 256 bytes. It must not contain whitespace or control characters.

## Schema and bindings

`schema/identity.v1.json` is generated from the Rust types by `schemars` and tightened by `src/schema_tighten.rs` so the schema carries the regex, length, integer range, depth, and `unverified` rules above. `scripts/generate_bindings.py` writes `bindings/python` and `bindings/typescript` from that schema and checks that the checked-in copies have not drifted.

Draft 2020-12 alone cannot state the following. The raw schema accepts them, while Rust, Python and TypeScript reject them via the generated bindings' semantic layer, and each conformance fixture names the reason:

- bound node equals session node. There is no standard `$data` reference from the bound node to the session node.
- lifetime is not arithmetic. The schema can bound each timestamp, and it cannot state `0 < expires_at - issued_at <= 3600000` or that the subtraction overflows.
- maxLength counts code points. An opaque id of 100 `你` is 100 code points and 300 bytes. The schema's `maxLength` allows it. The crate and bindings count UTF-8 bytes.
- duplicate keys are a parser rule. A standard JSON parser collapses a repeated key before the schema sees the object. Rust, Python and TypeScript reject the repeated key during parsing.
- integral JSON numbers compare equal. `type: integer` and `const: 1` compare values. After a standard JSON parser, `1.0` and `1` are the same number, so the schema accepts the spelling that Rust, Python and TypeScript reject.
- lone UTF-16 surrogate code units are rejected by parser/UTF-8 validation before or after JSON Schema evaluation. A permissive JSON parser decodes `\uD800` into a string that Draft 2020-12 `type: string` accepts, whereas Rust, Python and TypeScript reject lone surrogates during parsing or UTF-8 validation.
- malformed JSON number syntax (leading zero) is rejected by RFC 8259 JSON parsing before JSON Schema evaluation. Standard JSON parsers reject `01e17` as a syntax error before a JSON Schema validator can inspect a parsed instance.

## Consequences

`tests/conformance.rs` runs every fixture through Rust, Python `jsonschema`, and TypeScript `Ajv` (via `bun`), verifying 100% rejection parity across all invalid fixtures and 100% Rust ↔ Python/TypeScript round-trip parity across all valid fixtures.
