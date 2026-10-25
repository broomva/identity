# ADR 0001: Identity wire contract

Status: accepted
Date: 2026-10-25

## Context

Maestro's Rust spec (`#n-identity`) and the fleet runtime-boundaries ADR (2026-10-19, section 2) put the typed identity of hosts, agents and the owner in a standalone crate. Maestro and the change plane consume it as a tagged git dependency. The spec cites the ADR for `Principal` and `SessionRef` and does not copy Maestro's phase-0 session type. This ADR records the choices the two documents leave to the crate.

## Options

1. Copy Maestro's `SessionRef { surface, environment, id }` and its three-variant `Principal`, including `permits()`.
2. Follow the spec's four-field session and the ADR's six principal variants, and keep permission tables out of this crate.
3. Leave node-id grammar, canonical bytes and the open enums unspecified until a later node needs them.

## Decision

Option 2. The choices below are decisions of this crate, not proposals waiting on the owner.

1. Canonical bytes for an attestation are a line-oriented UTF-8 document, domain `identity.attestation.v1`, not a signature. Object keys inside `extra` sort by UTF-16 code units. The signature algorithm stays the fleet ADR's open question and is not chosen here. Session-end bytes are decision 13.
2. `NodeId` is 1 to 64 ASCII alphanumeric bytes, the same bound Cuenca uses for a Tailscale stable node id. DNS names and node keys are rejected. The name `volume` is not reserved.
3. `SessionRef` is surface, harness, node and id. Maestro's `{ surface, environment, id }` is not this type. Display form is `{surface}:{harness}@{node}/{id}` and drops unknown keys. JSON keeps them.
4. `Surface`, `HarnessId` and `EndReason` are open on the wire: unknown tokens stay in `Other`. There is no `claude` alias of `claude-code`. The T3 token is `t3`. A known token passed as `Other` is stored as the known variant. `Other` holds an `OpenToken` whose constructor is crate-private. `parse` is the public constructor: it refuses a token that would not deserialize, and it stores a known token as the named variant. `Other("t3")` and `T3` therefore compare equal after construction, and both spellings on the wire are the named variant.
5. `Principal` is a closed set of six: owner, owner device, agent, runner job, service, unverified. The JSON `kind` is not proof. Owner has no `via` field; a `via` key in `extra` is preserved and not interpreted. This crate has no `permits()` table.
6. An attestation and a session key expire at most one hour after they are issued, checked in `try_new` and in `Deserialize`. A lifetime of exactly one hour is valid. Zero or negative is not. Renewal is a new record.
7. An attestation's node and a session key's node must equal the session's node.
8. Unknown keys live in `extra`. Attestation canonical bytes cover both the attestation extra and the session extra. Non-integer numbers are refused. Nesting deeper than 32 is refused. Keys that name a known field are refused. An unverified principal that carries `session` is refused with its own rule.
9. `version` must be the integer 1. A missing version is an error, not a default.
10. `schema/identity.v1.json` is JSON Schema draft 2020-12 generated from the types, then tightened, and checked in. It states every constraint the dialect can state: `version` is the integer const 1, node ids match `^[A-Za-z0-9]{1,64}$`, wire tokens reject a doubled hyphen and a newline, opaque ids are 1 to 256 code points without whitespace or controls, scope items are unique and match the scope token, timestamps fit in i64, extra numbers fit in i64 or u64, extra values nest at most 32 levels by unrolling `ExtraValue1` through `ExtraValue33`, and an unverified principal has `session: false`. Python and TypeScript bindings are part of 0.1.0. `scripts/generate_bindings.py` writes them from this schema. CI fails when the bindings are stale, and it runs `fixtures/conformance` through Rust, through Python `jsonschema`, and through the TypeScript validator under bun.
11. CI is fmt, clippy, tests, binding generation, and mutation. Maestro's plugin parity, tail bench and bridge check do not apply to this crate.
12. Fields are private. A constructed value cannot widen its expiry or attach a session after the fact. A JSON object with a repeated key is rejected while it is read. `serde_json::Value` would otherwise keep the last copy.
13. `SessionEnd::canonical_bytes` is the shared signing representation for a session end, domain `identity.session_end.v1`. The lines are version, surface, harness, node, session, ended_at, reason, then the session-end extra and the session extra under the same canonical object rules as an attestation. It is not a signature. Auth signs these bytes. The algorithm stays the fleet ADR's open question.

Draft 2020-12 cannot state the following. The schema accepts them, Rust rejects them, and each conformance fixture names the reason:

- bound node equals session node. There is no standard `$data` reference from the bound node to the session node.
- lifetime is not arithmetic. The schema can bound each timestamp, and it cannot state `0 < expires_at - issued_at <= 3600000` or that the subtraction overflows.
- maxLength counts code points. An opaque id of 100 `你` is 100 code points and 300 bytes. The schema's `maxLength` allows it. The crate counts bytes.
- duplicate keys are a parser rule. A JSON parser collapses a repeated key before the schema sees the object, so the corpus cannot carry a duplicate-key fixture. The deserializer rejects the second key.
- integral JSON numbers compare equal. `type: integer` and `const: 1` compare values. After a JSON parser, `1.0` and `1` are the same number, so the schema accepts the spelling Rust rejects.

## Consequences

Later nodes (event-stream, auth, host-identity) depend on these types and on both canonical documents. They do not reinterpret `extra`. A verifier, not this crate, decides who may construct `Owner`. The Python and TypeScript bindings validate the schema. Rust remains the judge of the inexpressible set above. The signing algorithm is still not chosen.
