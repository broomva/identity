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

1. Canonical bytes are a line-oriented UTF-8 document for an attestation, domain `identity.attestation.v1`, not a signature. Object keys inside `extra` sort by UTF-16 code units. The signature algorithm stays the fleet ADR's open question and is not chosen here.
2. `NodeId` is 1 to 64 ASCII alphanumeric bytes, the same bound Cuenca uses for a Tailscale stable node id. DNS names and node keys are rejected. The name `volume` is not reserved.
3. `SessionRef` is surface, harness, node and id. Maestro's `{ surface, environment, id }` is not this type. Display form is `{surface}:{harness}@{node}/{id}` and drops unknown keys. JSON keeps them.
4. `Surface`, `HarnessId` and `EndReason` are open on the wire: unknown tokens stay in `Other`. There is no `claude` alias of `claude-code`. The T3 token is `t3`. A known token passed as `Other` is stored as the known variant.
5. `Principal` is a closed set of six: owner, owner device, agent, runner job, service, unverified. The JSON `kind` is not proof. Owner has no `via` field; a `via` key in `extra` is preserved and not interpreted. This crate has no `permits()` table.
6. An attestation and a session key expire at most one hour after they are issued, checked in `try_new` and in `Deserialize`. A lifetime of exactly one hour is valid. Zero or negative is not. Renewal is a new record.
7. An attestation's node and a session key's node must equal the session's node.
8. Unknown keys live in `extra`. Attestation canonical bytes cover both the attestation extra and the session extra. Non-integer numbers are refused. Nesting deeper than 32 is refused. Keys that name a known field are refused. An unverified principal that carries `session` is refused with its own rule.
9. `version` must be the integer 1. A missing version is an error, not a default.
10. `schema/identity.v1.json` is JSON Schema draft 2020-12 generated from the types and checked in. The schema is weaker than the code: it does not encode the one-hour lifetime, the node-id alphabet, the doubled hyphen, integer-only extra, or the depth cap. Python and TypeScript bindings are not part of 0.1.0.
11. CI is fmt, clippy, tests and mutation. Maestro's plugin parity, tail bench and bridge check do not apply to this crate.
12. Fields are private. A constructed value cannot widen its expiry or attach a session after the fact.

## Consequences

Later nodes (event-stream, auth, host-identity) depend on these types and on the canonical bytes. They do not reinterpret `extra`. A verifier, not this crate, decides who may construct `Owner`. Generated bindings, when they exist, must be checked against `schema/identity.v1.json` and against the stricter rules above.
