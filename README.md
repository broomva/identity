# identity

Typed identity of hosts, agents and the owner. Maestro and the change plane share this crate. It is serde only: no keys, no signatures, no permission table.

A `Principal` is one of owner, owner device, agent, runner job, service or unverified. A `SessionRef` is a surface, a harness, a node and an id. An `Attestation` names a session, a node, a scope and an expiry of at most one hour. `Attestation::canonical_bytes` and `SessionEnd::canonical_bytes` are the UTF-8 documents a later verifier signs. This crate does not sign them and does not check a signature.

The wire version is 1. Unknown JSON keys are kept. A repeated key is rejected. The JSON Schema is `schema/identity.v1.json`. `scripts/generate_bindings.py` writes Python and TypeScript bindings from that schema. `fixtures/conformance` is the corpus Rust, Python `jsonschema`, and the TypeScript validator share. The schema cannot express node equality, lifetime arithmetic, byte length, duplicate keys, or the spelling `1.0`. Those stay Rust rules. Decisions are in `docs/adr/0001-identity-wire-contract.md`.

```rust
use identity::{Extra, NodeId, Principal};

let node = NodeId::parse("nwPbDUaNzo11CNTRL")?;
let device = Principal::owner_device(node, Extra::new())?;
# Ok::<(), identity::IdentityError>(())
```

Depend on a tag, not a path:

```toml
identity = { git = "https://github.com/broomva/identity", tag = "v0.1.0" }
```

The `v0.1.0` tag is cut when this branch merges. Until then, pin the commit.

```bash
cargo test
cargo run --example dogfood
bash scripts/ci.sh
```

`scripts/ci.sh` runs binding generation, fmt, clippy, tests and mutation. The tests shell out to `python3` (with `jsonschema`) and `bun`.
