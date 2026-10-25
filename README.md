# identity

Typed identity of hosts, agents and the owner. Maestro and the change plane share this crate. It is serde only: no keys, no signatures, no permission table.

A `Principal` is one of owner, owner device, agent, runner job, service or unverified. A `SessionRef` is a surface, a harness, a node and an id. An `Attestation` names a session, a node, a scope and an expiry of at most one hour. `Attestation::canonical_bytes` is the UTF-8 document a later verifier signs. This crate does not sign it and does not check a signature.

The wire version is 1. Unknown JSON keys are kept. The JSON Schema is `schema/identity.v1.json`.

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

`scripts/ci.sh` runs fmt, clippy, tests and mutation. Decisions are in `docs/adr/0001-identity-wire-contract.md`.
