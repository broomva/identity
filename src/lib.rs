//! Typed identity of hosts, agents and the owner.
//!
//! This is the shared wire contract for Maestro and the change plane. It defines
//! who a caller is ([`Principal`]), which session they are ([`SessionRef`]), and
//! the bytes an attestation is signed over ([`Attestation::canonical_bytes`]).
//! It holds no key. Deserializing [`Principal`] does not prove that principal:
//! a verifier, in a later crate, decides who may construct `Owner`.
//!
//! The wire version is [`CONTRACT_VERSION`]. Any other version is refused.
//! Unknown keys are kept on each record and, for an attestation, covered by the
//! canonical bytes. The JSON Schema checked into `schema/identity.v1.json` is
//! generated from these types ([`SCHEMA_V1`]).
//!
//! ```
//! use identity::{Extra, NodeId, Principal};
//!
//! let node = NodeId::parse("nwPbDUaNzo11CNTRL")?;
//! let device = Principal::owner_device(node, Extra::new())?;
//! assert_eq!(device.kind(), identity::PrincipalKind::OwnerDevice);
//! # Ok::<(), identity::IdentityError>(())
//! ```

#![deny(missing_docs)]

mod attestation;
mod canonical;
mod check;
mod object;
mod principal;
#[cfg(test)]
mod schema_tighten;
mod session;

pub use attestation::{Attestation, EndReason, SessionEnd, SessionKey};
pub use check::IdentityError;
pub use principal::{Principal, PrincipalKind};
pub use serde_json::Value;
pub use session::{HarnessId, NodeId, OpenToken, SessionRef, Surface};

/// Unknown keys kept on a record, in sorted order.
pub type Extra = serde_json::Map<String, Value>;

/// Wire contract this crate reads and writes. A different version is an error.
pub const CONTRACT_VERSION: u32 = 1;

/// Longest attestation or session-key lifetime, in milliseconds. One hour.
pub const MAX_TTL_MS: i64 = 3_600_000;

/// Longest Tailscale stable node id, in bytes. The same bound Cuenca uses.
pub const MAX_NODE_BYTES: usize = 64;

/// Longest session id, runner-job id or public key id, in bytes.
pub const MAX_ID_BYTES: usize = 256;

/// Deepest value kept inside [`Extra`], counting the value stored on the record as 1.
///
/// One step past this is refused, so canonicalization cannot recurse without a bound.
pub const MAX_EXTRA_DEPTH: usize = 32;

/// JSON Schema draft 2020-12 generated from the types. `scripts/ci.sh` fails if it drifts.
pub const SCHEMA_V1: &str = include_str!("../schema/identity.v1.json");

#[cfg(test)]
mod schema_tests {
    use super::*;
    use schemars::schema_for;

    fn generated_schema() -> Value {
        let defs = serde_json::json!({
            "Principal": schema_for!(Principal),
            "SessionRef": schema_for!(SessionRef),
            "Attestation": schema_for!(Attestation),
            "SessionEnd": schema_for!(SessionEnd),
            "SessionKey": schema_for!(SessionKey),
            "NodeId": schema_for!(NodeId),
            "Surface": schema_for!(Surface),
            "HarnessId": schema_for!(HarnessId),
            "EndReason": schema_for!(EndReason),
        });
        let document = serde_json::json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "https://github.com/broomva/identity/blob/v0.1.0/schema/identity.v1.json",
            "title": "identity.v1",
            "description": "Wire contract version 1. A version field must be the integer 1. Node ids are 1-64 ASCII alphanumeric characters. Wire tokens are lowercase and reject a doubled hyphen. Opaque ids are 1-256 code points without whitespace or controls. Scope tokens are unique. Extra values are integers in the i64 or u64 range and nest at most 32 levels. An unverified principal has no session. Node equality, lifetime arithmetic, byte length, duplicate keys, and the spelling of an integral number are not expressible here.",
            "version": CONTRACT_VERSION,
            "$defs": defs,
        });
        schema_tighten::finish(document)
    }

    #[test]
    fn checked_in_schema_matches_the_types() {
        let got = serde_json::to_string_pretty(&generated_schema()).unwrap() + "\n";
        if std::env::var_os("IDENTITY_WRITE_SCHEMA").is_some() {
            let path = concat!(env!("CARGO_MANIFEST_DIR"), "/schema/identity.v1.json");
            std::fs::write(path, &got).unwrap();
        }
        assert_eq!(
            SCHEMA_V1, got,
            "schema/identity.v1.json drifted from the types; replace it with the generated document"
        );
    }
}
