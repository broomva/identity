//! An attestation names a session, a node, a scope and an expiry of at most one hour.
//! This crate defines the bytes. It does not sign them and it does not check a signature.

use std::fmt;
use std::str::FromStr;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::canonical;
use crate::check::{self, IdentityError};
use crate::object;
use crate::session::{NodeId, OpenToken, SessionRef};
use crate::{CONTRACT_VERSION, Extra, Value};

/// Why a session ended. Unknown wire tokens stay [`EndReason::Other`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EndReason {
    /// The work finished.
    Completed,
    /// Someone revoked it.
    Revoked,
    /// The expiry passed.
    Expired,
    /// A wire token this crate does not name.
    ///
    /// Build one with [`EndReason::parse`]. A known token is never stored here.
    Other(OpenToken),
}

impl EndReason {
    /// Accept an end reason.
    ///
    /// # Errors
    ///
    /// The text is not a lowercase wire token.
    pub fn parse(raw: &str) -> Result<Self, IdentityError> {
        check::require_wire_token(raw)?;
        Ok(match raw {
            "completed" => Self::Completed,
            "revoked" => Self::Revoked,
            "expired" => Self::Expired,
            other => Self::Other(OpenToken::from_validated(other)),
        })
    }

    /// The wire token.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Completed => "completed",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
            Self::Other(token) => token.as_str(),
        }
    }
}

impl fmt::Display for EndReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for EndReason {
    type Err = IdentityError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        Self::parse(raw)
    }
}

impl Serialize for EndReason {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for EndReason {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(D::Error::custom)
    }
}

const ATTESTATION_FIELDS: &[&str] = &[
    "version",
    "session",
    "node",
    "scope",
    "issued_at",
    "expires_at",
];

const SESSION_KEY_FIELDS: &[&str] = &[
    "version",
    "session",
    "node",
    "key_id",
    "issued_at",
    "expires_at",
];

const SESSION_END_FIELDS: &[&str] = &["version", "session", "ended_at", "reason"];

/// A claim that a session may act within a scope on a node until it expires.
///
/// The lifetime is greater than zero and at most one hour. Renewal is a new value.
/// The bound node equals the session node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
pub struct Attestation {
    version: u32,
    session: SessionRef,
    node: NodeId,
    scope: Vec<String>,
    issued_at: i64,
    expires_at: i64,
    #[serde(flatten)]
    extra: Extra,
}

impl Attestation {
    /// Build an attestation at [`CONTRACT_VERSION`](crate::CONTRACT_VERSION).
    ///
    /// Scope tokens are checked, de-duplicated and stored sorted.
    ///
    /// # Errors
    ///
    /// The node does not match the session, the lifetime is not inside one hour, a scope token
    /// is invalid or repeated, or `extra` is rejected.
    pub fn try_new(
        session: SessionRef,
        node: NodeId,
        scope: impl IntoIterator<Item = impl AsRef<str>>,
        issued_at: i64,
        expires_at: i64,
        extra: Extra,
    ) -> Result<Self, IdentityError> {
        check::require_same_node(session.node(), &node)?;
        check::require_ttl(issued_at, expires_at)?;
        let scope = check::normalize_scope(scope)?;
        check::validate_extra(&extra)?;
        check::reject_reserved(&extra, ATTESTATION_FIELDS)?;
        Ok(Self {
            version: CONTRACT_VERSION,
            session,
            node,
            scope,
            issued_at,
            expires_at,
            extra,
        })
    }

    pub(crate) fn from_value(value: Value) -> Result<Self, IdentityError> {
        let mut object = object::expect_object(value, "attestation must be a JSON object")?;
        let version = check::require_version_field(object.remove("version"))?;
        let session = take_session(&mut object)?;
        let node = take_node(&mut object)?;
        check::require_same_node(session.node(), &node)?;
        let scope = take_scope(&mut object)?;
        let issued_at = object::take_i64(
            &mut object,
            "issued_at",
            "missing issued_at",
            "issued_at must be an integer",
        )?;
        let expires_at = object::take_i64(
            &mut object,
            "expires_at",
            "missing expires_at",
            "expires_at must be an integer",
        )?;
        check::require_ttl(issued_at, expires_at)?;
        check::validate_extra(&object)?;
        check::reject_reserved(&object, ATTESTATION_FIELDS)?;
        Ok(Self {
            version,
            session,
            node,
            scope,
            issued_at,
            expires_at,
            extra: object,
        })
    }

    /// The contract version. Always [`CONTRACT_VERSION`](crate::CONTRACT_VERSION) for a value this crate built.
    pub fn version(&self) -> u32 {
        self.version
    }

    /// The session the claim is about.
    pub fn session(&self) -> &SessionRef {
        &self.session
    }

    /// The node the claim is bound to. Equal to [`SessionRef::node`].
    pub fn node(&self) -> &NodeId {
        &self.node
    }

    /// Scope tokens, sorted and unique.
    pub fn scope(&self) -> &[String] {
        &self.scope
    }

    /// Unix timestamp in milliseconds when the claim was issued.
    pub fn issued_at(&self) -> i64 {
        self.issued_at
    }

    /// Unix timestamp in milliseconds when the claim expires.
    pub fn expires_at(&self) -> i64 {
        self.expires_at
    }

    /// Unknown keys. They are covered by [`Attestation::canonical_bytes`].
    pub fn extra(&self) -> &Extra {
        &self.extra
    }

    /// The bytes a later verifier signs. UTF-8, one field per line, ending in a newline.
    ///
    /// The domain line is `identity.attestation.v1`. `extra` and the session's extra are canonical
    /// JSON with object keys ordered by UTF-16 code units. This is not a signature.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        canonical::attestation_bytes(self)
    }
}

impl<'de> Deserialize<'de> for Attestation {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = object::deserialize_value(deserializer)?;
        Self::from_value(value).map_err(D::Error::custom)
    }
}

/// The public half of a node-bound session key. The secret never enters this type.
///
/// The lifetime rule is the same one-hour rule as an attestation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
pub struct SessionKey {
    version: u32,
    session: SessionRef,
    node: NodeId,
    key_id: String,
    issued_at: i64,
    expires_at: i64,
    #[serde(flatten)]
    extra: Extra,
}

impl SessionKey {
    /// Describe a session key. This stores no secret material.
    ///
    /// # Errors
    ///
    /// The node does not match the session, the key id is rejected, the lifetime is outside one
    /// hour, or `extra` is rejected.
    pub fn try_new(
        session: SessionRef,
        node: NodeId,
        key_id: &str,
        issued_at: i64,
        expires_at: i64,
        extra: Extra,
    ) -> Result<Self, IdentityError> {
        check::require_same_node(session.node(), &node)?;
        check::require_opaque_id(key_id)?;
        check::require_ttl(issued_at, expires_at)?;
        check::validate_extra(&extra)?;
        check::reject_reserved(&extra, SESSION_KEY_FIELDS)?;
        Ok(Self {
            version: CONTRACT_VERSION,
            session,
            node,
            key_id: key_id.to_owned(),
            issued_at,
            expires_at,
            extra,
        })
    }

    pub(crate) fn from_value(value: Value) -> Result<Self, IdentityError> {
        let mut object = object::expect_object(value, "session key must be a JSON object")?;
        let version = check::require_version_field(object.remove("version"))?;
        let session = take_session(&mut object)?;
        let node = take_node(&mut object)?;
        check::require_same_node(session.node(), &node)?;
        let key_id = object::take_string(
            &mut object,
            "key_id",
            "missing key_id",
            "key_id must be a string",
        )?;
        check::require_opaque_id(&key_id)?;
        let issued_at = object::take_i64(
            &mut object,
            "issued_at",
            "missing issued_at",
            "issued_at must be an integer",
        )?;
        let expires_at = object::take_i64(
            &mut object,
            "expires_at",
            "missing expires_at",
            "expires_at must be an integer",
        )?;
        check::require_ttl(issued_at, expires_at)?;
        check::validate_extra(&object)?;
        check::reject_reserved(&object, SESSION_KEY_FIELDS)?;
        Ok(Self {
            version,
            session,
            node,
            key_id,
            issued_at,
            expires_at,
            extra: object,
        })
    }

    /// The contract version.
    pub fn version(&self) -> u32 {
        self.version
    }

    /// The session the key belongs to.
    pub fn session(&self) -> &SessionRef {
        &self.session
    }

    /// The node the key is bound to.
    pub fn node(&self) -> &NodeId {
        &self.node
    }

    /// Public id of the key. Not the key itself.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Unix timestamp in milliseconds when the key was issued.
    pub fn issued_at(&self) -> i64 {
        self.issued_at
    }

    /// Unix timestamp in milliseconds when the key expires.
    pub fn expires_at(&self) -> i64 {
        self.expires_at
    }

    /// Unknown keys.
    pub fn extra(&self) -> &Extra {
        &self.extra
    }
}

impl<'de> Deserialize<'de> for SessionKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = object::deserialize_value(deserializer)?;
        Self::from_value(value).map_err(D::Error::custom)
    }
}

/// A session has ended. This is a record, not a signature.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
pub struct SessionEnd {
    version: u32,
    session: SessionRef,
    ended_at: i64,
    reason: EndReason,
    #[serde(flatten)]
    extra: Extra,
}

impl SessionEnd {
    /// Record that `session` ended.
    ///
    /// # Errors
    ///
    /// The reason token is rejected, or `extra` is rejected.
    pub fn try_new(
        session: SessionRef,
        ended_at: i64,
        reason: EndReason,
        extra: Extra,
    ) -> Result<Self, IdentityError> {
        let reason = EndReason::parse(reason.as_str())?;
        check::validate_extra(&extra)?;
        check::reject_reserved(&extra, SESSION_END_FIELDS)?;
        Ok(Self {
            version: CONTRACT_VERSION,
            session,
            ended_at,
            reason,
            extra,
        })
    }

    pub(crate) fn from_value(value: Value) -> Result<Self, IdentityError> {
        let mut object = object::expect_object(value, "session end must be a JSON object")?;
        let version = check::require_version_field(object.remove("version"))?;
        let session = take_session(&mut object)?;
        let ended_at = object::take_i64(
            &mut object,
            "ended_at",
            "missing ended_at",
            "ended_at must be an integer",
        )?;
        let reason = EndReason::parse(&object::take_string(
            &mut object,
            "reason",
            "missing reason",
            "reason must be a string",
        )?)?;
        check::validate_extra(&object)?;
        check::reject_reserved(&object, SESSION_END_FIELDS)?;
        Ok(Self {
            version,
            session,
            ended_at,
            reason,
            extra: object,
        })
    }

    /// The contract version.
    pub fn version(&self) -> u32 {
        self.version
    }

    /// The session that ended.
    pub fn session(&self) -> &SessionRef {
        &self.session
    }

    /// Unix timestamp in milliseconds when it ended.
    pub fn ended_at(&self) -> i64 {
        self.ended_at
    }

    /// Why it ended.
    pub fn reason(&self) -> &EndReason {
        &self.reason
    }

    /// Unknown keys.
    pub fn extra(&self) -> &Extra {
        &self.extra
    }

    /// The bytes a later verifier signs for a session end. UTF-8, one field per line.
    ///
    /// The domain line is `identity.session_end.v1`. This is not a signature.
    /// Auth can read it with the same line rules as an attestation.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        canonical::session_end_bytes(self)
    }
}

impl<'de> Deserialize<'de> for SessionEnd {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = object::deserialize_value(deserializer)?;
        Self::from_value(value).map_err(D::Error::custom)
    }
}

fn take_session(object: &mut serde_json::Map<String, Value>) -> Result<SessionRef, IdentityError> {
    let value = object
        .remove("session")
        .ok_or(IdentityError::rule("missing session"))?;
    SessionRef::from_value(value)
}

fn take_node(object: &mut serde_json::Map<String, Value>) -> Result<NodeId, IdentityError> {
    NodeId::parse(&object::take_string(
        object,
        "node",
        "missing node",
        "node must be a string",
    )?)
}

fn take_scope(object: &mut serde_json::Map<String, Value>) -> Result<Vec<String>, IdentityError> {
    let value = object
        .remove("scope")
        .ok_or(IdentityError::rule("missing scope"))?;
    let Value::Array(items) = value else {
        return Err(IdentityError::rule("scope must be an array of strings"));
    };
    let mut tokens = Vec::with_capacity(items.len());
    for item in items {
        let Value::String(token) = item else {
            return Err(IdentityError::rule("scope must be an array of strings"));
        };
        tokens.push(token);
    }
    check::normalize_scope(tokens)
}

#[cfg(test)]
impl schemars::JsonSchema for EndReason {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "EndReason".into()
    }

    fn schema_id() -> std::borrow::Cow<'static, str> {
        concat!(module_path!(), "::EndReason").into()
    }

    fn inline_schema() -> bool {
        true
    }

    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "minLength": 1,
            "maxLength": 64,
            "pattern": "^[a-z0-9][a-z0-9-]*$",
            "anyOf": [
                { "enum": ["completed", "revoked", "expired"] },
                { "type": "string" }
            ],
            "description": "A lowercase wire token. The crate also rejects a doubled hyphen."
        })
    }
}

#[cfg(test)]
mod open_enum_tests {
    use super::*;
    use crate::Extra;
    use crate::session::HarnessId;

    #[test]
    fn try_new_canonicalizes_a_known_reason_stuffed_into_other() {
        let session = SessionRef::try_new(
            crate::session::Surface::parse("t3").unwrap(),
            HarnessId::parse("codex").unwrap(),
            NodeId::parse("n1").unwrap(),
            "id",
            Extra::new(),
        )
        .unwrap();
        let end = SessionEnd::try_new(
            session,
            1,
            EndReason::Other(OpenToken::from_validated("completed")),
            Extra::new(),
        )
        .unwrap();
        assert_eq!(end.reason(), &EndReason::Completed);
    }
}
