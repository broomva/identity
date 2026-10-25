//! A session is a surface, a harness, a node and an id.

use std::fmt;
use std::str::FromStr;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::check::{self, IdentityError};
use crate::object;
use crate::{Extra, MAX_NODE_BYTES, Value};

/// Tailscale stable node id. One to sixty-four ASCII alphanumeric bytes.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
pub struct NodeId(String);

impl NodeId {
    /// Accept a stable node id.
    ///
    /// # Errors
    ///
    /// Empty, longer than [`MAX_NODE_BYTES`](crate::MAX_NODE_BYTES), or not ASCII alphanumeric.
    pub fn parse(raw: &str) -> Result<Self, IdentityError> {
        if raw.is_empty() {
            return Err(IdentityError::rule("node id is empty"));
        }
        if raw.len() > MAX_NODE_BYTES {
            return Err(IdentityError::rule("node id is longer than 64 bytes"));
        }
        if !raw.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
            return Err(IdentityError::rule("node id must be ASCII alphanumeric"));
        }
        Ok(Self(raw.to_owned()))
    }

    /// The id text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for NodeId {
    type Err = IdentityError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        Self::parse(raw)
    }
}

impl TryFrom<&str> for NodeId {
    type Error = IdentityError;

    fn try_from(raw: &str) -> Result<Self, Self::Error> {
        Self::parse(raw)
    }
}

impl<'de> Deserialize<'de> for NodeId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(D::Error::custom)
    }
}

/// Where a session is attached. Unknown wire tokens stay [`Surface::Other`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Surface {
    /// Paseo.
    Paseo,
    /// T3.
    T3,
    /// A direct session, with no surface product in front.
    Direct,
    /// A wire token this crate does not name.
    Other(String),
}

impl Surface {
    /// Accept a surface token.
    ///
    /// # Errors
    ///
    /// The text is not a lowercase wire token.
    pub fn parse(raw: &str) -> Result<Self, IdentityError> {
        check::require_wire_token(raw)?;
        Ok(match raw {
            "paseo" => Self::Paseo,
            "t3" => Self::T3,
            "direct" => Self::Direct,
            other => Self::Other(other.to_owned()),
        })
    }

    /// The wire token.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Paseo => "paseo",
            Self::T3 => "t3",
            Self::Direct => "direct",
            Self::Other(token) => token,
        }
    }
}

impl fmt::Display for Surface {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Serialize for Surface {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Surface {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(D::Error::custom)
    }
}

/// Which harness is running. `claude` is not an alias of `claude-code`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HarnessId {
    /// Claude Code.
    ClaudeCode,
    /// Codex.
    Codex,
    /// Gemini.
    Gemini,
    /// Antigravity.
    Agy,
    /// A wire token this crate does not name.
    Other(String),
}

impl HarnessId {
    /// Accept a harness token.
    ///
    /// # Errors
    ///
    /// The text is not a lowercase wire token.
    pub fn parse(raw: &str) -> Result<Self, IdentityError> {
        check::require_wire_token(raw)?;
        Ok(match raw {
            "claude-code" => Self::ClaudeCode,
            "codex" => Self::Codex,
            "gemini" => Self::Gemini,
            "agy" => Self::Agy,
            other => Self::Other(other.to_owned()),
        })
    }

    /// The wire token.
    pub fn as_str(&self) -> &str {
        match self {
            Self::ClaudeCode => "claude-code",
            Self::Codex => "codex",
            Self::Gemini => "gemini",
            Self::Agy => "agy",
            Self::Other(token) => token,
        }
    }
}

impl fmt::Display for HarnessId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Serialize for HarnessId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for HarnessId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(D::Error::custom)
    }
}

/// One running session: surface, harness, node and a surface-local id.
///
/// The display form is `{surface}:{harness}@{node}/{id}`. It does not carry unknown keys. JSON does.
#[derive(Clone, Debug, Serialize)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
pub struct SessionRef {
    surface: Surface,
    harness: HarnessId,
    node: NodeId,
    id: String,
    #[serde(flatten)]
    extra: Extra,
}

impl SessionRef {
    /// Build a session.
    ///
    /// A known token passed as [`Surface::Other`] or [`HarnessId::Other`] is stored as the known variant.
    ///
    /// # Errors
    ///
    /// The id is empty, too long, or contains whitespace or controls. `extra` holds a reserved field,
    /// a non-integer, or is nested too deeply. A surface or harness token is not a wire token.
    pub fn try_new(
        surface: Surface,
        harness: HarnessId,
        node: NodeId,
        id: &str,
        extra: Extra,
    ) -> Result<Self, IdentityError> {
        let surface = Surface::parse(surface.as_str())?;
        let harness = HarnessId::parse(harness.as_str())?;
        check::require_opaque_id(id)?;
        check::validate_extra(&extra)?;
        check::reject_reserved(&extra, &["surface", "harness", "node", "id"])?;
        Ok(Self {
            surface,
            harness,
            node,
            id: id.to_owned(),
            extra,
        })
    }

    /// Parse `{surface}:{harness}@{node}/{id}`.
    ///
    /// The id is everything after the first slash, so it may itself contain slashes.
    ///
    /// # Errors
    ///
    /// The text is not that shape, or one of the four fields is rejected.
    pub fn parse(raw: &str) -> Result<Self, IdentityError> {
        let Some((surface, rest)) = raw.split_once(':') else {
            return Err(IdentityError::rule(
                "session ref must be surface:harness@node/id",
            ));
        };
        let Some((harness, rest)) = rest.split_once('@') else {
            return Err(IdentityError::rule(
                "session ref must be surface:harness@node/id",
            ));
        };
        let Some((node, id)) = rest.split_once('/') else {
            return Err(IdentityError::rule(
                "session ref must be surface:harness@node/id",
            ));
        };
        Self::try_new(
            Surface::parse(surface)?,
            HarnessId::parse(harness)?,
            NodeId::parse(node)?,
            id,
            Extra::new(),
        )
    }

    pub(crate) fn from_value(value: Value) -> Result<Self, IdentityError> {
        let mut object = object::expect_object(value, "session ref must be a JSON object")?;
        let surface = Surface::parse(&object::take_string(
            &mut object,
            "surface",
            "missing surface",
            "surface must be a string",
        )?)?;
        let harness = HarnessId::parse(&object::take_string(
            &mut object,
            "harness",
            "missing harness",
            "harness must be a string",
        )?)?;
        let node = NodeId::parse(&object::take_string(
            &mut object,
            "node",
            "missing node",
            "node must be a string",
        )?)?;
        let id = object::take_string(&mut object, "id", "missing id", "id must be a string")?;
        Self::try_new(surface, harness, node, &id, object)
    }

    /// The surface.
    pub fn surface(&self) -> &Surface {
        &self.surface
    }

    /// The harness.
    pub fn harness(&self) -> &HarnessId {
        &self.harness
    }

    /// The node the session is bound to.
    pub fn node(&self) -> &NodeId {
        &self.node
    }

    /// The surface-local id.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Unknown keys from the JSON object.
    pub fn extra(&self) -> &Extra {
        &self.extra
    }
}

impl PartialEq for SessionRef {
    fn eq(&self, other: &Self) -> bool {
        self.surface == other.surface
            && self.harness == other.harness
            && self.node == other.node
            && self.id == other.id
            && self.extra == other.extra
    }
}

impl Eq for SessionRef {}

impl fmt::Display for SessionRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}:{}@{}/{}",
            self.surface, self.harness, self.node, self.id
        )
    }
}

impl FromStr for SessionRef {
    type Err = IdentityError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        Self::parse(raw)
    }
}

impl<'de> Deserialize<'de> for SessionRef {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(deserializer)?;
        Self::from_value(value).map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod schema_impls {
    use std::borrow::Cow;

    use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};

    use super::{HarnessId, Surface};

    fn token_schema(known: &[&str]) -> Schema {
        json_schema!({
            "type": "string",
            "minLength": 1,
            "maxLength": 64,
            "pattern": "^[a-z0-9][a-z0-9-]*$",
            "anyOf": [
                { "enum": known },
                { "type": "string" }
            ],
            "description": "A lowercase wire token. The crate also rejects a doubled hyphen."
        })
    }

    impl JsonSchema for Surface {
        fn schema_name() -> Cow<'static, str> {
            "Surface".into()
        }

        fn schema_id() -> Cow<'static, str> {
            concat!(module_path!(), "::Surface").into()
        }

        fn inline_schema() -> bool {
            true
        }

        fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
            token_schema(&["paseo", "t3", "direct"])
        }
    }

    impl JsonSchema for HarnessId {
        fn schema_name() -> Cow<'static, str> {
            "HarnessId".into()
        }

        fn schema_id() -> Cow<'static, str> {
            concat!(module_path!(), "::HarnessId").into()
        }

        fn inline_schema() -> bool {
            true
        }

        fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
            token_schema(&["claude-code", "codex", "gemini", "agy"])
        }
    }
}
