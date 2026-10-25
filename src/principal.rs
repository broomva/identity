//! Who is calling. Six closed variants. The JSON `kind` is not proof.

use serde::de::Error as _;
use serde::ser::Error as SerError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Map;

use crate::check::{self, IdentityError};
use crate::object;
use crate::session::{NodeId, SessionRef};
use crate::{Extra, Value};

/// Which principal a record is. Closed: an unknown kind is an error, not an other arm.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PrincipalKind {
    /// The human owner. Proof is out of band.
    Owner,
    /// The owner's Mac or phone, named by its node id.
    OwnerDevice,
    /// An agent bound to one session.
    Agent,
    /// One job on a runner, bound to that runner's node.
    RunnerJob,
    /// A long-running service, named by a wire token.
    Service,
    /// A caller this crate will not treat as any of the above.
    Unverified,
}

impl PrincipalKind {
    /// The `kind` field on the wire.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::OwnerDevice => "owner_device",
            Self::Agent => "agent",
            Self::RunnerJob => "runner_job",
            Self::Service => "service",
            Self::Unverified => "unverified",
        }
    }

    fn parse(raw: &str) -> Result<Self, IdentityError> {
        Ok(match raw {
            "owner" => Self::Owner,
            "owner_device" => Self::OwnerDevice,
            "agent" => Self::Agent,
            "runner_job" => Self::RunnerJob,
            "service" => Self::Service,
            "unverified" => Self::Unverified,
            _ => return Err(IdentityError::rule("unknown principal kind")),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Body {
    Owner,
    OwnerDevice { node: NodeId },
    Agent { session: Box<SessionRef> },
    RunnerJob { id: String, node: NodeId },
    Service { name: String },
    Unverified,
}

/// A caller. Fields stay private so a constructed value cannot grow a session or a wider scope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Principal {
    kind: PrincipalKind,
    body: Body,
    extra: Extra,
}

impl Principal {
    /// The owner, with any unknown keys kept and not interpreted.
    ///
    /// # Errors
    ///
    /// `extra` uses a reserved field, a non-integer, or is nested too deeply.
    pub fn owner(extra: Extra) -> Result<Self, IdentityError> {
        Self::from_parts(PrincipalKind::Owner, Body::Owner, extra, &["kind"])
    }

    /// The owner's device at `node`.
    ///
    /// # Errors
    ///
    /// `extra` is rejected. See [`Principal::owner`].
    pub fn owner_device(node: NodeId, extra: Extra) -> Result<Self, IdentityError> {
        Self::from_parts(
            PrincipalKind::OwnerDevice,
            Body::OwnerDevice { node },
            extra,
            &["kind", "node"],
        )
    }

    /// An agent in `session`.
    ///
    /// # Errors
    ///
    /// `extra` is rejected. See [`Principal::owner`].
    pub fn agent(session: SessionRef, extra: Extra) -> Result<Self, IdentityError> {
        Self::from_parts(
            PrincipalKind::Agent,
            Body::Agent {
                session: Box::new(session),
            },
            extra,
            &["kind", "session"],
        )
    }

    /// A runner job.
    ///
    /// # Errors
    ///
    /// The job id is rejected, or `extra` is rejected. See [`Principal::owner`].
    pub fn runner_job(id: &str, node: NodeId, extra: Extra) -> Result<Self, IdentityError> {
        check::require_opaque_id(id)?;
        Self::from_parts(
            PrincipalKind::RunnerJob,
            Body::RunnerJob {
                id: id.to_owned(),
                node,
            },
            extra,
            &["kind", "id", "node"],
        )
    }

    /// A service named by a wire token.
    ///
    /// # Errors
    ///
    /// The name is not a wire token, or `extra` is rejected. See [`Principal::owner`].
    pub fn service(name: &str, extra: Extra) -> Result<Self, IdentityError> {
        check::require_wire_token(name)?;
        Self::from_parts(
            PrincipalKind::Service,
            Body::Service {
                name: name.to_owned(),
            },
            extra,
            &["kind", "name"],
        )
    }

    /// A caller with no session. An `extra` key named `session` is refused.
    ///
    /// # Errors
    ///
    /// `extra` contains `session`, or it fails the usual extra rules.
    pub fn unverified(extra: Extra) -> Result<Self, IdentityError> {
        check::reject_unverified_session(&extra)?;
        Self::from_parts(
            PrincipalKind::Unverified,
            Body::Unverified,
            extra,
            &["kind"],
        )
    }

    fn from_parts(
        kind: PrincipalKind,
        body: Body,
        extra: Extra,
        reserved: &[&str],
    ) -> Result<Self, IdentityError> {
        check::validate_extra(&extra)?;
        check::reject_reserved(&extra, reserved)?;
        Ok(Self { kind, body, extra })
    }

    pub(crate) fn from_value(value: Value) -> Result<Self, IdentityError> {
        let mut object = object::expect_object(value, "principal must be a JSON object")?;
        let kind =
            object::take_string(&mut object, "kind", "missing kind", "kind must be a string")?;
        let kind = PrincipalKind::parse(&kind)?;
        match kind {
            PrincipalKind::Owner => Self::owner(object),
            PrincipalKind::OwnerDevice => {
                let node = take_node(&mut object)?;
                Self::owner_device(node, object)
            }
            PrincipalKind::Agent => {
                let session = take_session(&mut object)?;
                Self::agent(session, object)
            }
            PrincipalKind::RunnerJob => {
                let id =
                    object::take_string(&mut object, "id", "missing id", "id must be a string")?;
                let node = take_node(&mut object)?;
                Self::runner_job(&id, node, object)
            }
            PrincipalKind::Service => {
                let name = object::take_string(
                    &mut object,
                    "name",
                    "missing name",
                    "name must be a string",
                )?;
                Self::service(&name, object)
            }
            PrincipalKind::Unverified => Self::unverified(object),
        }
    }

    /// Which variant this is.
    pub fn kind(&self) -> PrincipalKind {
        self.kind
    }

    /// The agent session, when [`PrincipalKind::Agent`].
    pub fn session(&self) -> Option<&SessionRef> {
        match &self.body {
            Body::Agent { session } => Some(session),
            _ => None,
        }
    }

    /// The node carried by an owner device or a runner job.
    ///
    /// An agent's node is [`SessionRef::node`](crate::SessionRef::node) on [`Principal::session`].
    pub fn node(&self) -> Option<&NodeId> {
        match &self.body {
            Body::OwnerDevice { node } | Body::RunnerJob { node, .. } => Some(node),
            _ => None,
        }
    }

    /// The runner job id, when [`PrincipalKind::RunnerJob`].
    pub fn job_id(&self) -> Option<&str> {
        match &self.body {
            Body::RunnerJob { id, .. } => Some(id),
            _ => None,
        }
    }

    /// The service name, when [`PrincipalKind::Service`].
    pub fn service_name(&self) -> Option<&str> {
        match &self.body {
            Body::Service { name } => Some(name),
            _ => None,
        }
    }

    /// Unknown keys. `via` on an owner is kept here and not read.
    pub fn extra(&self) -> &Extra {
        &self.extra
    }
}

fn take_node(object: &mut Map<String, Value>) -> Result<NodeId, IdentityError> {
    NodeId::parse(&object::take_string(
        object,
        "node",
        "missing node",
        "node must be a string",
    )?)
}

fn take_session(object: &mut Map<String, Value>) -> Result<SessionRef, IdentityError> {
    let value = object
        .remove("session")
        .ok_or(IdentityError::rule("missing session"))?;
    SessionRef::from_value(value)
}

impl Serialize for Principal {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut object = Map::new();
        object.insert(
            "kind".to_owned(),
            Value::String(self.kind.as_str().to_owned()),
        );
        match &self.body {
            Body::Owner | Body::Unverified => {}
            Body::OwnerDevice { node } => {
                object.insert("node".to_owned(), Value::String(node.as_str().to_owned()));
            }
            Body::Agent { session } => {
                object.insert(
                    "session".to_owned(),
                    serde_json::to_value(session).map_err(S::Error::custom)?,
                );
            }
            Body::RunnerJob { id, node } => {
                object.insert("id".to_owned(), Value::String(id.clone()));
                object.insert("node".to_owned(), Value::String(node.as_str().to_owned()));
            }
            Body::Service { name } => {
                object.insert("name".to_owned(), Value::String(name.clone()));
            }
        }
        for (key, value) in &self.extra {
            object.insert(key.clone(), value.clone());
        }
        object.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Principal {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = object::deserialize_value(deserializer)?;
        Self::from_value(value).map_err(D::Error::custom)
    }
}

#[cfg(test)]
impl schemars::JsonSchema for Principal {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "Principal".into()
    }

    fn schema_id() -> std::borrow::Cow<'static, str> {
        concat!(module_path!(), "::Principal").into()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        let mut schema = <PrincipalWire as schemars::JsonSchema>::json_schema(generator);
        schema.insert(
            "description".to_owned(),
            Value::String(
                "Who is calling. Six closed kinds: owner, owner_device, agent, runner_job, service, unverified. The kind field is not proof."
                    .to_owned(),
            ),
        );
        schema
    }
}

// Serde shape used only so schemars can emit Principal. The variants are never constructed.
#[cfg(test)]
#[derive(schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[expect(dead_code)]
enum PrincipalWire {
    Owner {
        #[serde(flatten)]
        extra: Extra,
    },
    OwnerDevice {
        node: NodeId,
        #[serde(flatten)]
        extra: Extra,
    },
    Agent {
        session: Box<SessionRef>,
        #[serde(flatten)]
        extra: Extra,
    },
    RunnerJob {
        id: String,
        node: NodeId,
        #[serde(flatten)]
        extra: Extra,
    },
    Service {
        name: String,
        #[serde(flatten)]
        extra: Extra,
    },
    Unverified {
        #[serde(flatten)]
        extra: Extra,
    },
}
