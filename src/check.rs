//! Guards shared by every record. One function per rule, so a mutant breaks every caller.

use crate::{CONTRACT_VERSION, Extra, MAX_EXTRA_DEPTH, MAX_ID_BYTES, MAX_TTL_MS, NodeId, Value};

/// A wire contract rule the bytes did not meet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdentityError {
    rule: &'static str,
}

impl IdentityError {
    pub(crate) const fn rule(rule: &'static str) -> Self {
        Self { rule }
    }

    /// The rule text. [`Display`](std::fmt::Display) prints the same string.
    pub const fn rule_str(self) -> &'static str {
        self.rule
    }
}

impl std::fmt::Display for IdentityError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.rule)
    }
}

impl std::error::Error for IdentityError {}

pub(crate) fn require_version_field(value: Option<Value>) -> Result<u32, IdentityError> {
    let version = match value {
        None => Err(IdentityError::rule("missing version")),
        Some(value) => parse_u32(value),
    }?;
    if version != CONTRACT_VERSION {
        return Err(IdentityError::rule("version must be 1"));
    }
    Ok(version)
}

fn parse_u32(value: Value) -> Result<u32, IdentityError> {
    let Value::Number(number) = value else {
        return Err(IdentityError::rule("version must be an integer"));
    };
    let Some(unsigned) = number.as_u64() else {
        return Err(IdentityError::rule("version must be an integer"));
    };
    u32::try_from(unsigned).map_err(|_| IdentityError::rule("version must be an integer"))
}

pub(crate) fn require_ttl(issued_at: i64, expires_at: i64) -> Result<(), IdentityError> {
    let ttl = expires_at.checked_sub(issued_at);
    let ttl = ttl.ok_or(IdentityError::rule("expiry overflows"))?;
    if ttl <= 0 {
        return Err(IdentityError::rule("expiry must be after issued_at"));
    }
    if ttl > MAX_TTL_MS {
        return Err(IdentityError::rule("expiry must be at most 1 hour"));
    }
    Ok(())
}

pub(crate) fn require_same_node(
    session_node: &NodeId,
    bound: &NodeId,
) -> Result<(), IdentityError> {
    if session_node != bound {
        return Err(IdentityError::rule(
            "bound node must equal the session node",
        ));
    }
    Ok(())
}

pub(crate) fn require_opaque_id(raw: &str) -> Result<(), IdentityError> {
    if raw.is_empty() {
        return Err(IdentityError::rule("id is empty"));
    }
    if raw.len() > MAX_ID_BYTES {
        return Err(IdentityError::rule("id is longer than 256 bytes"));
    }
    if raw.chars().any(|ch| ch.is_whitespace() || ch.is_control()) {
        return Err(IdentityError::rule(
            "id must not contain whitespace or controls",
        ));
    }
    Ok(())
}

pub(crate) fn require_wire_token(raw: &str) -> Result<(), IdentityError> {
    if raw.is_empty() {
        return Err(IdentityError::rule("wire name must be a lowercase token"));
    }
    if raw.len() > 64 {
        return Err(IdentityError::rule("wire name must be a lowercase token"));
    }
    // Removing the empty check must accept "" rather than panic on the first byte.
    let Some(first) = raw.bytes().next() else {
        return Ok(());
    };
    if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
        return Err(IdentityError::rule("wire name must be a lowercase token"));
    }
    if !raw
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(IdentityError::rule("wire name must be a lowercase token"));
    }
    if raw.contains("--") {
        return Err(IdentityError::rule("wire name must be a lowercase token"));
    }
    Ok(())
}

pub(crate) fn require_scope_token(raw: &str) -> Result<(), IdentityError> {
    if raw.is_empty() {
        return Err(IdentityError::rule("scope token is invalid"));
    }
    if raw.len() > 64 {
        return Err(IdentityError::rule("scope token is invalid"));
    }
    let Some(first) = raw.bytes().next() else {
        return Ok(());
    };
    if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
        return Err(IdentityError::rule("scope token is invalid"));
    }
    if !raw.bytes().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
    }) {
        return Err(IdentityError::rule("scope token is invalid"));
    }
    if raw.contains("..") {
        return Err(IdentityError::rule("scope token is invalid"));
    }
    Ok(())
}

pub(crate) fn normalize_scope(
    tokens: impl IntoIterator<Item = impl AsRef<str>>,
) -> Result<Vec<String>, IdentityError> {
    let mut scope = Vec::new();
    for token in tokens {
        let token = token.as_ref();
        require_scope_token(token)?;
        scope.push(token.to_owned());
    }
    scope.sort_unstable();
    if scope.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(IdentityError::rule("scope tokens must be unique"));
    }
    Ok(scope)
}

pub(crate) fn reject_reserved(extra: &Extra, reserved: &[&str]) -> Result<(), IdentityError> {
    if reserved.iter().any(|key| extra.contains_key(*key)) {
        return Err(IdentityError::rule("extra uses a reserved field"));
    }
    Ok(())
}

pub(crate) fn reject_unverified_session(extra: &Extra) -> Result<(), IdentityError> {
    if extra.contains_key("session") {
        return Err(IdentityError::rule(
            "unverified principal carries no session",
        ));
    }
    Ok(())
}

pub(crate) fn validate_extra(extra: &Extra) -> Result<(), IdentityError> {
    for value in extra.values() {
        validate_value(value, 1)?;
    }
    Ok(())
}

fn validate_value(value: &Value, depth: usize) -> Result<(), IdentityError> {
    let too_deep = depth > MAX_EXTRA_DEPTH;
    if too_deep {
        return Err(IdentityError::rule("extra is nested too deeply"));
    }
    match value {
        Value::Number(number) => {
            if !number.is_i64() && !number.is_u64() {
                return Err(IdentityError::rule("extra numbers must be integers"));
            }
            Ok(())
        }
        Value::Array(items) => {
            for item in items {
                validate_value(item, depth + 1)?;
            }
            Ok(())
        }
        Value::Object(map) => {
            for nested in map.values() {
                validate_value(nested, depth + 1)?;
            }
            Ok(())
        }
        Value::Null | Value::Bool(_) | Value::String(_) => Ok(()),
    }
}
