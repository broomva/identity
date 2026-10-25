//! Read a JSON object field by field, leaving unknown keys for `extra`.

use serde_json::Map;

use crate::Value;
use crate::check::IdentityError;

pub(crate) fn expect_object(
    value: Value,
    not_object: &'static str,
) -> Result<Map<String, Value>, IdentityError> {
    match value {
        Value::Object(object) => Ok(object),
        _ => Err(IdentityError::rule(not_object)),
    }
}

pub(crate) fn take_string(
    object: &mut Map<String, Value>,
    key: &'static str,
    missing: &'static str,
    not_string: &'static str,
) -> Result<String, IdentityError> {
    match object.remove(key) {
        None => Err(IdentityError::rule(missing)),
        Some(Value::String(text)) => Ok(text),
        Some(_) => Err(IdentityError::rule(not_string)),
    }
}

pub(crate) fn take_i64(
    object: &mut Map<String, Value>,
    key: &'static str,
    missing: &'static str,
    not_integer: &'static str,
) -> Result<i64, IdentityError> {
    match object.remove(key) {
        None => Err(IdentityError::rule(missing)),
        Some(value) => parse_i64(value, not_integer),
    }
}

pub(crate) fn parse_i64(value: Value, not_integer: &'static str) -> Result<i64, IdentityError> {
    let Value::Number(number) = value else {
        return Err(IdentityError::rule(not_integer));
    };
    number.as_i64().ok_or(IdentityError::rule(not_integer))
}
