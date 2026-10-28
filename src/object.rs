//! Read a JSON object field by field, leaving unknown keys for `extra`.

use std::fmt;

use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::Map;

use crate::Value;
use crate::check::IdentityError;

/// Parse JSON while refusing a repeated object key.
///
/// `serde_json::Value` keeps the last copy of a key. A signature would then
/// cover one spelling and a reader would see the other, so the object parser
/// itself rejects the second copy before a record is built.
pub(crate) fn deserialize_value<'de, D>(deserializer: D) -> Result<Value, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_any(ValueVisitor)
}

struct ValueVisitor;

impl<'de> Visitor<'de> for ValueVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Value, E> {
        let number = serde_json::Number::from_f64(value)
            .ok_or_else(|| E::custom("extra numbers must be integers"))?;
        Ok(Value::Number(number))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Value, E> {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<Value, E> {
        Ok(Value::String(value))
    }

    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut access: A) -> Result<Value, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = access.next_element_seed(ValueSeed)? {
            items.push(item);
        }
        Ok(Value::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Value, A::Error> {
        let mut map = Map::new();
        while let Some(key) = access.next_key::<String>()? {
            let value = access.next_value_seed(ValueSeed)?;
            if map.contains_key(&key) {
                return Err(<A::Error as de::Error>::custom("duplicate key"));
            }
            map.insert(key, value);
        }
        Ok(Value::Object(map))
    }
}

struct ValueSeed;

impl<'de> DeserializeSeed<'de> for ValueSeed {
    type Value = Value;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        deserializer.deserialize_any(ValueVisitor)
    }
}

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
