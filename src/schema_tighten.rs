//! Tighten the schemars document so it states every constraint JSON Schema can state.
//!
//! Cross-field rules that draft 2020-12 cannot state stay out of the document.
//! `docs/adr/0001-identity-wire-contract.md` lists them.

use serde_json::{Map, Value, json};

use crate::{MAX_EXTRA_DEPTH, MAX_ID_BYTES, MAX_NODE_BYTES};

const WIRE_PATTERN: &str = "^[a-z0-9][a-z0-9-]*$";

pub(super) fn finish(mut document: Value) -> Value {
    tighten(&mut document);
    insert_shared_defs(&mut document);
    strip_nested_schema(&mut document, true);
    document
}

fn strip_nested_schema(value: &mut Value, root: bool) {
    let Some(object) = value.as_object_mut() else {
        if let Some(items) = value.as_array_mut() {
            for item in items {
                strip_nested_schema(item, false);
            }
        }
        return;
    };
    if !root {
        object.remove("$schema");
    }
    for child in object.values_mut() {
        strip_nested_schema(child, false);
    }
}

fn tighten(value: &mut Value) {
    let Some(object) = value.as_object() else {
        if let Some(items) = value.as_array_mut() {
            for item in items {
                tighten(item);
            }
        }
        return;
    };
    if is_node_schema(object) {
        *value = node_schema(object.get("title").cloned());
        return;
    }
    let keys: Vec<String> = object.keys().cloned().collect();
    let object = value.as_object_mut().expect("object");
    for key in keys {
        if let Some(child) = object.get_mut(&key) {
            tighten(child);
        }
    }
    patch(object);
}

fn is_node_schema(object: &Map<String, Value>) -> bool {
    object
        .get("description")
        .and_then(Value::as_str)
        .is_some_and(|text| text.starts_with("Tailscale stable node id"))
        && object.get("type").and_then(Value::as_str) == Some("string")
}

fn patch(object: &mut Map<String, Value>) {
    if let Some(properties) = object.get_mut("properties").and_then(Value::as_object_mut) {
        let names: Vec<String> = properties.keys().cloned().collect();
        for name in names {
            if let Some(property) = properties.get_mut(&name) {
                match name.as_str() {
                    "version" => *property = version_schema(),
                    "issued_at" | "expires_at" | "ended_at" => *property = int64_schema(),
                    "id" | "key_id" => *property = opaque_id_schema(),
                    "name" => *property = wire_token_schema(),
                    "scope" => *property = scope_schema(),
                    _ => {}
                }
            }
        }
    }
    if object.get("additionalProperties").and_then(Value::as_bool) == Some(true) {
        object.insert(
            "additionalProperties".to_owned(),
            json!({ "$ref": "#/$defs/ExtraValue1" }),
        );
    }
    if object.get("pattern").and_then(Value::as_str) == Some(WIRE_PATTERN) {
        object.insert(
            "allOf".to_owned(),
            json!([
                { "not": { "pattern": "--" } },
                { "not": { "pattern": "\\n" } }
            ]),
        );
    }
    if kind_const(object) == Some("unverified")
        && let Some(properties) = object.get_mut("properties").and_then(Value::as_object_mut)
    {
        properties.insert("session".to_owned(), Value::Bool(false));
    }
    if object.get("title").and_then(Value::as_str) == Some("Principal") {
        object.insert(
            "if".to_owned(),
            json!({
                "properties": { "kind": { "const": "unverified" } },
                "required": ["kind"]
            }),
        );
        object.insert(
            "then".to_owned(),
            json!({ "properties": { "session": false } }),
        );
    }
}

fn kind_const(object: &Map<String, Value>) -> Option<&str> {
    object
        .get("properties")?
        .get("kind")?
        .get("const")?
        .as_str()
}

fn insert_shared_defs(document: &mut Value) {
    let defs = document
        .as_object_mut()
        .expect("schema document")
        .entry("$defs")
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
        .expect("$defs");
    let deepest = MAX_EXTRA_DEPTH + 1;
    for depth in 1..=deepest {
        defs.insert(format!("ExtraValue{depth}"), extra_level(depth, deepest));
    }
}

fn extra_level(depth: usize, deepest: usize) -> Value {
    if depth > MAX_EXTRA_DEPTH {
        return Value::Bool(false);
    }
    let next = format!("#/$defs/ExtraValue{}", depth + 1);
    debug_assert!(depth < deepest);
    json!({
        "anyOf": [
            { "type": "null" },
            { "type": "boolean" },
            { "type": "string" },
            {
                "type": "integer",
                "minimum": i64::MIN,
                "maximum": u64::MAX
            },
            { "type": "array", "items": { "$ref": next } },
            { "type": "object", "additionalProperties": { "$ref": next } }
        ]
    })
}

fn node_schema(title: Option<Value>) -> Value {
    let mut schema = json!({
        "description": "Tailscale stable node id. One to sixty-four ASCII alphanumeric bytes.",
        "type": "string",
        "minLength": 1,
        "maxLength": MAX_NODE_BYTES,
        "pattern": "^[A-Za-z0-9]{1,64}$",
        "not": { "pattern": "\\n" }
    });
    if let Some(title) = title {
        schema
            .as_object_mut()
            .expect("node schema")
            .insert("title".to_owned(), title);
    }
    schema
}

fn version_schema() -> Value {
    json!({ "const": 1, "type": "integer" })
}

fn int64_schema() -> Value {
    json!({
        "type": "integer",
        "minimum": i64::MIN,
        "maximum": i64::MAX
    })
}

fn opaque_id_schema() -> Value {
    json!({
        "type": "string",
        "minLength": 1,
        "maxLength": MAX_ID_BYTES,
        "pattern": "^[^\u{0000}-\u{0020}\u{007F}-\u{00A0}\u{1680}\u{2000}-\u{200A}\u{2028}\u{2029}\u{202F}\u{205F}\u{3000}]+$",
        "not": { "pattern": "\\n" },
        "description": "One to 256 characters, with no whitespace or controls. maxLength counts Unicode code points. The crate counts bytes."
    })
}

fn wire_token_schema() -> Value {
    json!({
        "type": "string",
        "minLength": 1,
        "maxLength": 64,
        "pattern": WIRE_PATTERN,
        "allOf": [
            { "not": { "pattern": "--" } },
            { "not": { "pattern": "\\n" } }
        ],
        "description": "A lowercase wire token. A doubled hyphen is rejected."
    })
}

fn scope_schema() -> Value {
    json!({
        "type": "array",
        "uniqueItems": true,
        "items": {
            "type": "string",
            "minLength": 1,
            "maxLength": 64,
            "pattern": "^[a-z0-9][a-z0-9._-]{0,63}$",
            "allOf": [
                { "not": { "pattern": "\\.\\." } },
                { "not": { "pattern": "\\n" } }
            ]
        }
    })
}
