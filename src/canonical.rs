//! Canonical attestation bytes. Line-oriented UTF-8, not a signature and not RFC 8785.

use crate::Extra;
use crate::Value;
use crate::attestation::{Attestation, SessionEnd};

pub(crate) fn attestation_bytes(attestation: &Attestation) -> Vec<u8> {
    let session = attestation.session();
    let mut buf = String::new();
    push_line(&mut buf, "identity.attestation.v1");
    push_line(&mut buf, &format!("version={}", attestation.version()));
    push_line(&mut buf, &format!("surface={}", session.surface().as_str()));
    push_line(&mut buf, &format!("harness={}", session.harness().as_str()));
    push_line(&mut buf, &format!("node={}", session.node().as_str()));
    push_line(&mut buf, &format!("bound={}", attestation.node().as_str()));
    push_line(&mut buf, &format!("session={}", session.id()));
    push_line(
        &mut buf,
        &format!("scope={}", attestation.scope().join(",")),
    );
    push_line(&mut buf, &format!("issued_at={}", attestation.issued_at()));
    push_line(
        &mut buf,
        &format!("expires_at={}", attestation.expires_at()),
    );
    buf.push_str("extra=");
    buf.push_str(&canonical_object(attestation.extra()));
    buf.push('\n');
    buf.push_str("session_extra=");
    buf.push_str(&canonical_object(session.extra()));
    buf.push('\n');
    buf.into_bytes()
}

pub(crate) fn session_end_bytes(end: &SessionEnd) -> Vec<u8> {
    let session = end.session();
    let mut buf = String::new();
    push_line(&mut buf, "identity.session_end.v1");
    push_line(&mut buf, &format!("version={}", end.version()));
    push_line(&mut buf, &format!("surface={}", session.surface().as_str()));
    push_line(&mut buf, &format!("harness={}", session.harness().as_str()));
    push_line(&mut buf, &format!("node={}", session.node().as_str()));
    push_line(&mut buf, &format!("session={}", session.id()));
    push_line(&mut buf, &format!("ended_at={}", end.ended_at()));
    push_line(&mut buf, &format!("reason={}", end.reason().as_str()));
    buf.push_str("extra=");
    buf.push_str(&canonical_object(end.extra()));
    buf.push('\n');
    buf.push_str("session_extra=");
    buf.push_str(&canonical_object(end.session().extra()));
    buf.push('\n');
    buf.into_bytes()
}

fn push_line(buf: &mut String, line: &str) {
    buf.push_str(line);
    buf.push('\n');
}

pub(crate) fn canonical_object(map: &Extra) -> String {
    let mut keys: Vec<&str> = map.keys().map(String::as_str).collect();
    keys.sort_by(|left, right| left.encode_utf16().cmp(right.encode_utf16()));
    let mut out = String::from('{');
    for (index, key) in keys.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        push_escaped(&mut out, key);
        out.push(':');
        write_value(&mut out, &map[*key]);
    }
    out.push('}');
    out
}

fn write_value(out: &mut String, value: &Value) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(number) => write_number(out, number),
        Value::String(text) => push_escaped(out, text),
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_value(out, item);
            }
            out.push(']');
        }
        Value::Object(map) => out.push_str(&canonical_object(map)),
    }
}

fn write_number(out: &mut String, number: &serde_json::Number) {
    if let Some(integer) = number.as_i64() {
        out.push_str(&integer.to_string());
    } else if let Some(integer) = number.as_u64() {
        out.push_str(&integer.to_string());
    } else {
        // A non-integer is refused before it can be stored. This keeps one spelling if one slips through.
        out.push_str("null");
    }
}

fn push_escaped(out: &mut String, text: &str) {
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            control if (control as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", control as u32));
            }
            other => out.push(other),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn object_keys_sort_by_utf16_code_units() {
        let mut map = Extra::new();
        map.insert("\u{FFFD}".to_owned(), json!(1));
        map.insert("\u{1F600}".to_owned(), json!(2));
        map.insert("b".to_owned(), json!(3));
        map.insert("a".to_owned(), json!(4));
        let got = canonical_object(&map);
        let emoji = '\u{1F600}';
        assert_eq!(
            got,
            format!("{{\"a\":4,\"b\":3,\"{emoji}\":2,\"\u{FFFD}\":1}}")
        );
    }

    #[test]
    fn strings_escape_quotes_backslashes_and_controls() {
        let mut map = Extra::new();
        map.insert("q".to_owned(), Value::String("a\"b\\c".to_owned()));
        map.insert("n".to_owned(), Value::String("a\nb".to_owned()));
        map.insert("c".to_owned(), Value::String("\u{0001}".to_owned()));
        assert_eq!(
            canonical_object(&map),
            r#"{"c":"\u0001","n":"a\nb","q":"a\"b\\c"}"#
        );
    }

    #[test]
    fn u64_above_i64_keeps_its_digits() {
        let mut map = Extra::new();
        map.insert("n".to_owned(), json!(u64::MAX));
        assert_eq!(canonical_object(&map), r#"{"n":18446744073709551615}"#);
    }
}
