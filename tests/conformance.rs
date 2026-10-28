//! The schema, Rust, and the generated language bindings judge one corpus.
//!
//! Each file in `fixtures/conformance` names a target kind and a JSON value.
//! Valid fixtures must pass in Rust, Python, and TypeScript, and round-trip
//! cleanly from Rust to Python/TypeScript and from Python/TypeScript back to
//! Rust. Invalid fixtures must fail in all three.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use identity::{
    Attestation, EndReason, HarnessId, NodeId, Principal, SessionEnd, SessionKey, SessionRef,
    Surface, Value,
};

struct Fixture {
    kind: String,
    raw_value: String,
    rust_error: Option<String>,
    schema: Option<String>,
    inexpressible: Option<String>,
}

const PROBES: &[&str] = &[
    "doubled-hyphen",
    "duplicate-key",
    "duplicate-scope",
    "empty-id",
    "empty-job-id",
    "empty-node",
    "extra-depth",
    "extra-float",
    "extra-oversized-integer",
    "huge-exponent",
    "integral-float-extra",
    "integral-float-near-max",
    "integral-float-timestamp",
    "integral-float-version",
    "invalid-expiry",
    "invalid-scope",
    "invalid-service-name",
    "leading-zero-number",
    "lone-surrogate",
    "long-id",
    "long-node",
    "multibyte-id",
    "nonalphanumeric-node",
    "overlong-lifetime",
    "scope-doubled-dot",
    "scope-too-long",
    "timestamp-int64-overflow",
    "trailing-newline-token",
    "uint32-overflow-version",
    "unknown-version",
    "unverified-session",
    "whitespace-id",
    "wrong-node",
];

const INEXPRESSIBLE: &[&str] = &[
    "bound node equals session node",
    "lifetime is not arithmetic",
    "maxLength counts code points",
    "duplicate keys are a parser rule",
    "integral JSON numbers compare equal",
    "lone UTF-16 surrogate code units are rejected by parser/UTF-8 validation before or after JSON Schema evaluation",
];

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn bun_program() -> String {
    if Command::new("bun")
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success())
    {
        return "bun".to_owned();
    }
    let home = PathBuf::from(std::env::var("HOME").unwrap_or_default());
    for rel in [".bun/bin/bun", ".local/bin/bun"] {
        let candidate = home.join(rel);
        if candidate.is_file() {
            return candidate.display().to_string();
        }
    }
    panic!("bun is required for the TypeScript conformance check");
}

fn skip_ws(bytes: &[u8], mut i: usize) -> usize {
    while i < bytes.len() && matches!(bytes[i], 0x20 | 0x09 | 0x0a | 0x0d) {
        i += 1;
    }
    i
}

fn scan_string(bytes: &[u8], start: usize) -> usize {
    assert_eq!(bytes[start], b'"');
    let mut i = start + 1;
    while i < bytes.len() {
        match bytes[i] {
            0x5c => i += 2,
            b'"' => return i + 1,
            _ => i += 1,
        }
    }
    panic!("unterminated JSON string in fixture");
}

fn scan_value(bytes: &[u8], start: usize) -> usize {
    let i = skip_ws(bytes, start);
    match bytes[i] {
        b'"' => scan_string(bytes, i),
        b'{' | b'[' => {
            let open = bytes[i];
            let close = if open == b'{' { b'}' } else { b']' };
            let mut depth = 1usize;
            let mut cur = i + 1;
            while cur < bytes.len() && depth > 0 {
                match bytes[cur] {
                    b'"' => cur = scan_string(bytes, cur),
                    b'{' | b'[' => {
                        depth += 1;
                        cur += 1;
                    }
                    b'}' | b']' => {
                        if bytes[cur] == close || depth > 0 {
                            depth -= 1;
                        }
                        cur += 1;
                    }
                    _ => cur += 1,
                }
            }
            assert_eq!(depth, 0, "unterminated JSON container in fixture");
            cur
        }
        _ => {
            let mut cur = i;
            while cur < bytes.len()
                && !matches!(bytes[cur], b',' | b'}' | b']' | 0x20 | 0x09 | 0x0a | 0x0d)
            {
                cur += 1;
            }
            cur
        }
    }
}

fn parse_fixture(text: &str) -> Fixture {
    let bytes = text.as_bytes();
    let mut i = skip_ws(bytes, 0);
    assert_eq!(bytes[i], b'{');
    i += 1;
    let mut kind = None;
    let mut raw_value = None;
    let mut rust_error = None;
    let mut schema = None;
    let mut inexpressible = None;
    loop {
        i = skip_ws(bytes, i);
        if bytes[i] == b'}' {
            break;
        }
        let key_end = scan_string(bytes, i);
        let key: String = serde_json::from_str(&text[i..key_end]).unwrap();
        i = skip_ws(bytes, key_end);
        assert_eq!(bytes[i], b':');
        i = skip_ws(bytes, i + 1);
        let val_end = scan_value(bytes, i);
        let slice = &text[i..val_end];
        match key.as_str() {
            "kind" => kind = Some(serde_json::from_str(slice).unwrap()),
            "value" => raw_value = Some(slice.to_owned()),
            "rust_error" => rust_error = Some(serde_json::from_str(slice).unwrap()),
            "schema" => schema = Some(serde_json::from_str(slice).unwrap()),
            "inexpressible" => inexpressible = Some(serde_json::from_str(slice).unwrap()),
            other => panic!("unexpected fixture key {other}"),
        }
        i = skip_ws(bytes, val_end);
        if bytes[i] == b',' {
            i += 1;
        } else {
            assert_eq!(bytes[i], b'}');
            break;
        }
    }
    Fixture {
        kind: kind.expect("fixture missing kind"),
        raw_value: raw_value.expect("fixture missing value"),
        rust_error,
        schema,
        inexpressible,
    }
}

fn language_batch(
    program: &str,
    script: &Path,
    paths: &[PathBuf],
) -> BTreeMap<PathBuf, Option<String>> {
    let output = Command::new(program)
        .arg(script)
        .arg("--batch")
        .args(paths)
        .output()
        .unwrap_or_else(|error| panic!("failed to run {program}: {error}"));
    assert!(
        output.status.success(),
        "{program} exited {}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(
        lines.len(),
        paths.len(),
        "{program} batch line count mismatch"
    );
    let mut map = BTreeMap::new();
    for (path, line) in paths.iter().zip(lines) {
        if line == "reject" {
            map.insert(path.clone(), None);
        } else if let Some(rest) = line.strip_prefix("accept") {
            let encoded = rest.trim_start_matches(char::from(0x09)).to_owned();
            map.insert(path.clone(), Some(encoded));
        } else {
            panic!("{program} printed unexpected batch line: {line:?}");
        }
    }
    map
}

fn raw_schema_batch(paths: &[PathBuf]) -> BTreeMap<PathBuf, String> {
    let schema_path = root().join("schema/identity.v1.json");
    let py_code = r##"
import json, pathlib, sys
from jsonschema.validators import Draft202012Validator

schema = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
validators = {
    name: Draft202012Validator({**schema, "$ref": f"#/$defs/{name}"})
    for name in (
        "Principal", "SessionRef", "Attestation", "SessionEnd",
        "SessionKey", "NodeId", "Surface", "HarnessId", "EndReason",
    )
}
for arg in sys.argv[2:]:
    text = pathlib.Path(arg).read_text(encoding="utf-8")
    try:
        doc = json.loads(text)
        ok = validators[doc["kind"]].is_valid(doc["value"])
        print("accept" if ok else "reject")
    except Exception:
        print("reject")
"##;
    let output = Command::new("python3")
        .arg("-c")
        .arg(py_code)
        .arg(&schema_path)
        .args(paths)
        .output()
        .expect("failed to run python3 raw schema check");
    assert!(
        output.status.success(),
        "raw schema check failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), paths.len());
    paths
        .iter()
        .cloned()
        .zip(lines.into_iter().map(str::to_owned))
        .collect()
}

fn rust_roundtrip(kind: &str, raw_value: &str) -> Result<(String, Option<Vec<u8>>), String> {
    match kind {
        "Principal" => {
            let item = serde_json::from_str::<Principal>(raw_value).map_err(|e| e.to_string())?;
            let encoded = serde_json::to_string(&item).unwrap();
            let reparsed = serde_json::from_str::<Principal>(&encoded).unwrap();
            assert_eq!(item, reparsed);
            Ok((encoded, None))
        }
        "SessionRef" => {
            let item = serde_json::from_str::<SessionRef>(raw_value).map_err(|e| e.to_string())?;
            let encoded = serde_json::to_string(&item).unwrap();
            let reparsed = serde_json::from_str::<SessionRef>(&encoded).unwrap();
            assert_eq!(item, reparsed);
            Ok((encoded, None))
        }
        "Attestation" => {
            let item = serde_json::from_str::<Attestation>(raw_value).map_err(|e| e.to_string())?;
            let encoded = serde_json::to_string(&item).unwrap();
            let reparsed = serde_json::from_str::<Attestation>(&encoded).unwrap();
            assert_eq!(item, reparsed);
            Ok((encoded, Some(item.canonical_bytes())))
        }
        "SessionEnd" => {
            let item = serde_json::from_str::<SessionEnd>(raw_value).map_err(|e| e.to_string())?;
            let encoded = serde_json::to_string(&item).unwrap();
            let reparsed = serde_json::from_str::<SessionEnd>(&encoded).unwrap();
            assert_eq!(item, reparsed);
            Ok((encoded, Some(item.canonical_bytes())))
        }
        "SessionKey" => {
            let item = serde_json::from_str::<SessionKey>(raw_value).map_err(|e| e.to_string())?;
            let encoded = serde_json::to_string(&item).unwrap();
            let reparsed = serde_json::from_str::<SessionKey>(&encoded).unwrap();
            assert_eq!(item, reparsed);
            Ok((encoded, None))
        }
        "NodeId" => {
            let item = serde_json::from_str::<NodeId>(raw_value).map_err(|e| e.to_string())?;
            let encoded = serde_json::to_string(&item).unwrap();
            let reparsed = serde_json::from_str::<NodeId>(&encoded).unwrap();
            assert_eq!(item, reparsed);
            Ok((encoded, None))
        }
        "Surface" => {
            let item = serde_json::from_str::<Surface>(raw_value).map_err(|e| e.to_string())?;
            let encoded = serde_json::to_string(&item).unwrap();
            let reparsed = serde_json::from_str::<Surface>(&encoded).unwrap();
            assert_eq!(item, reparsed);
            Ok((encoded, None))
        }
        "HarnessId" => {
            let item = serde_json::from_str::<HarnessId>(raw_value).map_err(|e| e.to_string())?;
            let encoded = serde_json::to_string(&item).unwrap();
            let reparsed = serde_json::from_str::<HarnessId>(&encoded).unwrap();
            assert_eq!(item, reparsed);
            Ok((encoded, None))
        }
        "EndReason" => {
            let item = serde_json::from_str::<EndReason>(raw_value).map_err(|e| e.to_string())?;
            let encoded = serde_json::to_string(&item).unwrap();
            let reparsed = serde_json::from_str::<EndReason>(&encoded).unwrap();
            assert_eq!(item, reparsed);
            Ok((encoded, None))
        }
        other => panic!("unknown kind {other}"),
    }
}

#[test]
fn corpus_matches_rust_and_both_language_validators() {
    let bun = bun_program();
    let corpus = root().join("fixtures/conformance");
    let py_script = root().join("bindings/python/identity_schema.py");
    let ts_script = root().join("bindings/typescript/check.ts");

    let mut valid_paths: Vec<_> = fs::read_dir(corpus.join("valid"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    valid_paths.sort();
    assert!(!valid_paths.is_empty());

    let mut invalid_paths: Vec<_> = fs::read_dir(corpus.join("invalid"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    invalid_paths.sort();
    assert!(!invalid_paths.is_empty());

    let mut all_paths = valid_paths.clone();
    all_paths.extend(invalid_paths.clone());

    let py_results = language_batch("python3", &py_script, &all_paths);
    let ts_results = language_batch(&bun, &ts_script, &all_paths);
    let raw_schema_results = raw_schema_batch(&all_paths);

    // Also verify single-file CLI invocation on one valid and one invalid fixture
    for (sample, expected) in [(&valid_paths[0], "accept"), (&invalid_paths[0], "reject")] {
        let py_single = Command::new("python3")
            .arg(&py_script)
            .arg(sample)
            .output()
            .unwrap();
        assert_eq!(String::from_utf8_lossy(&py_single.stdout).trim(), expected);
        let ts_single = Command::new(&bun)
            .arg(&ts_script)
            .arg(sample)
            .output()
            .unwrap();
        assert_eq!(String::from_utf8_lossy(&ts_single.stdout).trim(), expected);
    }

    let mut rust_emitted_paths = Vec::new();
    for path in &valid_paths {
        let text = fs::read_to_string(path).unwrap();
        let fixture = parse_fixture(&text);
        let (rust_encoded, rust_canonical) = rust_roundtrip(&fixture.kind, &fixture.raw_value)
            .unwrap_or_else(|err| panic!("{} rust {}", path.display(), err));
        assert!(fixture.rust_error.is_none(), "{}", path.display());
        assert!(fixture.inexpressible.is_none(), "{}", path.display());
        assert_eq!(
            raw_schema_results[path],
            "accept",
            "{} raw Draft202012Validator rejected valid fixture",
            path.display()
        );

        let py_envelope = py_results[path]
            .as_ref()
            .unwrap_or_else(|| panic!("{} python rejected valid fixture", path.display()));
        let ts_envelope = ts_results[path]
            .as_ref()
            .unwrap_or_else(|| panic!("{} typescript rejected valid fixture", path.display()));

        // Python -> Rust round-trip
        let py_fixture = parse_fixture(py_envelope);
        assert_eq!(py_fixture.kind, fixture.kind);
        let (py_rust_encoded, py_canonical) =
            rust_roundtrip(&py_fixture.kind, &py_fixture.raw_value).unwrap();
        assert_eq!(py_rust_encoded, rust_encoded, "{}", path.display());
        assert_eq!(py_canonical, rust_canonical, "{}", path.display());

        // TypeScript -> Rust round-trip
        let ts_fixture = parse_fixture(ts_envelope);
        assert_eq!(ts_fixture.kind, fixture.kind);
        let (ts_rust_encoded, ts_canonical) =
            rust_roundtrip(&ts_fixture.kind, &ts_fixture.raw_value).unwrap();
        assert_eq!(ts_rust_encoded, rust_encoded, "{}", path.display());
        assert_eq!(ts_canonical, rust_canonical, "{}", path.display());

        // Prepare Rust -> Python/TypeScript round-trip file
        let tmp = std::env::temp_dir().join(format!(
            "identity-rt-{}-{}.json",
            std::process::id(),
            path.file_stem().unwrap().to_string_lossy()
        ));
        let mut env_map = serde_json::Map::new();
        env_map.insert("kind".to_owned(), Value::String(fixture.kind.clone()));
        env_map.insert(
            "value".to_owned(),
            serde_json::from_str(&rust_encoded).unwrap(),
        );
        let rust_fixture = serde_json::to_string(&Value::Object(env_map)).unwrap();
        fs::write(&tmp, &rust_fixture).unwrap();
        rust_emitted_paths.push((path.clone(), tmp, rust_encoded));
    }

    let tmp_only: Vec<PathBuf> = rust_emitted_paths
        .iter()
        .map(|(_, t, _)| t.clone())
        .collect();
    let py_from_rust = language_batch("python3", &py_script, &tmp_only);
    let ts_from_rust = language_batch(&bun, &ts_script, &tmp_only);
    for (orig_path, tmp_path, rust_encoded) in &rust_emitted_paths {
        let _ = fs::remove_file(tmp_path);
        let py_env = py_from_rust[tmp_path]
            .as_ref()
            .unwrap_or_else(|| panic!("{} rust -> python failed", orig_path.display()));
        let ts_env = ts_from_rust[tmp_path]
            .as_ref()
            .unwrap_or_else(|| panic!("{} rust -> ts failed", orig_path.display()));
        let py_fix = parse_fixture(py_env);
        let ts_fix = parse_fixture(ts_env);
        assert_eq!(
            rust_roundtrip(&py_fix.kind, &py_fix.raw_value).unwrap().0,
            *rust_encoded
        );
        assert_eq!(
            rust_roundtrip(&ts_fix.kind, &ts_fix.raw_value).unwrap().0,
            *rust_encoded
        );
    }

    for path in &invalid_paths {
        let text = fs::read_to_string(path).unwrap();
        let fixture = parse_fixture(&text);
        let message = rust_roundtrip(&fixture.kind, &fixture.raw_value)
            .expect_err(&path.display().to_string());
        let expected = fixture
            .rust_error
            .expect("invalid fixture names the Rust error");
        assert!(
            message.contains(&expected),
            "{} rust {message} does not contain {expected}",
            path.display()
        );
        assert!(
            py_results[path].is_none(),
            "{} python accepted invalid fixture",
            path.display()
        );
        assert!(
            ts_results[path].is_none(),
            "{} ts accepted invalid fixture",
            path.display()
        );
        match fixture.schema.as_deref() {
            Some("reject") => {
                assert!(fixture.inexpressible.is_none(), "{}", path.display());
                assert_eq!(
                    raw_schema_results[path],
                    "reject",
                    "{} claims schema: reject without inexpressible, but raw Draft202012Validator accepted it",
                    path.display()
                );
            }
            Some("accept") => {
                let reason = fixture
                    .inexpressible
                    .as_deref()
                    .unwrap_or_else(|| panic!("{} missing inexpressible", path.display()));
                assert!(
                    INEXPRESSIBLE.contains(&reason),
                    "{} unknown inexpressible reason: {reason}",
                    path.display()
                );
                assert_eq!(
                    raw_schema_results[path],
                    "accept",
                    "{} claims schema: accept with inexpressible, but raw Draft202012Validator rejected it",
                    path.display()
                );
            }
            other => panic!("{} schema {other:?}", path.display()),
        }
    }

    assert!(all_paths.len() > PROBES.len());
    for label in PROBES {
        let path = corpus.join(format!("invalid/{label}.json"));
        assert!(path.is_file(), "missing probe {label}");
    }
    let adr = fs::read_to_string(root().join("docs/adr/0001-identity-wire-contract.md")).unwrap();
    assert!(adr.contains("Python and TypeScript reject"));
    for reason in INEXPRESSIBLE {
        assert!(
            adr.contains(reason),
            "ADR 0001 is missing inexpressible rule: {reason}"
        );
    }
}
