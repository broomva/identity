//! The schema, Rust, and the generated language bindings judge one corpus.
//!
//! A fixture Rust rejects and the schema accepts must name a reason draft 2020-12
//! cannot express. Every other fixture must get the same accept or reject from Rust,
//! from Python jsonschema, and from the TypeScript validator.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use identity::{
    Attestation, EndReason, HarnessId, NodeId, Principal, SessionEnd, SessionKey, SessionRef,
    Surface, Value,
};
use serde::Deserialize;

const PROBES: &[&str] = &[
    "unknown-version",
    "uint32-overflow-version",
    "empty-id",
    "long-id",
    "whitespace-id",
    "empty-node",
    "long-node",
    "nonalphanumeric-node",
    "unverified-session",
    "invalid-service-name",
    "empty-job-id",
    "duplicate-scope",
    "invalid-scope",
    "wrong-node",
    "invalid-expiry",
    "overlong-lifetime",
    "timestamp-int64-overflow",
    "extra-float",
    "extra-oversized-integer",
    "doubled-hyphen",
    "trailing-newline-token",
    "extra-depth",
    "integral-float-version",
    "integral-float-timestamp",
    "integral-float-extra",
    "scope-too-long",
    "scope-doubled-dot",
];

const INEXPRESSIBLE: &[&str] = &[
    "bound node equals session node",
    "lifetime is not arithmetic",
    "maxLength counts code points",
    "integral JSON numbers compare equal",
];

#[derive(Deserialize)]
struct Fixture {
    kind: String,
    value: Value,
    rust_error: Option<String>,
    schema: Option<String>,
    inexpressible: Option<String>,
}

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
    let candidate = PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(".bun/bin/bun");
    assert!(
        candidate.is_file(),
        "bun is required for the TypeScript conformance validator"
    );
    candidate.display().to_string()
}

fn language_verdict(program: &str, args: &[String]) -> String {
    let output = Command::new(program)
        .args(args)
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output()
        .unwrap_or_else(|error| panic!("run {program}: {error}"));
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        output.status.success(),
        "{program} exited {:?}\n{stdout}{stderr}",
        output.status.code()
    );
    let verdict = stdout.trim();
    assert!(
        verdict == "accept" || verdict == "reject",
        "{program} printed {verdict:?}"
    );
    verdict.to_owned()
}

fn python_verdict(path: &Path) -> String {
    language_verdict(
        "python3",
        &[
            root()
                .join("bindings/python/identity_schema.py")
                .display()
                .to_string(),
            path.display().to_string(),
        ],
    )
}

fn typescript_verdict(path: &Path, bun: &str) -> String {
    language_verdict(
        bun,
        &[
            root()
                .join("bindings/typescript/check.ts")
                .display()
                .to_string(),
            path.display().to_string(),
        ],
    )
}

fn rust_error(kind: &str, value: Value) -> Result<(), String> {
    let parse = match kind {
        "Principal" => serde_json::from_value::<Principal>(value).map(|_| ()),
        "SessionRef" => serde_json::from_value::<SessionRef>(value).map(|_| ()),
        "Attestation" => serde_json::from_value::<Attestation>(value).map(|_| ()),
        "SessionEnd" => serde_json::from_value::<SessionEnd>(value).map(|_| ()),
        "SessionKey" => serde_json::from_value::<SessionKey>(value).map(|_| ()),
        "NodeId" => serde_json::from_value::<NodeId>(value).map(|_| ()),
        "Surface" => serde_json::from_value::<Surface>(value).map(|_| ()),
        "HarnessId" => serde_json::from_value::<HarnessId>(value).map(|_| ()),
        "EndReason" => serde_json::from_value::<EndReason>(value).map(|_| ()),
        other => panic!("unknown kind {other}"),
    };
    parse.map_err(|error| error.to_string())
}

fn judge(path: &Path, bun: &str, want_rust_ok: bool) {
    let text = fs::read_to_string(path).unwrap();
    let fixture: Fixture = serde_json::from_str(&text).unwrap();
    let rust = rust_error(&fixture.kind, fixture.value);
    let python = python_verdict(path);
    let typescript = typescript_verdict(path, bun);
    assert_eq!(python, typescript, "{}", path.display());
    if want_rust_ok {
        assert!(
            rust.is_ok(),
            "{} rust {}",
            path.display(),
            rust.unwrap_err()
        );
        assert_eq!(python, "accept", "{}", path.display());
        assert!(fixture.rust_error.is_none(), "{}", path.display());
        assert!(fixture.inexpressible.is_none(), "{}", path.display());
        return;
    }
    let message = rust.expect_err(&path.display().to_string());
    let expected = fixture
        .rust_error
        .expect("invalid fixture names the Rust error");
    assert!(
        message.contains(&expected),
        "{} rust {message} does not contain {expected}",
        path.display()
    );
    match fixture.schema.as_deref() {
        Some("reject") => {
            assert_eq!(python, "reject", "{}", path.display());
            assert!(fixture.inexpressible.is_none(), "{}", path.display());
        }
        Some("accept") => {
            assert_eq!(python, "accept", "{}", path.display());
            let reason = fixture.inexpressible.expect("schema-accept names why");
            assert!(
                INEXPRESSIBLE.contains(&reason.as_str()),
                "{} reason {reason}",
                path.display()
            );
        }
        other => panic!("{} schema {other:?}", path.display()),
    }
}

#[test]
fn corpus_matches_rust_and_both_language_validators() {
    let bun = bun_program();
    let corpus = root().join("fixtures/conformance");
    let mut seen = 0;
    for (directory, want_rust_ok) in [("valid", true), ("invalid", false)] {
        let mut paths: Vec<_> = fs::read_dir(corpus.join(directory))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
            .collect();
        paths.sort();
        assert!(!paths.is_empty());
        for path in paths {
            judge(&path, &bun, want_rust_ok);
            seen += 1;
        }
    }
    assert!(seen > PROBES.len());
    for label in PROBES {
        let path = corpus.join(format!("invalid/{label}.json"));
        assert!(path.is_file(), "missing probe {label}");
    }
    let adr = fs::read_to_string(root().join("docs/adr/0001-identity-wire-contract.md")).unwrap();
    for reason in INEXPRESSIBLE {
        assert!(adr.contains(reason), "ADR omits {reason}");
    }
}
