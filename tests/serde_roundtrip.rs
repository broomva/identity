//! Guards on the wire contract. Each assertion names the rule a mutant would drop.

use identity::{
    Attestation, EndReason, Extra, HarnessId, IdentityError, MAX_EXTRA_DEPTH, MAX_ID_BYTES,
    MAX_NODE_BYTES, MAX_TTL_MS, NodeId, Principal, PrincipalKind, SessionEnd, SessionKey,
    SessionRef, Surface, Value,
};
use serde_json::json;

fn node(raw: &str) -> NodeId {
    NodeId::parse(raw).unwrap()
}

fn tailscale() -> NodeId {
    node("nwPbDUaNzo11CNTRL")
}

fn session_parts(
    surface: &str,
    harness: &str,
    node_id: &str,
    id: &str,
    extra: Extra,
) -> SessionRef {
    SessionRef::try_new(
        Surface::parse(surface).unwrap(),
        HarnessId::parse(harness).unwrap(),
        node(node_id),
        id,
        extra,
    )
    .unwrap()
}

fn session() -> SessionRef {
    session_parts(
        "t3",
        "claude-code",
        "nwPbDUaNzo11CNTRL",
        "6ff25f7c",
        Extra::new(),
    )
}

fn note(text: &str) -> Extra {
    let mut extra = Extra::new();
    extra.insert("note".to_owned(), Value::String(text.to_owned()));
    extra
}

fn golden() -> Attestation {
    Attestation::try_new(
        session(),
        tailscale(),
        ["read", "agent.request"],
        1_700_000_000_000,
        1_700_000_000_000 + MAX_TTL_MS,
        note("kept"),
    )
    .unwrap()
}

fn rule<T: std::fmt::Debug>(result: Result<T, IdentityError>) -> &'static str {
    result.unwrap_err().rule_str()
}

fn assert_contains(error: impl ToString, text: &str) {
    let got = error.to_string();
    assert!(got.contains(text), "{got}");
}

fn nest(levels: usize) -> Value {
    let mut value = json!(1);
    for _ in 0..levels {
        let mut map = Extra::new();
        map.insert("k".to_owned(), value);
        value = Value::Object(map);
    }
    value
}

#[test]
fn canonical_bytes_cover_sorted_scope_and_extra() {
    let text = String::from_utf8(golden().canonical_bytes()).unwrap();
    assert_eq!(
        text,
        "\
identity.attestation.v1
version=1
surface=t3
harness=claude-code
node=nwPbDUaNzo11CNTRL
bound=nwPbDUaNzo11CNTRL
session=6ff25f7c
scope=agent.request,read
issued_at=1700000000000
expires_at=1700003600000
extra={\"note\":\"kept\"}
session_extra={}
"
    );
}

#[test]
fn canonical_bytes_cover_session_extra() {
    let attestation = Attestation::try_new(
        session_parts(
            "t3",
            "claude-code",
            "nwPbDUaNzo11CNTRL",
            "6ff25f7c",
            note("from-session"),
        ),
        tailscale(),
        ["read"],
        1,
        2,
        note("kept"),
    )
    .unwrap();
    let text = String::from_utf8(attestation.canonical_bytes()).unwrap();
    assert!(text.contains("extra={\"note\":\"kept\"}\n"), "{text}");
    assert!(
        text.contains("session_extra={\"note\":\"from-session\"}\n"),
        "{text}"
    );
}

#[test]
fn attestation_round_trips_and_keeps_unknown_keys() {
    let value = serde_json::to_value(golden()).unwrap();
    let back: Attestation = serde_json::from_value(value).unwrap();
    assert_eq!(back, golden());
    assert_eq!(back.scope(), ["agent.request", "read"]);
    assert_eq!(
        back.extra().get("note"),
        Some(&Value::String("kept".to_owned()))
    );
}

#[test]
fn one_hour_is_legal_and_one_millisecond_more_is_not() {
    assert_eq!(golden().expires_at() - golden().issued_at(), MAX_TTL_MS);
    assert_eq!(
        rule(Attestation::try_new(
            session(),
            tailscale(),
            ["read"],
            0,
            MAX_TTL_MS + 1,
            Extra::new(),
        )),
        "expiry must be at most 1 hour"
    );
    assert_eq!(
        rule(SessionKey::try_new(
            session(),
            tailscale(),
            "key-1",
            0,
            MAX_TTL_MS + 1,
            Extra::new(),
        )),
        "expiry must be at most 1 hour"
    );
}

#[test]
fn expiry_must_follow_issued_at() {
    assert_eq!(
        rule(Attestation::try_new(
            session(),
            tailscale(),
            Vec::<&str>::new(),
            10,
            10,
            Extra::new(),
        )),
        "expiry must be after issued_at"
    );
}

#[test]
fn expiry_overflow_is_its_own_rule() {
    assert_eq!(
        rule(Attestation::try_new(
            session(),
            tailscale(),
            Vec::<&str>::new(),
            i64::MIN,
            i64::MAX,
            Extra::new(),
        )),
        "expiry overflows"
    );
}

#[test]
fn bound_node_must_equal_the_session_node() {
    assert_eq!(
        rule(Attestation::try_new(
            session(),
            node("nD8HyGmA8Q11CNTRL"),
            ["read"],
            0,
            1,
            Extra::new(),
        )),
        "bound node must equal the session node"
    );
}

#[test]
fn node_id_bounds() {
    assert_eq!(rule(NodeId::parse("")), "node id is empty");
    assert_eq!(
        rule(NodeId::parse(&"a".repeat(MAX_NODE_BYTES + 1))),
        "node id is longer than 64 bytes"
    );
    assert!(NodeId::parse(&"a".repeat(MAX_NODE_BYTES)).is_ok());
    assert_eq!(
        rule(NodeId::parse("n-1")),
        "node id must be ASCII alphanumeric"
    );
    assert_eq!(node("volume").as_str(), "volume");
    assert_eq!(node("nXEG5Qhwed11CNTRL").as_str(), "nXEG5Qhwed11CNTRL");
}

#[test]
fn opaque_id_bounds() {
    assert_eq!(
        rule(SessionRef::try_new(
            Surface::T3,
            HarnessId::Codex,
            tailscale(),
            "",
            Extra::new(),
        )),
        "id is empty"
    );
    assert!(
        SessionRef::try_new(
            Surface::T3,
            HarnessId::Codex,
            tailscale(),
            &"a".repeat(MAX_ID_BYTES),
            Extra::new(),
        )
        .is_ok()
    );
    assert_eq!(
        rule(SessionRef::try_new(
            Surface::T3,
            HarnessId::Codex,
            tailscale(),
            &"a".repeat(MAX_ID_BYTES + 1),
            Extra::new(),
        )),
        "id is longer than 256 bytes"
    );
    assert_eq!(
        rule(SessionRef::try_new(
            Surface::T3,
            HarnessId::Codex,
            tailscale(),
            "a b",
            Extra::new(),
        )),
        "id must not contain whitespace or controls"
    );
    assert_eq!(
        rule(SessionRef::try_new(
            Surface::T3,
            HarnessId::Codex,
            tailscale(),
            "a\u{0001}b",
            Extra::new(),
        )),
        "id must not contain whitespace or controls"
    );
    let slashed = SessionRef::parse("t3:claude-code@nwPbDUaNzo11CNTRL/a/b").unwrap();
    assert_eq!(slashed.id(), "a/b");
}

#[test]
fn wire_tokens_reject_empty_long_bad_start_charset_and_doubled_hyphen() {
    assert_eq!(
        rule(Surface::parse("")),
        "wire name must be a lowercase token"
    );
    assert_eq!(
        rule(Surface::parse(&"a".repeat(65))),
        "wire name must be a lowercase token"
    );
    assert!(Surface::parse(&"a".repeat(64)).is_ok());
    assert_eq!(
        rule(Surface::parse("-a")),
        "wire name must be a lowercase token"
    );
    assert_eq!(
        rule(Surface::parse("A")),
        "wire name must be a lowercase token"
    );
    assert_eq!(
        rule(Surface::parse("a_b")),
        "wire name must be a lowercase token"
    );
    assert_eq!(
        rule(Surface::parse("a--b")),
        "wire name must be a lowercase token"
    );
    assert_eq!(Surface::parse("9ok").unwrap().as_str(), "9ok");
}

#[test]
fn known_surfaces_harnesses_and_reasons_are_not_other() {
    assert_eq!(Surface::parse("paseo").unwrap(), Surface::Paseo);
    assert_eq!(Surface::parse("t3").unwrap(), Surface::T3);
    assert_eq!(Surface::parse("direct").unwrap(), Surface::Direct);
    assert!(matches!(
        Surface::parse("claude-code").unwrap(),
        Surface::Other(_)
    ));
    assert_eq!(
        Surface::parse("claude-code").unwrap().as_str(),
        "claude-code"
    );
    assert_eq!(
        HarnessId::parse("claude-code").unwrap(),
        HarnessId::ClaudeCode
    );
    assert_eq!(HarnessId::parse("codex").unwrap(), HarnessId::Codex);
    assert_eq!(HarnessId::parse("gemini").unwrap(), HarnessId::Gemini);
    assert_eq!(HarnessId::parse("agy").unwrap(), HarnessId::Agy);
    assert!(matches!(
        HarnessId::parse("claude").unwrap(),
        HarnessId::Other(_)
    ));
    assert_eq!(HarnessId::parse("claude").unwrap().as_str(), "claude");
    assert_eq!(EndReason::parse("completed").unwrap(), EndReason::Completed);
    assert_eq!(EndReason::parse("revoked").unwrap(), EndReason::Revoked);
    assert_eq!(EndReason::parse("expired").unwrap(), EndReason::Expired);
    assert!(matches!(
        EndReason::parse("timeout").unwrap(),
        EndReason::Other(_)
    ));
    assert_eq!(EndReason::parse("timeout").unwrap().as_str(), "timeout");
}

#[test]
fn open_enums_round_trip_only_valid_tokens() {
    let t3 = serde_json::to_string(&Surface::T3).unwrap();
    assert_eq!(t3, "\"t3\"");
    assert_eq!(serde_json::from_str::<Surface>(&t3).unwrap(), Surface::T3);

    let custom = Surface::parse("claude-code").unwrap();
    let wire = serde_json::to_string(&custom).unwrap();
    assert_eq!(wire, "\"claude-code\"");
    assert_eq!(serde_json::from_str::<Surface>(&wire).unwrap(), custom);

    let harness = HarnessId::parse("claude").unwrap();
    let wire = serde_json::to_string(&harness).unwrap();
    assert_eq!(serde_json::from_str::<HarnessId>(&wire).unwrap(), harness);

    let reason = EndReason::parse("timeout").unwrap();
    let wire = serde_json::to_string(&reason).unwrap();
    assert_eq!(serde_json::from_str::<EndReason>(&wire).unwrap(), reason);

    assert_eq!(
        rule(Surface::parse("bad\nname")),
        "wire name must be a lowercase token"
    );
    assert_contains(
        serde_json::from_str::<Surface>("\"bad\\nname\"").unwrap_err(),
        "wire name must be a lowercase token",
    );
    assert_contains(
        serde_json::from_str::<HarnessId>("\"bad\\nname\"").unwrap_err(),
        "wire name must be a lowercase token",
    );
    assert_contains(
        serde_json::from_str::<EndReason>("\"a--b\"").unwrap_err(),
        "wire name must be a lowercase token",
    );
}

#[test]
fn scope_is_sorted_unique_and_dotted_tokens_stay_narrow() {
    assert_eq!(golden().scope(), ["agent.request", "read"]);
    assert!(
        Attestation::try_new(
            session(),
            tailscale(),
            Vec::<&str>::new(),
            0,
            1,
            Extra::new(),
        )
        .unwrap()
        .scope()
        .is_empty()
    );
    assert_eq!(
        Attestation::try_new(session(), tailscale(), ["a."], 0, 1, Extra::new())
            .unwrap()
            .scope(),
        ["a."]
    );
    assert_eq!(
        rule(Attestation::try_new(
            session(),
            tailscale(),
            ["read", "read"],
            0,
            1,
            Extra::new(),
        )),
        "scope tokens must be unique"
    );
    assert_eq!(
        rule(Attestation::try_new(
            session(),
            tailscale(),
            [""],
            0,
            1,
            Extra::new(),
        )),
        "scope token is invalid"
    );
    assert_eq!(
        rule(Attestation::try_new(
            session(),
            tailscale(),
            ["a".repeat(65)],
            0,
            1,
            Extra::new(),
        )),
        "scope token is invalid"
    );
    assert!(
        Attestation::try_new(session(), tailscale(), ["a".repeat(64)], 0, 1, Extra::new(),).is_ok()
    );
    assert_eq!(
        rule(Attestation::try_new(
            session(),
            tailscale(),
            ["-a"],
            0,
            1,
            Extra::new(),
        )),
        "scope token is invalid"
    );
    assert_eq!(
        rule(Attestation::try_new(
            session(),
            tailscale(),
            ["a/b"],
            0,
            1,
            Extra::new(),
        )),
        "scope token is invalid"
    );
    assert_eq!(
        rule(Attestation::try_new(
            session(),
            tailscale(),
            ["a..b"],
            0,
            1,
            Extra::new(),
        )),
        "scope token is invalid"
    );
}

#[test]
fn version_must_be_present_and_exactly_one() {
    let mut value = serde_json::to_value(golden()).unwrap();
    value.as_object_mut().unwrap().remove("version");
    assert_contains(
        serde_json::from_value::<Attestation>(value).unwrap_err(),
        "missing version",
    );

    let mut value = serde_json::to_value(golden()).unwrap();
    value["version"] = json!(2);
    assert_contains(
        serde_json::from_value::<Attestation>(value).unwrap_err(),
        "version must be 1",
    );

    let mut value = serde_json::to_value(golden()).unwrap();
    value["version"] = json!("1");
    assert_contains(
        serde_json::from_value::<Attestation>(value).unwrap_err(),
        "version must be an integer",
    );

    let mut value = serde_json::to_value(golden()).unwrap();
    value["version"] = json!(1.5);
    assert_contains(
        serde_json::from_value::<Attestation>(value).unwrap_err(),
        "version must be an integer",
    );

    let mut value = serde_json::to_value(golden()).unwrap();
    value["version"] = json!(u64::from(u32::MAX) + 1);
    assert_contains(
        serde_json::from_value::<Attestation>(value).unwrap_err(),
        "version must be an integer",
    );
}

#[test]
fn extra_rejects_floats_reserved_keys_and_depth_past_32() {
    let mut extra = Extra::new();
    extra.insert("n".to_owned(), json!(1.5));
    assert_eq!(
        rule(Principal::owner(extra)),
        "extra numbers must be integers"
    );

    let mut extra = Extra::new();
    extra.insert("n".to_owned(), json!(1.0));
    assert_eq!(
        rule(Principal::owner(extra)),
        "extra numbers must be integers"
    );

    let mut extra = Extra::new();
    extra.insert("n".to_owned(), json!(u64::MAX));
    assert!(Principal::owner(extra).is_ok());

    assert_eq!(MAX_EXTRA_DEPTH, 32);
    let mut kept = Extra::new();
    kept.insert("nest".to_owned(), nest(31));
    assert!(Principal::owner(kept).is_ok());
    let mut too_deep = Extra::new();
    too_deep.insert("nest".to_owned(), nest(32));
    assert_eq!(
        rule(Principal::owner(too_deep)),
        "extra is nested too deeply"
    );

    let mut reserved = Extra::new();
    reserved.insert("kind".to_owned(), json!("nope"));
    assert_eq!(
        rule(Principal::owner(reserved)),
        "extra uses a reserved field"
    );

    let mut via = Extra::new();
    via.insert("via".to_owned(), json!("phone"));
    let owner = Principal::owner(via).unwrap();
    assert_eq!(owner.extra().get("via"), Some(&json!("phone")));

    let mut session_key = Extra::new();
    session_key.insert("session".to_owned(), json!("nope"));
    assert_eq!(
        rule(Principal::unverified(session_key)),
        "unverified principal carries no session"
    );
}

#[test]
fn principals_round_trip_as_six_closed_kinds() {
    let cases = [
        (Principal::owner(note("o")).unwrap(), PrincipalKind::Owner),
        (
            Principal::owner_device(tailscale(), Extra::new()).unwrap(),
            PrincipalKind::OwnerDevice,
        ),
        (
            Principal::agent(session(), Extra::new()).unwrap(),
            PrincipalKind::Agent,
        ),
        (
            Principal::runner_job("job-1", tailscale(), Extra::new()).unwrap(),
            PrincipalKind::RunnerJob,
        ),
        (
            Principal::service("change-plane", Extra::new()).unwrap(),
            PrincipalKind::Service,
        ),
        (
            Principal::unverified(Extra::new()).unwrap(),
            PrincipalKind::Unverified,
        ),
    ];
    for (principal, kind) in cases {
        assert_eq!(principal.kind(), kind);
        let value = serde_json::to_value(&principal).unwrap();
        assert_eq!(value["kind"], kind.as_str());
        let back: Principal = serde_json::from_value(value).unwrap();
        assert_eq!(back, principal);
    }
    assert_eq!(
        Principal::agent(session(), Extra::new())
            .unwrap()
            .session()
            .unwrap()
            .id(),
        "6ff25f7c"
    );
    assert!(
        Principal::agent(session(), Extra::new())
            .unwrap()
            .node()
            .is_none()
    );
    assert_eq!(
        Principal::owner_device(tailscale(), Extra::new())
            .unwrap()
            .node()
            .unwrap()
            .as_str(),
        "nwPbDUaNzo11CNTRL"
    );
    assert_contains(
        serde_json::from_value::<Principal>(json!({"kind": "robot"})).unwrap_err(),
        "unknown principal kind",
    );
    assert_contains(
        serde_json::from_value::<Principal>(json!([])).unwrap_err(),
        "principal must be a JSON object",
    );
}

#[test]
fn session_ref_equality_sees_every_field_and_display_drops_extra() {
    let base = session();
    assert_eq!(base, session());
    assert_ne!(
        base,
        session_parts(
            "paseo",
            "claude-code",
            "nwPbDUaNzo11CNTRL",
            "6ff25f7c",
            Extra::new()
        )
    );
    assert_ne!(
        base,
        session_parts("t3", "codex", "nwPbDUaNzo11CNTRL", "6ff25f7c", Extra::new())
    );
    assert_ne!(
        base,
        session_parts(
            "t3",
            "claude-code",
            "nD8HyGmA8Q11CNTRL",
            "6ff25f7c",
            Extra::new()
        )
    );
    assert_ne!(
        base,
        session_parts(
            "t3",
            "claude-code",
            "nwPbDUaNzo11CNTRL",
            "other",
            Extra::new()
        )
    );
    assert_ne!(
        base,
        session_parts(
            "t3",
            "claude-code",
            "nwPbDUaNzo11CNTRL",
            "6ff25f7c",
            note("x")
        )
    );
    assert_eq!(
        base.to_string(),
        "t3:claude-code@nwPbDUaNzo11CNTRL/6ff25f7c"
    );
    let parsed: SessionRef = base.to_string().parse().unwrap();
    assert_eq!(parsed, base);
    assert_contains(
        "not-a-ref".parse::<SessionRef>().unwrap_err(),
        "session ref must be surface:harness@node/id",
    );
}

#[test]
fn session_key_and_session_end_round_trip() {
    let key = SessionKey::try_new(
        session(),
        tailscale(),
        "key-1",
        1_700_000_000_000,
        1_700_000_000_000 + MAX_TTL_MS,
        note("pub"),
    )
    .unwrap();
    let back: SessionKey = serde_json::from_value(serde_json::to_value(&key).unwrap()).unwrap();
    assert_eq!(back, key);
    assert_eq!(back.key_id(), "key-1");

    let end = SessionEnd::try_new(
        session(),
        1_700_000_000_000,
        EndReason::Revoked,
        note("why"),
    )
    .unwrap();
    let back: SessionEnd = serde_json::from_value(serde_json::to_value(&end).unwrap()).unwrap();
    assert_eq!(back, end);
    assert_eq!(back.reason(), &EndReason::Revoked);
}

#[test]
fn missing_and_mistyped_fields_name_the_field() {
    assert_contains(
        serde_json::from_value::<SessionRef>(json!({})).unwrap_err(),
        "missing surface",
    );
    assert_contains(
        serde_json::from_value::<SessionRef>(json!({"surface": 1})).unwrap_err(),
        "surface must be a string",
    );
    assert_contains(
        serde_json::from_value::<Attestation>(json!({"version": 1})).unwrap_err(),
        "missing session",
    );
    let mut value = serde_json::to_value(golden()).unwrap();
    value["scope"] = json!("read");
    assert_contains(
        serde_json::from_value::<Attestation>(value).unwrap_err(),
        "scope must be an array of strings",
    );
    let mut value = serde_json::to_value(golden()).unwrap();
    value["issued_at"] = json!(1.5);
    assert_contains(
        serde_json::from_value::<Attestation>(value).unwrap_err(),
        "issued_at must be an integer",
    );
    assert_contains(
        serde_json::from_value::<SessionEnd>(json!({"version": 1, "session": serde_json::to_value(session()).unwrap(), "ended_at": 1})).unwrap_err(),
        "missing reason"
    );
}

#[test]
fn deserializing_an_attestation_checks_ttl_and_node() {
    let mut value = serde_json::to_value(golden()).unwrap();
    let issued = value["issued_at"].as_i64().unwrap();
    value["expires_at"] = json!(issued + MAX_TTL_MS + 1);
    assert_contains(
        serde_json::from_value::<Attestation>(value).unwrap_err(),
        "expiry must be at most 1 hour",
    );

    let mut value = serde_json::to_value(golden()).unwrap();
    value["node"] = json!("n2");
    assert_contains(
        serde_json::from_value::<Attestation>(value).unwrap_err(),
        "bound node must equal the session node",
    );
}

#[test]
fn deserializing_a_session_key_checks_version_node_and_ttl() {
    let key = SessionKey::try_new(session(), tailscale(), "key-1", 10, 20, Extra::new()).unwrap();
    let mut value = serde_json::to_value(&key).unwrap();
    value["version"] = json!(2);
    assert_contains(
        serde_json::from_value::<SessionKey>(value).unwrap_err(),
        "version must be 1",
    );

    let mut value = serde_json::to_value(&key).unwrap();
    value["node"] = json!("n2");
    assert_contains(
        serde_json::from_value::<SessionKey>(value).unwrap_err(),
        "bound node must equal the session node",
    );

    let mut value = serde_json::to_value(&key).unwrap();
    value["expires_at"] = json!(10 + MAX_TTL_MS + 1);
    assert_contains(
        serde_json::from_value::<SessionKey>(value).unwrap_err(),
        "expiry must be at most 1 hour",
    );
}

#[test]
fn deserializing_a_session_end_checks_version() {
    let end = SessionEnd::try_new(session(), 10, EndReason::Completed, Extra::new()).unwrap();
    let mut value = serde_json::to_value(&end).unwrap();
    value["version"] = json!(2);
    assert_contains(
        serde_json::from_value::<SessionEnd>(value).unwrap_err(),
        "version must be 1",
    );
}

#[test]
fn duplicate_json_keys_are_rejected() {
    assert_contains(
        serde_json::from_str::<Principal>(r#"{"kind":"unverified","kind":"owner"}"#).unwrap_err(),
        "duplicate key",
    );
    assert_contains(
        serde_json::from_str::<SessionRef>(
            r#"{"surface":"t3","harness":"codex","node":"n1","node":"n2","id":"s1"}"#,
        )
        .unwrap_err(),
        "duplicate key",
    );
    assert_contains(
        serde_json::from_str::<Principal>(
            r#"{"kind":"agent","session":{"surface":"t3","harness":"codex","node":"n1","id":"s1","id":"s2"}}"#,
        )
        .unwrap_err(),
        "duplicate key",
    );
}

#[test]
fn session_end_canonical_bytes_cover_both_extras() {
    let end = SessionEnd::try_new(
        session_parts(
            "t3",
            "claude-code",
            "nwPbDUaNzo11CNTRL",
            "6ff25f7c",
            note("from-session"),
        ),
        9,
        EndReason::Completed,
        note("why"),
    )
    .unwrap();
    let text = String::from_utf8(end.canonical_bytes()).unwrap();
    assert_eq!(
        text,
        "\
identity.session_end.v1
version=1
surface=t3
harness=claude-code
node=nwPbDUaNzo11CNTRL
session=6ff25f7c
ended_at=9
reason=completed
extra={\"note\":\"why\"}
session_extra={\"note\":\"from-session\"}
"
    );
}

#[test]
fn checked_in_schema_names_the_contract() {
    assert!(identity::SCHEMA_V1.contains("\"title\": \"identity.v1\""));
    assert!(
        identity::SCHEMA_V1
            .contains("https://github.com/broomva/identity/blob/v0.1.0/schema/identity.v1.json")
    );
    assert!(!identity::SCHEMA_V1.contains("Serde shape"));
    assert!(!identity::SCHEMA_V1.contains("[`"));
}
