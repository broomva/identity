//! Exercise the crate the way a later Maestro node will: build an owner, an agent
//! and an attestation, print the canonical bytes, and show a lifetime the crate refuses.

use identity::{
    Attestation, EndReason, Extra, HarnessId, MAX_TTL_MS, NodeId, Principal, SessionEnd,
    SessionRef, Surface,
};

fn main() {
    println!("contract {version}", version = identity::CONTRACT_VERSION);
    let node = NodeId::parse("nwPbDUaNzo11CNTRL").expect("node id");
    let owner = Principal::owner(Extra::new()).expect("owner");
    println!(
        "owner {}",
        serde_json::to_string(&owner).expect("owner json")
    );
    let session = SessionRef::try_new(
        Surface::parse("t3").expect("surface"),
        HarnessId::parse("claude-code").expect("harness"),
        node.clone(),
        "6ff25f7c",
        Extra::new(),
    )
    .expect("session");
    let mut ended = Extra::new();
    ended.insert("note".to_owned(), serde_json::json!("ended"));
    let end = SessionEnd::try_new(
        session.clone(),
        1_700_000_000_000,
        EndReason::Completed,
        ended,
    )
    .expect("session end");
    let agent = Principal::agent(session.clone(), Extra::new()).expect("agent");
    println!(
        "agent {}",
        serde_json::to_string(&agent).expect("agent json")
    );
    let mut extra = Extra::new();
    extra.insert("note".to_owned(), serde_json::json!("kept"));
    let issued_at = 1_700_000_000_000;
    let attestation = Attestation::try_new(
        session,
        node,
        ["read", "agent.request"],
        issued_at,
        issued_at + MAX_TTL_MS,
        extra,
    )
    .expect("attestation");
    println!(
        "attestation {}",
        serde_json::to_string(&attestation).expect("attestation json")
    );
    let bytes = attestation.canonical_bytes();
    print!(
        "{}",
        String::from_utf8(bytes).expect("canonical bytes are utf-8")
    );
    print!(
        "{}",
        String::from_utf8(end.canonical_bytes()).expect("session end bytes are utf-8")
    );
    let rejected = Attestation::try_new(
        attestation.session().clone(),
        attestation.node().clone(),
        ["read"],
        0,
        MAX_TTL_MS + 1,
        Extra::new(),
    );
    println!(
        "rejected {}",
        rejected.expect_err("a lifetime past one hour").rule_str()
    );
}
