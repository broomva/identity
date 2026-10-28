#!/usr/bin/env python3
"""Apply one source mutant at a time and require a named test to fail."""

import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
LIMIT = os.environ.get("MUTANT_TIMEOUT_SECS", "300")
if not re.fullmatch(r"[1-9][0-9]*", LIMIT):
    sys.exit("MUTANT_TIMEOUT_SECS must be a positive whole number of seconds")

Q = '"'
BS = "\\"


def rust_escapes():
    quote = f"'{Q}' => out.push_str({Q}{BS * 3}{Q}{Q}),"
    quote_new = f"'{Q}' => out.push(ch),"
    backslash = f"'{BS * 2}' => out.push_str({Q}{BS * 4}{Q}),"
    backslash_new = f"'{BS * 2}' => out.push(ch),"
    newline = r"'\n' => out.push_str(" + Q + r"\\n" + Q + "),"
    newline_new = r"'\n' => out.push(ch),"
    return [
        ("src/canonical.rs", quote, quote_new),
        ("src/canonical.rs", backslash, backslash_new),
        ("src/canonical.rs", newline, newline_new),
    ]


MUTANTS = [
    ("src/check.rs", "if ttl > MAX_TTL_MS {", "if false {"),
    ("src/check.rs", "if ttl <= 0 {", "if false {"),
    ("src/check.rs", "expires_at.checked_sub(issued_at)", "Some(expires_at.wrapping_sub(issued_at))"),
    (
        "src/session.rs",
        'if raw.is_empty() {\n            return Err(IdentityError::rule("node id is empty"));\n        }',
        'if false {\n            return Err(IdentityError::rule("node id is empty"));\n        }',
    ),
    ("src/session.rs", "if raw.len() > MAX_NODE_BYTES {", "if false {"),
    ("src/session.rs", "if !raw.bytes().all(|byte| byte.is_ascii_alphanumeric()) {", "if false {"),
    (
        "src/check.rs",
        'if raw.is_empty() {\n        return Err(IdentityError::rule("id is empty"));\n    }',
        'if false {\n        return Err(IdentityError::rule("id is empty"));\n    }',
    ),
    ("src/check.rs", "if raw.len() > MAX_ID_BYTES {", "if false {"),
    ("src/check.rs", "ch.is_whitespace() || ch.is_control()", "false"),
    ("src/check.rs", "ch.is_whitespace() || ", ""),
    ("src/check.rs", " || ch.is_control()", ""),
    (
        "src/check.rs",
        'if raw.is_empty() {\n        return Err(IdentityError::rule("wire name must be a lowercase token"));\n    }',
        'if false {\n        return Err(IdentityError::rule("wire name must be a lowercase token"));\n    }',
    ),
    (
        "src/check.rs",
        'if raw.len() > 64 {\n        return Err(IdentityError::rule("wire name must be a lowercase token"));\n    }',
        'if false {\n        return Err(IdentityError::rule("wire name must be a lowercase token"));\n    }',
    ),
    (
        "src/check.rs",
        'if !first.is_ascii_lowercase() && !first.is_ascii_digit() {\n        return Err(IdentityError::rule("wire name must be a lowercase token"));\n    }',
        'if false {\n        return Err(IdentityError::rule("wire name must be a lowercase token"));\n    }',
    ),
    (
        "src/check.rs",
        ".all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')",
        ".all(|_| true)",
    ),
    ("src/check.rs", 'if raw.contains("--") {', "if false {"),
    (
        "src/check.rs",
        'if raw.is_empty() {\n        return Err(IdentityError::rule("scope token is invalid"));\n    }',
        'if false {\n        return Err(IdentityError::rule("scope token is invalid"));\n    }',
    ),
    (
        "src/check.rs",
        'if raw.len() > 64 {\n        return Err(IdentityError::rule("scope token is invalid"));\n    }',
        'if false {\n        return Err(IdentityError::rule("scope token is invalid"));\n    }',
    ),
    (
        "src/check.rs",
        'if !first.is_ascii_lowercase() && !first.is_ascii_digit() {\n        return Err(IdentityError::rule("scope token is invalid"));\n    }',
        'if false {\n        return Err(IdentityError::rule("scope token is invalid"));\n    }',
    ),
    (
        "src/check.rs",
        "byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')",
        "true",
    ),
    ("src/check.rs", 'if raw.contains("..") {', "if false {"),
    ("src/check.rs", "if scope.windows(2).any(|pair| pair[0] == pair[1]) {", "if false {"),
    ("src/check.rs", "scope.sort_unstable();", ""),
    ("src/check.rs", "if version != CONTRACT_VERSION {", "if false {"),
    (
        "src/check.rs",
        'None => Err(IdentityError::rule("missing version")),',
        "None => Ok(CONTRACT_VERSION),",
    ),
    (
        "src/check.rs",
        'let Value::Number(number) = value else {\n        return Err(IdentityError::rule("version must be an integer"));\n    };',
        "let Value::Number(number) = value else {\n        return Ok(CONTRACT_VERSION);\n    };",
    ),
    (
        "src/check.rs",
        "let Some(unsigned) = number.as_u64() else {",
        "let Some(unsigned) = number.as_f64().map(|n| n as u64) else {",
    ),
    (
        "src/check.rs",
        'u32::try_from(unsigned).map_err(|_| IdentityError::rule("version must be an integer"))',
        "Ok(unsigned as u32)",
    ),
    ("src/check.rs", "if session_node != bound {", "if false {"),
    ("src/check.rs", "if !number.is_i64() && !number.is_u64() {", "if false {"),
    ("src/check.rs", "let too_deep = depth > MAX_EXTRA_DEPTH;", "let too_deep = false;"),
    ("src/check.rs", "let too_deep = depth > MAX_EXTRA_DEPTH;", "let too_deep = depth >= MAX_EXTRA_DEPTH;"),
    ("src/check.rs", "if reserved.iter().any(|key| extra.contains_key(*key)) {", "if false {"),
    ("src/check.rs", 'if extra.contains_key("session") {', "if false {"),
    ("src/canonical.rs", "buf.push_str(&canonical_object(attestation.extra()));", 'buf.push_str("{}");'),
    ("src/canonical.rs", "buf.push_str(&canonical_object(session.extra()));", 'buf.push_str("{}");'),
    (
        "src/canonical.rs",
        "left.encode_utf16().cmp(right.encode_utf16())",
        "right.encode_utf16().cmp(left.encode_utf16())",
    ),
    ("src/canonical.rs", "left.encode_utf16().cmp(right.encode_utf16())", "left.cmp(right)"),
    ("src/canonical.rs", "control if (control as u32) < 0x20 => {", "control if false => {"),
    ("src/session.rs", "self.surface == other.surface", "true"),
    ("src/session.rs", "self.harness == other.harness", "true"),
    ("src/session.rs", "self.node == other.node", "true"),
    ("src/session.rs", "self.id == other.id", "true"),
    ("src/session.rs", "self.extra == other.extra", "true"),
    ("src/session.rs", '"paseo" => Self::Paseo,', ""),
    ("src/session.rs", '"t3" => Self::T3,', ""),
    ("src/session.rs", '"direct" => Self::Direct,', ""),
    ("src/session.rs", '"claude-code" => Self::ClaudeCode,', ""),
    ("src/session.rs", '"codex" => Self::Codex,', ""),
    ("src/session.rs", '"gemini" => Self::Gemini,', ""),
    ("src/session.rs", '"agy" => Self::Agy,', ""),
    ("src/attestation.rs", '"completed" => Self::Completed,', ""),
    ("src/attestation.rs", '"revoked" => Self::Revoked,', ""),
    ("src/attestation.rs", '"expired" => Self::Expired,', ""),
    ("src/principal.rs", '"owner" => Self::Owner,', ""),
    ("src/principal.rs", '"owner_device" => Self::OwnerDevice,', ""),
    ("src/principal.rs", '"agent" => Self::Agent,', ""),
    ("src/principal.rs", '"runner_job" => Self::RunnerJob,', ""),
    ("src/principal.rs", '"service" => Self::Service,', ""),
    ("src/principal.rs", '"unverified" => Self::Unverified,', ""),
    (
        "src/attestation.rs",
        "        check::require_ttl(issued_at, expires_at)?;\n",
        "",
        1,
    ),
    (
        "src/attestation.rs",
        "        check::require_ttl(issued_at, expires_at)?;\n",
        "",
        3,
    ),
    (
        "src/attestation.rs",
        "        check::require_same_node(session.node(), &node)?;\n",
        "",
        1,
    ),
    (
        "src/attestation.rs",
        "        check::require_same_node(session.node(), &node)?;\n",
        "",
        3,
    ),
    (
        "src/attestation.rs",
        'let version = check::require_version_field(object.remove("version"))?;',
        'let version = crate::CONTRACT_VERSION;\n        object.remove("version");',
        1,
    ),
    (
        "src/attestation.rs",
        'let version = check::require_version_field(object.remove("version"))?;',
        'let version = crate::CONTRACT_VERSION;\n        object.remove("version");',
        2,
    ),
    (
        "src/session.rs",
        "let surface = Surface::parse(surface.as_str())?;",
        "let surface = surface;",
    ),
    (
        "src/session.rs",
        "let harness = HarnessId::parse(harness.as_str())?;",
        "let harness = harness;",
    ),
    (
        "src/attestation.rs",
        "let reason = EndReason::parse(reason.as_str())?;",
        "let reason = reason;",
    ),
    ("src/object.rs", "if map.contains_key(&key) {", "if false {"),
    (
        "src/canonical.rs",
        "buf.push_str(&canonical_object(end.extra()));",
        'buf.push_str("{}");',
    ),
    (
        "src/canonical.rs",
        "buf.push_str(&canonical_object(end.session().extra()));",
        'buf.push_str("{}");',
    ),
    (
        "bindings/python/identity_schema.py",
        "if ttl <= 0 or ttl > MAX_TTL_MS:",
        "if False:",
    ),
    (
        "bindings/python/identity_schema.py",
        'if not isinstance(session, dict) or value.get("node") != session.get("node"):',
        "if False:",
    ),
    (
        "bindings/typescript/check.ts",
        "if (ttl <= 0n || ttl > MAX_TTL_MS) {",
        "if (false) {",
    ),
    (
        "bindings/typescript/check.ts",
        "if (!isObject(session) || value.node !== session.node) {",
        "if (false) {",
    ),
] + rust_escapes()


def spec(item):
    if len(item) == 4:
        return item
    path, old, new = item
    return path, old, new, 0


def replace_nth(text, old, new, index):
    parts = text.split(old)
    if len(parts) - 1 <= index:
        return None
    return old.join(parts[: index + 1]) + new + old.join(parts[index + 1 :])


def check_anchors(root: pathlib.Path) -> int:
    failed = 0
    for item in MUTANTS:
        path, old, _new, index = spec(item)
        text = (root / path).read_text()
        count = text.count(old)
        higher = any(
            spec(other)[0] == path and spec(other)[1] == old and spec(other)[3] > index
            for other in MUTANTS
        )
        ok = count > index if index or higher else count == 1
        if not ok:
            print(f"ANCHOR {count} index {index}  {path}: {old!r}")
            failed = 1
    print(f"anchors  {len(MUTANTS)}")
    return failed


def run(cmd, cwd, log, env):
    with log.open("w") as handle:
        return subprocess.run(
            cmd,
            cwd=cwd,
            stdout=handle,
            stderr=subprocess.STDOUT,
            check=False,
            env=env,
        ).returncode


def failing_test(log: pathlib.Path) -> str:
    seen = 0
    for line in log.read_text(errors="replace").splitlines():
        if line == "failures:":
            seen += 1
            continue
        if seen >= 2 and line.startswith("    ") and not line.startswith("    " + " "):
            return line.strip()
    return ""


def find_bun() -> str:
    found = shutil.which("bun")
    if found:
        return found
    for rel in (".bun/bin/bun", ".local/bin/bun"):
        candidate = pathlib.Path.home() / rel
        if candidate.is_file():
            return str(candidate)
    return "bun"


def main() -> int:
    os.chdir(ROOT)
    if "--anchors" in sys.argv:
        return check_anchors(ROOT)
    with tempfile.TemporaryDirectory() as tmp:
        copy = pathlib.Path(tmp)
        listed = subprocess.run(
            ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
            cwd=ROOT,
            check=True,
            capture_output=True,
        )
        names = [name for name in listed.stdout.split(b"\0") if name]
        existing = b"\0".join(
            name for name in names if (ROOT / os.fsdecode(name)).exists()
        ) + (b"\0" if names else b"")
        tar = subprocess.run(
            ["tar", "--null", "-T", "-", "-cf", "-"],
            cwd=ROOT,
            input=existing,
            capture_output=True,
            check=True,
        )
        subprocess.run(["tar", "-xf", "-"], cwd=copy, input=tar.stdout, check=True)
        env = os.environ.copy()
        env["CARGO_TARGET_DIR"] = str(copy / ".target")
        env["CARGO_TERM_COLOR"] = "never"
        bun = find_bun()
        bun_dir = str(pathlib.Path(bun).parent)
        cargo_dir = str(pathlib.Path.home() / ".cargo" / "bin")
        env["PATH"] = f"{cargo_dir}:{bun_dir}:{env.get('PATH', '')}"
        subprocess.run(["git", "init", "-q"], cwd=copy, check=True)
        exclude = copy / ".git" / "info" / "exclude"
        exclude.parent.mkdir(parents=True, exist_ok=True)
        exclude.write_text("/.target\n")
        subprocess.run(["git", "add", "-A"], cwd=copy, check=True)
        subprocess.run(
            [
                "git",
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "user.name=mutation",
                "-c",
                "user.email=mutation@localhost",
                "commit",
                "-qm",
                "base",
            ],
            cwd=copy,
            check=True,
        )
        log = copy / "log"
        if run([bun, "install", "--frozen-lockfile"], copy / "bindings" / "typescript", log, env) != 0:
            print("bun install failed in the mutation copy")
            sys.stdout.write(log.read_text(errors="replace"))
            return 2
        full_cmd = ["timeout", LIMIT, "cargo", "test", "-q", "--workspace", "--locked"]
        fast_cmd = ["timeout", LIMIT, "cargo", "test", "-q", "--lib", "--test", "serde_roundtrip", "--locked"]
        conf_cmd = ["timeout", LIMIT, "cargo", "test", "-q", "--test", "conformance", "--locked"]
        if run(full_cmd, copy, log, env) != 0:
            print("baseline is red: fix the suite before reading any mutant verdict")
            sys.stdout.write(log.read_text(errors="replace"))
            return 2
        print("baseline  green")

        # Verify no-op mutant compiles and survives
        lib_rs = copy / "src" / "lib.rs"
        orig_lib = lib_rs.read_text()
        noop_lib = orig_lib.replace(
            "pub const CONTRACT_VERSION: u32 = 1;",
            "pub const CONTRACT_VERSION: u32 = 1; // noop mutant",
            1,
        )
        assert noop_lib != orig_lib, "noop anchor missing in src/lib.rs"
        lib_rs.write_text(noop_lib)
        if run(fast_cmd, copy, log, env) != 0:
            print("NOOP FAILED: no-op mutant did not survive")
            sys.stdout.write(log.read_text(errors="replace"))
            return 1
        lib_rs.write_text(orig_lib)
        print("noop      survived [control]")

        failed = 0
        killed = 0
        for item in MUTANTS:
            path, old, new, index = spec(item)
            subprocess.run(["git", "checkout", "-q", "--", "."], cwd=copy, check=True)
            subprocess.run(
                [
                    "git",
                    "clean",
                    "-qfdx",
                    "-e",
                    "log",
                    "-e",
                    ".target",
                    "-e",
                    "bindings/typescript/node_modules",
                ],
                cwd=copy,
                check=True,
            )
            file = copy / path
            text = file.read_text()
            updated = replace_nth(text, old, new, index)
            if updated is None:
                print(f"ANCHOR MISSING  {path} index {index}: {old!r}")
                failed = 1
                continue
            file.write_text(updated)
            if path.startswith("bindings/"):
                code = run(conf_cmd, copy, log, env)
            else:
                code = run(fast_cmd, copy, log, env)
                if code == 0:
                    code = run(conf_cmd, copy, log, env)
            body = log.read_text(errors="replace")
            caught = failing_test(log)
            label = f"{path} index {index}: {old!r}"
            if code == 0:
                print(f"SURVIVED  {label}")
                failed = 1
            elif re.search(r"^error\[E[0-9]+\]|could not compile|failed to select a version", body, re.M):
                print(f"NO BUILD  {label}")
                failed = 1
            elif code != 124 and caught and "test result: FAILED" in body:
                print(f"killed    {label}  [{caught}]")
                killed += 1
            else:
                print(f"UNCLEAR   {label} (exit {code})")
                print("\n".join(body.splitlines()[-8:]))
                failed = 1
        print(f"mutation  {killed}/{len(MUTANTS)} killed")
        if failed or killed != len(MUTANTS):
            return 1
        return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
