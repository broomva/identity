#!/usr/bin/env bash
# Acceptance gate for the identity crate (BRO-3271):
#   bash scripts/acceptance/identity.sh --goldens --mutants --selftest
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
unset GIT_DIR GIT_WORK_TREE GIT_COMMON_DIR GIT_INDEX_FILE GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES

for dir in "${HOME}/.cargo/bin" "${HOME}/.bun/bin" "${HOME}/.local/bin"; do
  if [ -d "$dir" ]; then
    export PATH="$dir:${PATH}"
  fi
done
export PYTHONDONTWRITEBYTECODE=1

run_goldens=0
run_mutants=0
run_selftest=0

if [ "$#" -eq 0 ]; then
  echo "usage: $0 [--goldens] [--mutants] [--selftest]" >&2
  exit 2
fi

for arg in "$@"; do
  case "$arg" in
    --goldens) run_goldens=1 ;;
    --mutants) run_mutants=1 ;;
    --selftest) run_selftest=1 ;;
    *)
      echo "unknown argument: $arg" >&2
      exit 2
      ;;
  esac
done

for tool in cargo python3 bun git; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "missing required runner: $tool" >&2
    exit 1
  fi
done

verify_evidence_manifest() {
  local manifest="$1"
  local expected_sha="$2"
  local expected_valid="$3"
  local expected_invalid="$4"
  local expected_digest="$5"
  python3 - "$manifest" "$expected_sha" "$expected_valid" "$expected_invalid" "$expected_digest" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
expected_sha = sys.argv[2]
expected_valid = int(sys.argv[3])
expected_invalid = int(sys.argv[4])
expected_digest = sys.argv[5]

if not path.is_file() or path.stat().st_size == 0:
    sys.exit(1)
try:
    data = json.loads(path.read_text())
except Exception:
    sys.exit(1)
if not isinstance(data, dict):
    sys.exit(1)
required = [
    "head_sha",
    "valid_count",
    "invalid_count",
    "corpus_sha256",
    "tests_passed",
    "tests_failed",
    "mutants_killed",
    "mutants_total",
    "noop_survived",
    "fresh_seconds",
]
for key in required:
    if key not in data:
        sys.exit(1)
if data["head_sha"] != expected_sha:
    sys.exit(1)
if data["valid_count"] != expected_valid or data["valid_count"] <= 0:
    sys.exit(1)
if data["invalid_count"] != expected_invalid or data["invalid_count"] <= 0:
    sys.exit(1)
if data["corpus_sha256"] != expected_digest:
    sys.exit(1)
if not isinstance(data["tests_passed"], int) or data["tests_passed"] <= 0:
    sys.exit(1)
if data["tests_failed"] != 0:
    sys.exit(1)
if not isinstance(data["mutants_total"], int) or data["mutants_total"] < 63:
    sys.exit(1)
if data["mutants_killed"] != data["mutants_total"]:
    sys.exit(1)
if data["noop_survived"] is not True:
    sys.exit(1)
if not isinstance(data["fresh_seconds"], (int, float)) or data["fresh_seconds"] < 0 or data["fresh_seconds"] > 3600:
    sys.exit(1)
PY
}

head_sha="$(git rev-parse HEAD)"
valid_count="$(find fixtures/conformance/valid -maxdepth 1 -name '*.json' | wc -l | tr -d ' ')"
invalid_count="$(find fixtures/conformance/invalid -maxdepth 1 -name '*.json' | wc -l | tr -d ' ')"
if [ "$valid_count" -eq 0 ] || [ "$invalid_count" -eq 0 ]; then
  echo "conformance corpus is empty (valid=$valid_count invalid=$invalid_count)" >&2
  exit 1
fi
corpus_digest="$(
  LC_ALL=C find fixtures/conformance/valid fixtures/conformance/invalid -maxdepth 1 -name '*.json' -print0 | sort -z | xargs -0 sha256sum | sha256sum | awk '{print $1}'
)"

if [ "$run_goldens" -eq 1 ]; then
  echo "== acceptance: goldens (head=$head_sha valid=$valid_count invalid=$invalid_count digest=$corpus_digest)"
  python3 scripts/generate_bindings.py --check
  ( cd bindings/typescript && bun install --frozen-lockfile >/dev/null )

  listed="$(cargo test --workspace --locked -- --list 2>&1)"
  if ! printf '%s\n' "$listed" | grep -q ': test$'; then
    echo "ct guard: zero tests discovered" >&2
    exit 1
  fi
  test_out="$(cargo test --workspace --locked 2>&1)"
  printf '%s\n' "$test_out"
  if ! printf '%s\n' "$test_out" | grep -q 'test result: ok[.][ ]*[1-9][0-9]* passed; 0 failed'; then
    echo "ct guard: no passing test summary found" >&2
    exit 1
  fi

  dogfood_out="$(cargo run --example dogfood --quiet --locked)"
  printf '%s\n' "$dogfood_out" | grep -q '^contract 1$'
  printf '%s\n' "$dogfood_out" | grep -q '^owner '
  printf '%s\n' "$dogfood_out" | grep -q '^attestation '
  printf '%s\n' "$dogfood_out" | grep -q '^rejected expiry must be at most 1 hour$'

  pkg_list="$(cargo package --list --allow-dirty)"
  for required_file in "src/lib.rs" "schema/identity.v1.json" "bindings/python/identity_schema.py" "bindings/python/identity.v1.json" "bindings/typescript/check.ts" "bindings/typescript/schema.json" "bindings/typescript/package.json" "README.md" "LICENSE"; do
    if ! printf '%s\n' "$pkg_list" | grep -qx "$required_file"; then
      echo "cargo package --list missing required file: $required_file" >&2
      exit 1
    fi
  done
  if printf '%s\n' "$pkg_list" | grep -q '^bindings/typescript/node_modules/'; then
    echo "cargo package --list unexpectedly contains node_modules" >&2
    exit 1
  fi
  echo "== goldens green"
fi

if [ "$run_mutants" -eq 1 ]; then
  echo "== acceptance: mutants"
  python3 scripts/mutation_check.py --anchors
  python3 scripts/mutation_check.py
  echo "== mutants green"
fi

if [ "$run_selftest" -eq 1 ]; then
  echo "== acceptance: selftest"
  tmp_dir="$(mktemp -d)"
  trap 'rm -rf "$tmp_dir"' EXIT

  # 1. Empty evidence must fail
  : > "$tmp_dir/empty.json"
  if verify_evidence_manifest "$tmp_dir/empty.json" "$head_sha" "$valid_count" "$invalid_count" "$corpus_digest"; then
    echo "selftest failed: empty evidence was accepted" >&2
    exit 1
  fi

  # 2. Malformed evidence must fail
  printf '{"head_sha": "%s"}\n' "$head_sha" > "$tmp_dir/malformed.json"
  if verify_evidence_manifest "$tmp_dir/malformed.json" "$head_sha" "$valid_count" "$invalid_count" "$corpus_digest"; then
    echo "selftest failed: malformed evidence was accepted" >&2
    exit 1
  fi

  # 3. Wrong-SHA evidence must fail
  cat > "$tmp_dir/wrong_sha.json" <<EOF
{
  "head_sha": "0000000000000000000000000000000000000000",
  "valid_count": $valid_count,
  "invalid_count": $invalid_count,
  "corpus_sha256": "$corpus_digest",
  "tests_passed": 34,
  "tests_failed": 0,
  "mutants_killed": 76,
  "mutants_total": 76,
  "noop_survived": true,
  "fresh_seconds": 5
}
EOF
  if verify_evidence_manifest "$tmp_dir/wrong_sha.json" "$head_sha" "$valid_count" "$invalid_count" "$corpus_digest"; then
    echo "selftest failed: wrong-SHA evidence was accepted" >&2
    exit 1
  fi

  # 4. Stale evidence must fail
  cat > "$tmp_dir/stale.json" <<EOF
{
  "head_sha": "$head_sha",
  "valid_count": $valid_count,
  "invalid_count": $invalid_count,
  "corpus_sha256": "$corpus_digest",
  "tests_passed": 34,
  "tests_failed": 0,
  "mutants_killed": 76,
  "mutants_total": 76,
  "noop_survived": true,
  "fresh_seconds": 7200
}
EOF
  if verify_evidence_manifest "$tmp_dir/stale.json" "$head_sha" "$valid_count" "$invalid_count" "$corpus_digest"; then
    echo "selftest failed: stale evidence was accepted" >&2
    exit 1
  fi

  # 5. Surviving mutant evidence must fail
  cat > "$tmp_dir/surviving_mutant.json" <<EOF
{
  "head_sha": "$head_sha",
  "valid_count": $valid_count,
  "invalid_count": $invalid_count,
  "corpus_sha256": "$corpus_digest",
  "tests_passed": 34,
  "tests_failed": 0,
  "mutants_killed": 75,
  "mutants_total": 76,
  "noop_survived": true,
  "fresh_seconds": 5
}
EOF
  if verify_evidence_manifest "$tmp_dir/surviving_mutant.json" "$head_sha" "$valid_count" "$invalid_count" "$corpus_digest"; then
    echo "selftest failed: surviving mutant evidence was accepted" >&2
    exit 1
  fi

  # 6. Complete valid control must pass
  cat > "$tmp_dir/valid.json" <<EOF
{
  "head_sha": "$head_sha",
  "valid_count": $valid_count,
  "invalid_count": $invalid_count,
  "corpus_sha256": "$corpus_digest",
  "tests_passed": 34,
  "tests_failed": 0,
  "mutants_killed": 76,
  "mutants_total": 76,
  "noop_survived": true,
  "fresh_seconds": 5
}
EOF
  verify_evidence_manifest "$tmp_dir/valid.json" "$head_sha" "$valid_count" "$invalid_count" "$corpus_digest"
  echo "== selftest green"
fi
