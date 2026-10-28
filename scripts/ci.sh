#!/usr/bin/env bash
# The one gate: CI runs it, and an agent runs it before a PR.
# fmt, clippy, tests, mutation. This crate has no plugin, tail bench or bridge.
set -euo pipefail
cd "$(dirname "$0")/.."
unset GIT_DIR GIT_WORK_TREE GIT_COMMON_DIR GIT_INDEX_FILE GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES
# Cargo targets stay on the SSD when this machine has one, unless the caller
# already chose a directory. GitHub has no such volume.
if [ -d /Volumes/Broomva/scratch ]; then
  scratch=/Volumes/Broomva/scratch/identity-ci
  mkdir -p "$scratch/tmp" "$scratch/target"
  if [ -z "${TMPDIR:-}" ]; then
    export TMPDIR="$scratch/tmp"
  fi
  if [ -z "${CARGO_TARGET_DIR:-}" ]; then
    export CARGO_TARGET_DIR="$scratch/target"
  fi
fi
for dir in "${HOME}/.cargo/bin" "${HOME}/.bun/bin" "${HOME}/.local/bin"; do
  if [ -d "$dir" ]; then
    export PATH="$dir:${PATH}"
  fi
done
JSONSCHEMA_VERSION=4.25.1
pin_jsonschema() {
  if python3 -c "import importlib.metadata; from jsonschema.validators import Draft202012Validator; assert importlib.metadata.version('jsonschema') == '$JSONSCHEMA_VERSION'" 2>/dev/null; then
    return 0
  fi
  if [ "${IDENTITY_OFFLINE:-0}" = 1 ]; then
    echo "jsonschema==$JSONSCHEMA_VERSION is required in offline mode" >&2
    exit 1
  fi
  python3 -m pip install --user "jsonschema==$JSONSCHEMA_VERSION"
  python3 -c "import importlib.metadata; from jsonschema.validators import Draft202012Validator; assert importlib.metadata.version('jsonschema') == '$JSONSCHEMA_VERSION'"
}
pin_jsonschema
export PYTHONDONTWRITEBYTECODE=1
if ! command -v bun >/dev/null 2>&1; then
  echo "bun is required to check the TypeScript binding" >&2
  exit 1
fi
step() { echo "== $*"; "$@"; }
step python3 scripts/generate_bindings.py --check
( cd bindings/typescript && bun install --frozen-lockfile )
step cargo fmt --all --check
step cargo clippy --workspace --all-targets --locked -- -D warnings
step cargo test --workspace --locked
step scripts/mutation-check.sh
echo "== ci green"
