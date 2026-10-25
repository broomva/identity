#!/usr/bin/env bash
# The one gate: CI runs it, and an agent runs it before a PR.
# fmt, clippy, tests, mutation. This crate has no plugin, tail bench or bridge.
set -euo pipefail
cd "$(dirname "$0")/.."
unset GIT_DIR GIT_WORK_TREE GIT_COMMON_DIR GIT_INDEX_FILE GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES
# Cargo targets stay on the SSD when this machine has one. GitHub has no such volume.
if [ -d /Volumes/Broomva/scratch ]; then
  scratch=/Volumes/Broomva/scratch/identity-ci
  mkdir -p "$scratch/tmp" "$scratch/target"
  export TMPDIR="$scratch/tmp"
  export CARGO_TARGET_DIR="$scratch/target"
fi
pyroot="${CARGO_TARGET_DIR:-$PWD/target}/py"
mkdir -p "$pyroot"
python3 -m pip install -q --disable-pip-version-check --target "$pyroot" 'jsonschema>=4.18'
export PYTHONPATH="$pyroot${PYTHONPATH:+:$PYTHONPATH}"
export PYTHONDONTWRITEBYTECODE=1
if [ -x "${HOME}/.bun/bin/bun" ]; then
  export PATH="${HOME}/.bun/bin:${PATH}"
fi
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
