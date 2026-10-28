#!/usr/bin/env bash
# Each mutant breaks one guard. The suite must fail on a named test for every one.
# A mutant that does not build, times out, or exits without a failing test is a failure.
set -euo pipefail
cd "$(dirname "$0")/.."
command -v timeout >/dev/null || { echo "mutation-check needs \`timeout\` (GNU coreutils)"; exit 3; }
if [ -d /Volumes/Broomva/scratch ] && [[ "${TMPDIR:-}" != /Volumes/Broomva/* ]]; then
  mkdir -p /Volumes/Broomva/scratch/identity-ci/tmp
  export TMPDIR=/Volumes/Broomva/scratch/identity-ci/tmp
fi
exec python3 scripts/mutation_check.py "$@"
