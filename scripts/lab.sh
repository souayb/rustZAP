#!/usr/bin/env bash
# Drive the deliberately-vulnerable lab target (tests/fixtures/lab).
#
# This is a MANUAL convenience — it is never invoked by CI or the git hooks. The
# pure-Rust matrix (tests/vuln_lab_*.rs) is what gates the scanner in CI and
# needs neither node nor docker.
#
# Usage:
#   scripts/lab.sh up        # build + start the lab on http://localhost:3001
#   scripts/lab.sh scan      # full DAST scan of the running lab → reports/
#   scripts/lab.sh redteam   # point the agent's OWASP-LLM battery at the lab
#   scripts/lab.sh down       # stop the lab
#
# Prefer localhost/lab targets only — never scan hosts you do not own.
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LAB_URL="${LAB_URL:-http://localhost:3001}"
SCOPE="$ROOT/tests/fixtures/lab/scope.yaml"

cmd="${1:-help}"
case "$cmd" in
  up)
    docker compose --profile labs up -d --build vuln-lab
    echo "vuln-lab up on $LAB_URL"
    ;;
  down)
    docker compose --profile labs down
    ;;
  scan)
    mkdir -p "$ROOT/reports"
    cargo run --manifest-path "$ROOT/Cargo.toml" -- scan \
      --target "$LAB_URL" --active-all-paths -o "$ROOT/reports/lab-report.json"
    ;;
  redteam)
    cargo run --manifest-path "$ROOT/Cargo.toml" -- agent \
      --scope "$SCOPE" \
      --target "$LAB_URL/v1/chat/completions" \
      --ai-redteam --ai-redteam-marker "rustzap-lab-secret-directive" \
      --autonomy auto -o "$ROOT/reports/lab-agent-report.json"
    ;;
  analyze)
    cargo run --manifest-path "$ROOT/Cargo.toml" -- analyze \
      "$ROOT/tests/fixtures/lab" --tools native --yes -o "$ROOT/reports/lab-sast.json"
    ;;
  *)
    grep '^#' "$0" | sed 's/^# \{0,1\}//'
    ;;
esac
