#!/usr/bin/env bash
# Tests of `tycho security deploy credentials` (static and live controls).
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
audit="${here}/../bin/credentials.sh"
fixture="${here}/fixtures/provider"
failures=0

# expect <description> <jq filter over the JSON report that must be true>
expect() {
    if echo "$REPORT" | jq -e "$2" >/dev/null; then
        echo "ok   - $1"
    else
        echo "FAIL - $1"
        failures=$((failures + 1))
    fi
}
status_of() {
    echo "(.findings | map(select(.control == \"$1\" and .subject == \"$2\")) | .[0].status) == \"$3\""
}

# --- static ---
REPORT="$(bash "$audit" --recipes "$fixture" --format json)"
code=$?
expect "exit code 1 when a control fails" "$code == 1"
expect "undeclared recipe fails credentials.declared" "$(status_of credentials.declared acme-proxy FAIL)"
expect "empty declaration passes" "$(status_of credentials.declared acme-cache PASS)"
expect "renamed login passes" "$(status_of credentials.login-replaced acme-server/administrator PASS)"
expect "secret-sourced passes for the compliant recipe" '[.findings[] | select(.subject == "acme-server/administrator" and .control == "credentials.secret-sourced")] | all(.status == "PASS")'
expect "exposure order passes" "$(status_of credentials.exposure-order acme-server/administrator PASS)"
expect "default login fails login-replaced" "$(status_of credentials.login-replaced acme-console/bootstrap FAIL)"
expect "optional login variable with default fails secret-sourced" '[.findings[] | select(.subject == "acme-console/bootstrap" and .control == "credentials.secret-sourced" and .status == "FAIL")] | length >= 1'
expect "missing exposure fails" "$(status_of credentials.exposure-order acme-console/bootstrap FAIL)"
expect "account kept as is fails login-replaced" "$(status_of credentials.login-replaced acme-gitops/built-in FAIL)"
expect "every finding cites the rule" '[.findings[] | .rule == "factory-default-credentials"] | all'

REPORT="$(bash "$audit" --recipes "$fixture" --recipe acme-cache --format json)"
code=$?
expect "--recipe filters, exit 0 when nothing fails" "$code == 0 and (.findings | length) == 1"

# --- live ---
if command -v python3 >/dev/null 2>&1; then
    REPORT="$(PATH="${here}/shim:${PATH}" bash "$audit" --recipes "$fixture" --live --format json)"
    expect "factory pair rejected by the compliant service" "$(status_of credentials.factory-rejected acme-server/administrator PASS)"
    expect "factory login retired on the compliant service" "$(status_of credentials.factory-login-retired acme-server/administrator PASS)"
    expect "kept bootstrap login detected live" "$(status_of credentials.factory-login-retired acme-console/bootstrap FAIL)"
    expect "deployed passwords never appear in the report" '(tostring | contains("Deployed-Passw0rd") or contains("console-deployed-pass")) | not'
else
    echo "skip - live tests (python3 missing)"
fi

echo
if [ "$failures" -gt 0 ]; then
    echo "${failures} test(s) failed"
    exit 1
fi
echo "all tests passed"
