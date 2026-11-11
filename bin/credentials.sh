#!/usr/bin/env bash
# ==============================================================================
# tycho security deploy credentials — factory default credentials audit
#
#   tycho security deploy credentials [--recipes <dir>] [--recipe <name>]
#                                     [--live] [--context <kubectl-context>]
#                                     [--format text|json]
#
# Implements the controls of the knowledge unit "Factory Default Credentials"
# (AGENTS.okf, content/cybersecurity/factory-default-credentials.md).
#
# Static controls read a recipe provider descriptor (.tycho/repository.json and
# .tycho/recipes/<engine>/<recipe>/package.json, field tycho.credentials):
#   credentials.declared         every recipe declares its factory accounts
#   credentials.login-replaced   login replaced (variable, no default, not well
#                                known) or built-in account disabled; an
#                                account kept as is (replacement: none) fails
#   credentials.secret-sourced   login and password variables are required
#                                secrets without default
#   credentials.exposure-order   public route published after the replacement
#
# Live controls (--live) reach each declared service over a local kubectl
# port-forward, ONE login attempt per control and account:
#   credentials.factory-rejected       the factory pair is refused
#   credentials.factory-login-retired  the factory login with the deployed
#                                      password is refused
#
# Exit code: 0 without failure, 1 when a control fails, 2 on usage errors.
# Replacement values read from the cluster are never printed.
# ==============================================================================
set -euo pipefail

RULE="factory-default-credentials"
WELL_KNOWN_LOGINS="admin administrator root superuser sysadmin system user test guest operator ops sa"

RECIPES_DIR="."
ONLY_RECIPE=""
LIVE=0
CONTEXT=""
FORMAT="text"

usage() {
    sed -n '4,7p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit 2
}

while [ $# -gt 0 ]; do
    case "$1" in
        --recipes) shift; RECIPES_DIR="${1:-}"; [ -n "$RECIPES_DIR" ] || usage ;;
        --recipe) shift; ONLY_RECIPE="${1:-}"; [ -n "$ONLY_RECIPE" ] || usage ;;
        --live) LIVE=1 ;;
        --context) shift; CONTEXT="${1:-}"; [ -n "$CONTEXT" ] || usage ;;
        --format) shift; FORMAT="${1:-}"; case "$FORMAT" in text|json) ;; *) usage ;; esac ;;
        -h|--help|help) usage ;;
        *) echo "Unknown option: $1" >&2; usage ;;
    esac
    shift
done

for tool in jq curl; do
    command -v "$tool" >/dev/null 2>&1 || { echo "Missing tool: ${tool}" >&2; exit 2; }
done
DESCRIPTOR="${RECIPES_DIR%/}/.tycho"
[ -f "${DESCRIPTOR}/repository.json" ] || { echo "No recipe provider descriptor: ${DESCRIPTOR}/repository.json" >&2; exit 2; }

# --- Findings -------------------------------------------------------------------
FINDINGS="$(mktemp)"
PF_PID=""
cleanup() {
    rm -f "$FINDINGS"
    if [ -n "$PF_PID" ]; then
        kill "$PF_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# finding <PASS|FAIL|WARN|SKIP> <control> <subject> <message>
finding() {
    jq -nc --arg s "$1" --arg c "$2" --arg o "$3" --arg m "$4" --arg r "$RULE" \
        '{status: $s, control: $c, subject: $o, message: $m, rule: $r}' >> "$FINDINGS"
}

variable_def() {
    jq -c --arg v "$1" '.variables[$v] // empty' "${DESCRIPTOR}/repository.json"
}
is_well_known() {
    local value
    value="$(echo "$1" | tr '[:upper:]' '[:lower:]')"
    for name in $WELL_KNOWN_LOGINS; do
        [ "$value" = "$name" ] && return 0
    done
    return 1
}

# --- Static controls --------------------------------------------------------------
# check_variable <recipe-json> <subject> <role> <variable>
check_variable() {
    local recipe="$1" subject="$2" role="$3" variable="$4" def required problems=""
    def="$(variable_def "$variable")"
    required="$(echo "$recipe" | jq --arg v "$variable" '(.requiredEnv // []) | index($v) != null')"
    if [ -z "$def" ]; then
        problems="not defined in repository.json"
    else
        [ "$(echo "$def" | jq '.secret == true')" = "true" ] || problems="${problems:+$problems, }not secret"
        [ "$(echo "$def" | jq 'has("default")')" = "false" ] || problems="${problems:+$problems, }has a default"
    fi
    [ "$required" = "true" ] || problems="${problems:+$problems, }not in requiredEnv"
    if [ -n "$problems" ]; then
        finding FAIL credentials.secret-sourced "$subject" "${role} variable ${variable}: ${problems}"
    else
        finding PASS credentials.secret-sourced "$subject" "${role} variable ${variable} is a required secret without default"
    fi
}

static_audit() {
    local file="$1" recipe name count i entry subject replacement login password exposure def example default
    recipe="$(cat "$file")"
    name="$(echo "$recipe" | jq -r '.name')"
    if [ "$(echo "$recipe" | jq '.tycho | has("credentials")')" != "true" ]; then
        finding FAIL credentials.declared "$name" "no tycho.credentials declaration (declare [] when the software has no factory account)"
        return
    fi
    count="$(echo "$recipe" | jq '.tycho.credentials | length')"
    if [ "$count" = "0" ]; then
        finding PASS credentials.declared "$name" "declares no factory account"
        return
    fi
    finding PASS credentials.declared "$name" "declares ${count} factory account(s)"
    for i in $(seq 0 $((count - 1))); do
        entry="$(echo "$recipe" | jq -c ".tycho.credentials[$i]")"
        subject="${name}/$(echo "$entry" | jq -r '.account // "account"')"
        replacement="$(echo "$entry" | jq -r '.replacement // "rename"')"
        login="$(echo "$entry" | jq -r '.login // empty')"
        password="$(echo "$entry" | jq -r '.password // empty')"
        exposure="$(echo "$entry" | jq -r '.exposure // empty')"

        case "$replacement" in
            disable)
                finding PASS credentials.login-replaced "$subject" "built-in account disabled by the recipe"
                ;;
            rename)
                if [ -z "$login" ]; then
                    finding FAIL credentials.login-replaced "$subject" "replacement 'rename' without a login variable: the factory login '$(echo "$entry" | jq -r '.factory.login // "?"')' stays in use"
                else
                    def="$(variable_def "$login")"
                    default="$(echo "$def" | jq -r '.default // empty' 2>/dev/null || true)"
                    example="$(echo "$def" | jq -r '.example // empty' 2>/dev/null || true)"
                    if [ -n "$default" ]; then
                        finding FAIL credentials.login-replaced "$subject" "login variable ${login} has the default '${default}'"
                    elif [ -n "$example" ] && is_well_known "$example"; then
                        finding FAIL credentials.login-replaced "$subject" "login variable ${login} suggests the well-known login '${example}'"
                    else
                        finding PASS credentials.login-replaced "$subject" "login replaced through ${login}"
                    fi
                    check_variable "$recipe" "$subject" login "$login"
                fi
                ;;
            none)
                finding FAIL credentials.login-replaced "$subject" "factory account '$(echo "$entry" | jq -r '.factory.login // "?"')' kept as is (replacement: none)"
                ;;
            *)
                finding FAIL credentials.login-replaced "$subject" "unknown replacement '${replacement}' (rename, disable or none)"
                ;;
        esac
        if [ -n "$password" ]; then
            check_variable "$recipe" "$subject" password "$password"
        elif [ "$replacement" = "rename" ]; then
            finding FAIL credentials.secret-sourced "$subject" "no password variable declared"
        fi
        if [ "$exposure" = "after-replacement" ]; then
            finding PASS credentials.exposure-order "$subject" "public route published after the replacement"
        else
            finding FAIL credentials.exposure-order "$subject" "exposure is '${exposure:-undeclared}', expected 'after-replacement'"
        fi
    done
}

# --- Live controls ------------------------------------------------------------------
KUBECTL=(kubectl)
if [ -n "$CONTEXT" ]; then
    KUBECTL=(kubectl --context "$CONTEXT")
fi

secret_value() {
    "${KUBECTL[@]}" get secret "$2" -n "$1" -o "jsonpath={.data.$3}" 2>/dev/null | base64 -d 2>/dev/null || true
}

# try_login <probe-json> <base-url> <login> <password> -> 0 when accepted
try_login() {
    local probe="$1" base="$2" login="$3" password="$4" type path accept body content_type code out
    type="$(echo "$probe" | jq -r '.type')"
    path="$(echo "$probe" | jq -r '.path // "/"')"
    accept="$(echo "$probe" | jq -r '.accept // "200"')"
    out="$(mktemp)"
    case "$type" in
        http-basic)
            code="$(curl -s -o "$out" -w '%{http_code}' --max-time 15 -u "${login}:${password}" "${base}${path}" || echo 000)"
            ;;
        http-post)
            content_type="$(echo "$probe" | jq -r '.contentType // "form"')"
            if [ "$content_type" = "json" ]; then
                body="$(echo "$probe" | jq -r --arg l "$login" --arg p "$password" \
                    '.body | gsub("\\{login\\}"; ($l | tojson | .[1:-1])) | gsub("\\{password\\}"; ($p | tojson | .[1:-1]))')"
                code="$(curl -s -o "$out" -w '%{http_code}' --max-time 15 -H 'Content-Type: application/json' \
                    --data "$body" "${base}${path}" || echo 000)"
            else
                body="$(echo "$probe" | jq -r --arg l "$login" --arg p "$password" \
                    '.body | gsub("\\{login\\}"; ($l | @uri)) | gsub("\\{password\\}"; ($p | @uri))')"
                code="$(curl -s -o "$out" -w '%{http_code}' --max-time 15 -H 'Content-Type: application/x-www-form-urlencoded' \
                    --data "$body" "${base}${path}" || echo 000)"
            fi
            ;;
        *)
            rm -f "$out"
            return 2
            ;;
    esac
    if echo "$accept" | grep -qE '^[0-9]{3}$'; then
        [ "$code" = "$accept" ] && { rm -f "$out"; return 0; }
    elif [ "${code:0:1}" = "2" ] && grep -qE -- "$accept" "$out"; then
        rm -f "$out"
        return 0
    fi
    rm -f "$out"
    return 1
}

live_audit() {
    local file="$1" recipe name count i entry subject probe namespace service port local_port base
    local factory_login factory_password secret_name password_key deployed
    recipe="$(cat "$file")"
    name="$(echo "$recipe" | jq -r '.name')"
    count="$(echo "$recipe" | jq '(.tycho.credentials // []) | length')"
    [ "$count" != "0" ] || return 0
    for i in $(seq 0 $((count - 1))); do
        entry="$(echo "$recipe" | jq -c ".tycho.credentials[$i]")"
        subject="${name}/$(echo "$entry" | jq -r '.account // "account"')"
        probe="$(echo "$entry" | jq -c '.probe // empty')"
        if [ -z "$probe" ]; then
            finding WARN credentials.factory-rejected "$subject" "no probe declared: live check impossible, verify by hand"
            continue
        fi
        namespace="$(echo "$probe" | jq -r '.namespace')"
        service="$(echo "$probe" | jq -r '.service')"
        port="$(echo "$probe" | jq -r '.port')"
        if ! "${KUBECTL[@]}" get service "$service" -n "$namespace" >/dev/null 2>&1; then
            finding SKIP credentials.factory-rejected "$subject" "service ${namespace}/${service} not deployed"
            continue
        fi
        local_port=$((20000 + RANDOM % 20000))
        "${KUBECTL[@]}" port-forward -n "$namespace" "svc/${service}" "${local_port}:${port}" >/dev/null 2>&1 &
        PF_PID=$!
        base="http://127.0.0.1:${local_port}"
        for _ in $(seq 1 20); do
            curl -s -o /dev/null --max-time 2 "$base/" && break
            sleep 0.5
        done

        factory_login="$(echo "$entry" | jq -r '.factory.login // empty')"
        factory_password="$(echo "$entry" | jq -r '.factory.password // empty')"
        if [ -z "$factory_password" ] && [ "$(echo "$entry" | jq '.factory | has("passwordFrom")')" = "true" ]; then
            factory_password="$(secret_value "$namespace" "$(echo "$entry" | jq -r '.factory.passwordFrom.secret')" "$(echo "$entry" | jq -r '.factory.passwordFrom.key')")"
            if [ -z "$factory_password" ]; then
                finding PASS credentials.factory-rejected "$subject" "generated factory password Secret is gone"
            fi
        fi
        if [ -n "$factory_login" ] && [ -n "$factory_password" ]; then
            if try_login "$probe" "$base" "$factory_login" "$factory_password"; then
                finding FAIL credentials.factory-rejected "$subject" "factory credentials of '${factory_login}' ACCEPTED by ${namespace}/${service}"
            else
                finding PASS credentials.factory-rejected "$subject" "factory credentials rejected"
            fi
        fi

        secret_name="$(echo "$entry" | jq -r '.secret.name // empty')"
        password_key="$(echo "$entry" | jq -r '.secret.passwordKey // empty')"
        if [ -n "$factory_login" ] && [ -n "$secret_name" ] && [ -n "$password_key" ]; then
            deployed="$(secret_value "$namespace" "$secret_name" "$password_key")"
            if [ -z "$deployed" ]; then
                finding WARN credentials.factory-login-retired "$subject" "deployed password ${secret_name}/${password_key} not readable"
            elif try_login "$probe" "$base" "$factory_login" "$deployed"; then
                finding FAIL credentials.factory-login-retired "$subject" "factory login '${factory_login}' still accepted with the deployed password"
            else
                finding PASS credentials.factory-login-retired "$subject" "factory login '${factory_login}' retired"
            fi
        fi
        kill "$PF_PID" 2>/dev/null || true
        wait "$PF_PID" 2>/dev/null || true
        PF_PID=""
    done
}

# --- Run -----------------------------------------------------------------------------
shopt -s nullglob
RECIPE_FILES=("${DESCRIPTOR}"/recipes/*/*/package.json)
[ "${#RECIPE_FILES[@]}" -gt 0 ] || { echo "No recipe under ${DESCRIPTOR}/recipes" >&2; exit 2; }
if [ "$LIVE" = "1" ]; then
    command -v kubectl >/dev/null 2>&1 || { echo "Missing tool: kubectl (--live)" >&2; exit 2; }
fi
for file in "${RECIPE_FILES[@]}"; do
    if [ -n "$ONLY_RECIPE" ] && [ "$(jq -r '.name' "$file")" != "$ONLY_RECIPE" ]; then
        continue
    fi
    static_audit "$file"
    if [ "$LIVE" = "1" ]; then
        live_audit "$file"
    fi
done

if [ "$FORMAT" = "json" ]; then
    jq -s '{rule: "factory-default-credentials", findings: ., summary: (group_by(.status) | map({key: .[0].status, value: length}) | from_entries)}' "$FINDINGS"
else
    while IFS=$'\t' read -r status control subject message; do
        case "$status" in
            PASS) color="\033[32m" ;;
            FAIL) color="\033[31m" ;;
            WARN) color="\033[33m" ;;
            *) color="\033[90m" ;;
        esac
        printf "${color}%-4s\033[0m  %-36s %-28s %s\n" "$status" "$control" "$subject" "$message"
    done < <(jq -r '[.status, .control, .subject, .message] | @tsv' "$FINDINGS")
    echo
    echo "Rule: ${RULE} | $(jq -rs 'group_by(.status) | map("\(.[0].status) \(length)") | join(" · ")' "$FINDINGS")"
fi
if [ "$(jq -s 'map(select(.status == "FAIL")) | length' "$FINDINGS")" != "0" ]; then
    exit 1
fi
