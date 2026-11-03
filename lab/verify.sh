#!/usr/bin/env bash
# verify.sh -- the executable self-test for the XAMMU v1.0.0 laboratory.
#
# Starts the lab, asserts all five documented behaviours plus response-shape
# separation and the strip-marker-headers mode, prints a PASS/FAIL table, tears
# the lab down and exits non-zero on any mismatch. A compose file alone is never
# accepted as proof of reproducibility: this script is the proof.
#
#   ./verify.sh              start, assert, tear down
#   KEEP_LAB=1 ./verify.sh   leave the lab running for manual poking
#   ./verify.sh --no-down    same as KEEP_LAB=1
#   ./verify.sh --only B2    run one section only (B1 B2 B3 B4 B5 S K)
#
# Probes run INSIDE the lab network (compose service netrunner) because the
# network is internal: true and therefore unreachable from the host. See
# lab/README.md for the measured evidence behind that decision.
set -uo pipefail

LAB_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="$LAB_DIR/compose.yaml"
DIGESTS_FILE="$LAB_DIR/DIGESTS.txt"

KEEP_LAB="${KEEP_LAB:-0}"
ONLY=""
while [ $# -gt 0 ]; do
  case "$1" in
    --no-down) KEEP_LAB=1 ;;
    --only) ONLY="${2:-}"; shift ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
  esac
  shift
done

W="http://waf:8080"
WS="http://waf-stripped:8080"
O="http://origin:8081"
MARKER="XAMMU-LAB-WAF-BLOCK"

# ---------------------------------------------------------------------------
# Diagnostic probes. Shape-only by construction: they keep the lexical features a
# real signature matches and drop everything that could actually run. No complete
# SQL statement, no working JavaScript, no real command, no existing path. The
# project rule is absolute: if a payload can exploit, it does not enter the corpus.
# ---------------------------------------------------------------------------
P_SQLI_CANON="' or 1=1 xammu-probe"                    # no table, no target
P_SQLI_ENC1='%27%20or%201%3d1%20xammu-probe'           # same value, encoded once
P_SQLI_ENC2='%2527%2520or%25201%253d1%2520xammu-probe' # same value, encoded twice
P_XSS_ENC1='%3Cxammu-probe-script%3E'                  # inert: no handler, no end tag
P_XSS_ENC2='%253Cxammu-probe-script%253E'
P_XSS_URI_ENC='%6aavascript%3Axammu-probe'             # inert: nothing follows the colon
P_TRAV_ENC='%2e%2e%2f%2e%2e%2fxammu-probe'             # inert: path exists nowhere
P_TRAV_ENC2='%252e%252e%252f%252e%252e%252fxammu-probe'
P_CMD_ENC='%3b%20xammu-probe%20%3b'                    # inert: names no binary
P_TOKEN='xammu-probe-token'                            # laboratory sentinel

# The identical probe as it appears in each transport. Both sides collapse to
# exactly this string, which is what makes the B1 comparison a measurement and
# not a hand-wave.
BODY_JSON="{\"q\": \"' or 1=1 xammu-probe\"}"

# ---------------------------------------------------------------------------
# Result collection
# ---------------------------------------------------------------------------
declare -a A_SECT A_NAME A_EXP A_ACT A_RES
PASS_N=0 FAIL_N=0
SECTION=""

section() { SECTION="$1"; printf '\n\033[1m== %s\033[0m\n' "$1"; }

wanted() { # wanted <SECTION-ID>  -> 0 when this section should run
  [ -z "$ONLY" ] && return 0
  case "$SECTION" in *"$1"*) return 0 ;; *) return 1 ;; esac
}

ck() { # ck <id> <name> <expected> <actual>
  local id="$1" name="$2" expected="$3" actual="$4"
  wanted "$id" || return 0
  local status
  if [ "$expected" = "$actual" ]; then
    status="PASS"; PASS_N=$((PASS_N + 1))
  else
    status="FAIL"; FAIL_N=$((FAIL_N + 1))
  fi
  A_SECT+=("$id"); A_NAME+=("$name"); A_EXP+=("$expected"); A_ACT+=("$actual"); A_RES+=("$status")
  if [ "$status" = "PASS" ]; then
    printf '  \033[32mPASS\033[0m %-13s %-50s expected=%-26s actual=%s\n' "$id" "$name" "$expected" "$actual"
  else
    printf '  \033[1;31mFAIL\033[0m %-13s %-50s expected=%-26s \033[31mactual=%s\033[0m\n' "$id" "$name" "$expected" "$actual"
  fi
}

# ---------------------------------------------------------------------------
# Probing. RESPONDER runs inside netrunner. Values travel through env vars so
# spaces inside header values and bodies survive intact. The response body stays
# in /tmp/b and the headers in /tmp/h for follow-up inspection.
#
# Output is pipe-delimited, one line, nine fields:
#   status | content-type | server | x-lab-waf-action | body-length
#        | marker-in-body | marker-in-title | from-origin | x-lab-waf-rule
#
# The ninth field is the rule-attribution trace header. It is suppressed by
# LAB_STRIP_WAF_TRACE_HEADERS, so it is used only to name the rule behind a
# decision, never to decide whether one happened.
# ---------------------------------------------------------------------------
RESPONDER='
set -- -s --max-time 20
[ -n "${P_H1:-}" ] && set -- "$@" -H "$P_H1"
[ -n "${P_H2:-}" ] && set -- "$@" -H "$P_H2"
[ -n "${P_CT:-}" ]  && set -- "$@" -H "Content-Type: $P_CT"
if [ -n "${P_DATA:-}" ]; then
  set -- "$@" -X "${P_METHOD:-POST}" --data-binary "$P_DATA"
else
  set -- "$@" -X "${P_METHOD:-GET}"
fi
code=$(curl -o /tmp/b -D /tmp/h -w "%{http_code}" "$@" "${P_URL}") || code=000
ct=$(grep -i "^content-type:" /tmp/h | head -1 | tr -d "\r\n" | cut -d" " -f2- | tr -d " ")
svr=$(grep -i "^server:" /tmp/h | head -1 | tr -d "\r\n" | cut -d" " -f2- | tr -d " ")
act=$(grep -i "^x-lab-waf-action:" /tmp/h | head -1 | tr -d "\r\n" | cut -d" " -f2- | tr -d " ")
rule=$(grep -i "^x-lab-waf-rule:" /tmp/h | head -1 | tr -d "\r\n" | cut -d" " -f2- | tr -d " ")
blen=$(wc -c < /tmp/b | tr -d " ")
if grep -q "${P_MARKER}" /tmp/b; then mk=1; else mk=0; fi
if grep -q "<title>[^<]*${P_MARKER}" /tmp/b; then tmk=1; else tmk=0; fi
if grep -q "\"source\": \"origin\"" /tmp/b; then src=1; else src=0; fi
printf "%s|%s|%s|%s|%s|%s|%s|%s|%s\n" "$code" "$ct" "$svr" "$act" "$blen" "$mk" "$tmk" "$src" "$rule"
'

# probe <url> [h1] [h2] [data] [content-type] [method]
probe() {
  docker compose -f "$COMPOSE_FILE" exec -T \
    -e P_URL="$1" -e P_H1="${2:-}" -e P_H2="${3:-}" -e P_DATA="${4:-}" \
    -e P_CT="${5:-}" -e P_METHOD="${6:-}" -e P_MARKER="$MARKER" \
    netrunner sh -c "$RESPONDER" 2>/dev/null
}

field() { printf '%s\n' "$1" | cut -d'|' -f"$2"; }

# labsh <script> runs a one-off shell inside netrunner (for checks that need
# curl flags the generic responder does not carry).
labsh() { docker compose -f "$COMPOSE_FILE" exec -T netrunner sh -c "$1" 2>/dev/null; }

# The two diagnostic endpoints take JSON documents as parameters. Values are
# carried through the environment rather than interpolated into a shell string,
# because a value containing a double quote would otherwise break the command --
# which is exactly the kind of silent test-authoring bug that fakes a green run.
COV_RESPONDER='
set -- -s --max-time 25 -G
[ -n "${P_T:-}" ]    && set -- "$@" --data-urlencode "transport=$P_T"
[ -n "${P_BODY:-}" ] && set -- "$@" --data-urlencode "body=$P_BODY"
[ -n "${P_RAWQ:-}" ] && set -- "$@" --data-urlencode "raw_query=$P_RAWQ"
[ -n "${P_PATH:-}" ] && set -- "$@" --data-urlencode "path=$P_PATH"
curl "$@" "${P_URL}"
'

# cov <url> <transport> [body] [raw_query] [path] -> coverage JSON, one line per
# field. Spaces are KEPT on purpose: both diagnostic endpoints pretty-print, so a
# pattern like `"signature": "' or 1=1 xammu-probe"` only matches if the interior
# spaces of the value survive. Collapsing whitespace here would silently break the
# comparisons that matter most.
cov() {
  docker compose -f "$COMPOSE_FILE" exec -T \
    -e P_URL="$1" -e P_T="$2" -e P_BODY="${3:-}" -e P_RAWQ="${4:-}" -e P_PATH="${5:-}" \
    netrunner sh -c "$COV_RESPONDER" 2>/dev/null | tr -d '\r\t'
}

NORM_RESPONDER='
curl -s --max-time 25 -X POST -H "Content-Type: application/json" \
     --data-binary "$P_NORM" "${P_URL}"
'

# norm <json-object> -> origin decoding report (same space-preserving rationale)
norm() {
  docker compose -f "$COMPOSE_FILE" exec -T \
    -e P_URL="$O/internal/normalize" -e P_NORM="$1" \
    netrunner sh -c "$NORM_RESPONDER" 2>/dev/null | tr -d '\r\t'
}

# has <text> <pattern> -> 1 when the pattern occurs at least once, else 0.
# Presence, not a count: the coverage document deliberately repeats the same
# signature in two places (the accounting entry and the per-value check), and an
# exact count there would be a property of the report's layout rather than of the
# WAF. What the checks need is "is this evidence present at all".
has() {
  if printf '%s' "$1" | grep -q -- "$2"; then printf '1'; else printf '0'; fi
}

# ---------------------------------------------------------------------------
# 0. Preflight
# ---------------------------------------------------------------------------
command -v docker >/dev/null 2>&1 || { echo "docker is required and was not found" >&2; exit 2; }
docker info >/dev/null 2>&1 || { echo "the docker daemon is not answering" >&2; exit 2; }
[ -f "$COMPOSE_FILE" ] || { echo "missing $COMPOSE_FILE" >&2; exit 2; }
[ -f "$DIGESTS_FILE" ] || { echo "missing $DIGESTS.txt -- run ./build.sh first" >&2; exit 2; }

echo "XAMMU v1.0.0 laboratory self-test"
echo "  compose : $COMPOSE_FILE"
echo "  digests : $DIGESTS_FILE"
[ -n "$ONLY" ] && echo "  only    : $ONLY"

section "startup"

# ---------------------------------------------------------------------------
# 1. Start and identity
# ---------------------------------------------------------------------------
docker compose -f "$COMPOSE_FILE" down --remove-orphans >/dev/null 2>&1 || true
if ! docker compose -f "$COMPOSE_FILE" up -d --wait --wait-timeout 120 >/tmp/lab-up.log 2>&1; then
  echo "the lab did not become healthy; tail of compose output:" >&2
  tail -25 /tmp/lab-up.log >&2
  exit 3
fi

for c in xammu-lab-origin xammu-lab-waf xammu-lab-waf-stripped xammu-lab-netrunner; do
  ck "UP" "$c healthy" "healthy" "$(docker inspect --format '{{.State.Health.Status}}' "$c" 2>/dev/null || echo missing)"
done

digest_of() { # digest_of <image-name> -> image_id recorded in DIGESTS.txt
  sed -n "s|^${1}[[:space:]]*image_id=\(sha256:[0-9a-f]*\).*|\1|p" "$DIGESTS_FILE" | head -1
}

want_origin=$(digest_of "xammu-lab-origin:1.0.0")
want_waf=$(digest_of "xammu-lab-waf:1.0.0")
ck "UP" "origin digest recorded by build.sh" "sha256" \
  "$(printf '%s' "$want_origin" | cut -c1-6)"
ck "UP" "waf digest recorded by build.sh" "sha256" \
  "$(printf '%s' "$want_waf" | cut -c1-6)"
ck "UP" "running origin image matches DIGESTS.txt" "$want_origin" "$(docker inspect --format '{{.Image}}' xammu-lab-origin)"
ck "UP" "running waf image matches DIGESTS.txt" "$want_waf" "$(docker inspect --format '{{.Image}}' xammu-lab-waf)"

# The engine has to say, in its own words, what it does not look at -- otherwise
# the gap is only something the README claims.
ck "UP" "info lists json_body among uninspected vectors" "1" \
  "$(labsh "curl -s $W/__lab/info | tr -d ' \n' | grep -c '\"uninspected_vectors\":\[\"json_body\"\]'")"
ck "UP" "info declares exactly one decode pass" "1" \
  "$(labsh "curl -s $W/__lab/info | tr -d ' \n' | grep -c '\"decode_passes\":1'")"

# ---------------------------------------------------------------------------
# B1 -- vector gap  (coverage_gap + vector_asymmetry)
# ---------------------------------------------------------------------------
section "B1 vector gap: same probe rejected in query string, forwarded in JSON body"

r=$(probe "$W/api/search?q=$P_SQLI_ENC1")
ck "B1" "SQLi shape in query string is rejected" "403" "$(field "$r" 1)"
ck "B1" "rejection carries the marker in the body" "1" "$(field "$r" 6)"
ck "B1" "rejection is an HTML interstitial" "text/html;charset=utf-8" "$(field "$r" 2)"
ck "B1" "rejection is attributed to rule SQLI-001" "SQLI-001" "$(field "$r" 9)"

r=$(probe "$W/api/search" "" "" "$BODY_JSON" "application/json")
ck "B1" "identical probe in JSON body is forwarded" "200" "$(field "$r" 1)"
ck "B1" "forwarded body really reached the origin" "1" "$(field "$r" 8)"

r=$(probe "$O/api/search" "" "" "$BODY_JSON" "application/json")
ck "B1" "origin alone accepts the same probe" "200" "$(field "$r" 1)"

# The WAF states the gap in its own words rather than leaving us to infer it.
sig_pat="\"signature\": \"' or 1=1 xammu-probe\""
cb=$(cov "$W/__lab/coverage" "json_body" "$BODY_JSON")
ck "B1" "coverage: body transport verdict is passed" "1" "$(has "$cb" '"probe_verdict": "passed"')"
ck "B1" "coverage: body value would match SQLI-001" "1" "$(has "$cb" '"would_match_rule": "SQLI-001"')"
ck "B1" "coverage: body transport flagged not inspected" "1" "$(has "$cb" '"vector_inspected": false')"
ck "B1" "coverage: body signature IS the rejected query value" "1" "$(has "$cb" "$sig_pat")"

cq=$(cov "$W/__lab/coverage" "query_string" "" "q=$P_SQLI_ENC1")
ck "B1" "coverage: query transport verdict is blocked" "1" "$(has "$cq" '"probe_verdict": "blocked"')"
ck "B1" "coverage: query value blocked by SQLI-001" "1" "$(has "$cq" '"blocked_by_rule": "SQLI-001"')"
ck "B1" "coverage: query signature is the same canonical probe" "1" "$(has "$cq" "$sig_pat")"

r=$(probe "$W/api/search?q=hello" "" "" "xammu_form_field=$P_SQLI_CANON" "application/x-www-form-urlencoded")
ck "B1" "SQLi shape in a form-encoded body is forwarded too" "200" "$(field "$r" 1)"

# ---------------------------------------------------------------------------
# B2 -- encoding bypass  (encoding_bypass_pattern)
# ---------------------------------------------------------------------------
section "B2 encoding: canonical and single-encoded rejected, double-encoded forwarded"

section "B2 encoding: canonical and single-encoded rejected, double-encoded forwarded"

# Canonical first: the literal characters exactly as the signature is written, with
# no percent-encoding at all. For the SQLi shape the spaces travel as '+', which
# net/url translates inside the SAME single pass the fixture documents -- it is not
# a second decode.
ck "B2" "canonical XSS tag is rejected" "403" "$(field "$(probe "$W/api/search?x=<xammu-probe-script")" 1)"
ck "B2" "canonical javascript: URI is rejected" "403" "$(field "$(probe "$W/api/search?x=javascript:xammu-probe")" 1)"
ck "B2" "canonical SQLi tautology is rejected" "403" "$(field "$(probe "$W/api/search?q='+or+1=1+xammu-probe")" 1)"
ck "B2" "canonical SQLi rejection is attributed to SQLI-001" "SQLI-001" \
  "$(field "$(probe "$W/api/search?q='+or+1=1+xammu-probe")" 9)"
ck "B2" "canonical XSS tag rejection is attributed to XSS-001" "XSS-001" \
  "$(field "$(probe "$W/api/search?x=<xammu-probe-script")" 9)"

ck "B2" "single-encoded XSS is rejected" "403" "$(field "$(probe "$W/api/search?x=$P_XSS_ENC1")" 1)"
ck "B2" "single-encoded XSS URI scheme is rejected" "403" "$(field "$(probe "$W/api/search?x=$P_XSS_URI_ENC")" 1)"
ck "B2" "single-encoded SQLi is rejected" "403" "$(field "$(probe "$W/api/search?q=$P_SQLI_ENC1")" 1)"
ck "B2" "double-encoded XSS is forwarded" "200" "$(field "$(probe "$W/api/search?x=$P_XSS_ENC2")" 1)"
ck "B2" "double-encoded XSS carries no marker" "0" "$(field "$(probe "$W/api/search?x=$P_XSS_ENC2")" 6)"
ck "B2" "double-encoded SQLi is forwarded" "200" "$(field "$(probe "$W/api/search?q=$P_SQLI_ENC2")" 1)"
ck "B2" "double-encoded traversal is forwarded" "200" "$(field "$(probe "$W/api/search?t=$P_TRAV_ENC2")" 1)"
ck "B2" "single-encoded traversal is rejected" "403" "$(field "$(probe "$W/api/search?t=$P_TRAV_ENC")" 1)"
ck "B2" "single-encoded command shape is rejected" "403" "$(field "$(probe "$W/api/search?c=$P_CMD_ENC")" 1)"

# The bypass is a property of normalization depth, not a special case for the
# word "double". The origin attests to the same depth on both shapes.
n1=$(norm "{\"one\":\"$P_SQLI_ENC1\"}")
n2=$(norm "{\"two\":\"$P_SQLI_ENC2\"}")
ck "B2" "origin declares exactly one decode pass" "1" "$(has "$n1" '"decode_passes": 1')"
ck "B2" "single-encoded: one pass already yields the canonical form" "0" "$(has "$n1" 'a_second_decode_would_yield')"
ck "B2" "double-encoded: a second pass would still change the value" "1" "$(has "$n2" 'a_second_decode_would_yield')"

# ---------------------------------------------------------------------------
# B3 -- uninspected vectors  (coverage_gap over headers and cookies)
# ---------------------------------------------------------------------------
section "B3 uninspected vectors: custom header values and unscanned cookie names"

ck "B3" "SQLi shape in a custom header passes" "200" "$(field "$(probe "$W/api/search?q=hello" "X-Lab-Probe-Payload: $P_SQLI_CANON")" 1)"
ck "B3" "sentinel in a custom header passes (values are not parsed)" "200" "$(field "$(probe "$W/api/search?q=hello" "X-Lab-Probe-Payload: $P_TOKEN")" 1)"
ck "B3" "sentinel in an unscanned cookie name passes" "200" "$(field "$(probe "$W/api/search?q=hello" "Cookie: xammu_probe_payload=$P_TOKEN")" 1)"
ck "B3" "the SAME sentinel in a scanned cookie name is blocked" "403" "$(field "$(probe "$W/api/search?q=hello" "Cookie: lab_probe_payload=$P_TOKEN")" 1)"
ck "B3" "scanned-cookie block is attributed to GENERIC-001" "GENERIC-001" \
  "$(field "$(probe "$W/api/search?q=hello" "Cookie: lab_probe_payload=$P_TOKEN")" 9)"
ck "B3" "traversal in a scanned cookie is blocked" "403" "$(field "$(probe "$W/api/search?q=hello" "Cookie: lab_probe_payload=$P_TRAV_ENC")" 1)"
ck "B3" "traversal cookie block is attributed to TRAVERSAL-001" "TRAVERSAL-001" \
  "$(field "$(probe "$W/api/search?q=hello" "Cookie: lab_probe_payload=$P_TRAV_ENC")" 9)"
ck "B3" "sentinel in a normal header IS blocked (gap is specific, not blanket)" "403" "$(field "$(probe "$W/api/search?q=hello" "User-Agent: $P_TOKEN")" 1)"
ck "B3" "normal-header block is attributed to GENERIC-001" "GENERIC-001" \
  "$(field "$(probe "$W/api/search?q=hello" "User-Agent: $P_TOKEN")" 9)"
ck "B3" "traversal in the request path is blocked" "403" "$(field "$(probe "$W/api/search/$P_TRAV_ENC")" 1)"
ck "B3" "path block is attributed to TRAVERSAL-001" "TRAVERSAL-001" \
  "$(field "$(probe "$W/api/search/$P_TRAV_ENC")" 9)"
# The header-name policy, and what it is NOT.
#
# The policy is a NAME-presence decision, so three separate properties have to be
# pinned down or the check is worth nothing:
#   - it fires on a value that is protocol-valid and completely innocuous;
#   - it fires whatever the capitalisation of the name;
#   - it does NOT fire on a near-miss name, which proves the denylist is exact
#     and not a prefix match over "x-lab-probe-".
# And one property of the tooling, documented because it bit us: curl's
# -H "Name:" syntax REMOVES a header rather than sending an empty one. So the
# empty-value case cannot express "present but empty" through curl at all, and we
# assert the actual curl semantics instead of pretending. That is a fact about
# the test harness, not a gap in the fixture.
ck "B3" "header-name policy blocks the smuggling name" "403" "$(field "$(probe "$W/api/search?q=hello" "X-Lab-Probe-Transfer-Encoding: chunked")" 1)"
ck "B3" "policy keys on the name, case-insensitively" "403" "$(field "$(probe "$W/api/search?q=hello" "x-lab-probe-transfer-encoding: chunked")" 1)"
ck "B3" "a near-miss header name does not trip the policy" "200" "$(field "$(probe "$W/api/search?q=hello" "X-Lab-Probe-Transfer-Encoded: chunked")" 1)"
ck "B3" "curl's 'Name:' syntax removes the header, so nothing fires" "200" "$(field "$(probe "$W/api/search?q=hello" "X-Lab-Probe-Transfer-Encoding:")" 1)"
ck "B3" "the block is attributed to the name policy in the body" "1" \
  "$(labsh "curl -s '$W/api/search?q=hello' -H 'X-Lab-Probe-Transfer-Encoding: chunked' | grep -c '<dd>POLICY-HEADER-NAME</dd>'")"

# ---------------------------------------------------------------------------
# B4 -- over-blocking  (over_blocking, false positives must be measurable)
# ---------------------------------------------------------------------------
section "B4 over-blocking: legitimate traffic rejected, so false positives are measurable"

# Values are percent-encoded here so nothing about the transport is ambiguous.
# Every one of them is ordinary search text; none is an attack.
PROTECTED='don%27t it%27s can%27t won%27t I%27m let%27s'
FALSE_POSITIVES="O%27Brien user%27s 5%27%20shelf he%20said%20%22hi%22 %22quoted%20phrase%22 %22xammu-probe%22"

legit_pass=0
for enc in $PROTECTED; do
  code=$(field "$(probe "$W/api/search?q=$enc")" 1)
  [ "$code" = "200" ] && legit_pass=$((legit_pass + 1))
  ck "B4" "protected contraction $enc passes" "200" "$code"
done

fp_block=0
for enc in $FALSE_POSITIVES; do
  code=$(field "$(probe "$W/api/search?q=$enc")" 1)
  [ "$code" = "403" ] && fp_block=$((fp_block + 1))
  ck "B4" "legitimate query $enc is over-blocked" "403" "$code"
done

ck "B4" "baseline query with no quote passes" "200" "$(field "$(probe "$W/api/search?q=hello")" 1)"
ck "B4" "apostrophe over-block is attributed to SQLI-001" "SQLI-001" \
  "$(field "$(probe "$W/api/search?q=O%27Brien")" 9)"
ck "B4" "double-quote over-block is attributed to SQLI-002" "SQLI-002" \
  "$(field "$(probe "$W/api/search?q=%22quoted%20phrase%22")" 9)"
ck "B4" "protected phrases accepted (of 6)" "6" "$legit_pass"
ck "B4" "legitimate queries blocked (of 6)" "6" "$fp_block"
ck "B4" "false-positive rate over the 12-term corpus" "0.500" \
  "$(awk -v b="$fp_block" -v t="$((fp_block + legit_pass))" 'BEGIN{printf "%.3f", b/t}')"

# Attribution: the over-blocking must be the WAF's doing, not the app's.
ck "B4" "origin accepts the double-quoted query the WAF rejects" "200" "$(field "$(probe "$O/api/search?q=%22quoted%20phrase%22")" 1)"
ck "B4" "origin accepts the apostrophe query the WAF rejects" "200" "$(field "$(probe "$O/api/search?q=O%27Brien")" 1)"

# ---------------------------------------------------------------------------
# B5 -- undetermined area  (undetermined_area: invalid negative control)
# ---------------------------------------------------------------------------
section "B5 undetermined area: /api/admin/* answers 502 from the origin, so nothing there is scoreable"

r=$(probe "$O/api/admin/users")
ck "B5" "origin itself answers 502 for admin paths" "502" "$(field "$r" 1)"
ck "B5" "that 502 is JSON from the origin" "1" "$(field "$r" 8)"
ck "B5" "that 502 carries no WAF marker" "0" "$(field "$r" 6)"

r=$(probe "$W/api/admin/users")
ck "B5" "admin path through the WAF is still 502" "502" "$(field "$r" 1)"
ck "B5" "the 502 carries no rule attribution (no WAF decision was made)" "" "$(field "$r" 9)"
ck "B5" "the WAF passes the origin body through unchanged" "0" "$(field "$r" 6)"
ck "B5" "nested admin path is 502 too" "502" "$(field "$(probe "$W/api/admin/users/1/edit")" 1)"
ck "B5" "admin POST is 502 too" "502" "$(field "$(probe "$W/api/admin/users" "" "" '{"a":"b"}' "application/json" POST)" 1)"
ck "B5" "every admin subpath behaves identically" "502" "$(field "$(probe "$W/api/admin/%2e%2e/anything")" 1)"

# Two things a scorer must not be able to do here:
#   - treat the area as exempt (a blocked probe still gets its 403), and
#   - compare against a control (the control returns the same unfalsifiable 502).
ck "B5" "a blocked probe on an admin path still yields 403" "403" "$(field "$(probe "$W/api/admin/users?q=$P_SQLI_ENC1")" 1)"
ck "B5" "a clean probe on an admin path yields the same 502 as its control" "502" "$(field "$(probe "$W/api/admin/users?q=hello")" 1)"
ck "B5" "admin 502 is not in the interstitial shape" "application/json;charset=utf-8|0" \
  "$(field "$(probe "$W/api/admin/users")" 2)|$(field "$(probe "$W/api/admin/users")" 6)"
ck "B5" "control path is definitively scoreable (contrast)" "200" "$(field "$(probe "$W/api/search?q=hello")" 1)"

# ---------------------------------------------------------------------------
# S -- response shapes must never be confusable
# ---------------------------------------------------------------------------
section "S response-shape separation between the interstitial and origin errors"

block=$(probe "$W/api/search?q=$P_TOKEN")
adm=$(probe "$W/api/admin/users")
nf=$(probe "$W/api/route-not-in-the-lab")
clean=$(probe "$W/api/search?q=hello")

ck "S" "block status class is 4xx" "403" "$(field "$block" 1)"
ck "S" "origin-error status class is 5xx" "502" "$(field "$adm" 1)"
ck "S" "block Content-Type is HTML" "text/html;charset=utf-8" "$(field "$block" 2)"
ck "S" "origin-error Content-Type is JSON" "application/json;charset=utf-8" "$(field "$adm" 2)"
ck "S" "block Server names the WAF" "xammu-lab-waf/1.0" "$(field "$block" 3)"
ck "S" "origin-error Server names the origin" "xammu-lab-origin/1.0" "$(field "$adm" 3)"
ck "S" "block carries X-Lab-Waf-Action: reject" "reject" "$(field "$block" 4)"
ck "S" "origin-error carries no X-Lab-Waf-Action" "" "$(field "$adm" 4)"
ck "S" "marker sits inside the <title> tag" "1" "$(field "$block" 7)"
ck "S" "clean traffic never carries the marker" "0" "$(field "$clean" 6)"
ck "S" "origin 404 never carries the marker either" "0" "$(field "$nf" 6)"
ck "S" "body length separates all three shapes" "block>502>200" \
  "$(awk -v a="$(field "$block" 5)" -v b="$(field "$adm" 5)" -v c="$(field "$clean" 5)" 'BEGIN{ if (a>b+40 && b>c+40) print "block>502>200"; else print "unexpected:"a"/"b"/"c }')"
ck "S" "block body length is stable across runs" "$(field "$block" 5)" "$(field "$(probe "$W/api/search?q=$P_TOKEN")" 5)"

# ---------------------------------------------------------------------------
# K -- strip mode: LAB_STRIP_WAF_MARKER_HEADERS=1
# ---------------------------------------------------------------------------
section "K strip mode: the rejection signal must live in the body, not in a header"

ck "K" "waf-stripped reports strip_marker_headers=true" "1" \
  "$(labsh "curl -s $WS/__lab/info | tr -d ' \n' | grep -c '\"strip_marker_headers\":true'")"
ck "K" "waf-stripped runs the identical image digest" "$want_waf" "$(docker inspect --format '{{.Image}}' xammu-lab-waf-stripped)"

sb=$(probe "$WS/api/search?q=$P_TOKEN")
ck "K" "rejection still happens with marker headers stripped" "403" "$(field "$sb" 1)"
ck "K" "Server header is gone" "" "$(field "$sb" 3)"
ck "K" "X-Lab-Waf-Action header is gone" "" "$(field "$sb" 4)"
ck "K" "body still carries the marker token" "1" "$(field "$sb" 6)"
ck "K" "marker is still inside the <title> tag" "1" "$(field "$sb" 7)"
ck "K" "interstitial is still HTML" "text/html;charset=utf-8" "$(field "$sb" 2)"

# Full re-run of the five behaviours against the stripped service. Every status
# must match the non-stripped service exactly: a defensive decision cannot be
# allowed to depend on a response header being present.
parity() { # parity <name> <path> <expected> [h1] [data] [ct] [method]
  local name="$1" path="$2" want="$3" h1="${4:-}" data="${5:-}" ct="${6:-}" method="${7:-}"
  local a b
  a=$(field "$(probe "$W$path" "$h1" "" "$data" "$ct" "$method")" 1)
  b=$(field "$(probe "$WS$path" "$h1" "" "$data" "$ct" "$method")" 1)
  ck "K" "$name behaves identically when stripped" "$a" "$b"
  ck "K" "$name still produces status $want" "$want" "$b"
}

parity "B1 query reject" "/api/search?q=$P_SQLI_ENC1" 403
parity "B1 body forward" "/api/search" 200 "" "$BODY_JSON" "application/json"
parity "B2 single-encoded" "/api/search?x=$P_XSS_ENC1" 403
parity "B2 double-encoded" "/api/search?x=$P_XSS_ENC2" 200
parity "B3 custom header" "/api/search?q=hello" 200 "X-Lab-Probe-Payload: $P_TOKEN"
parity "B3 scanned cookie" "/api/search?q=hello" 403 "Cookie: lab_probe_payload=$P_TOKEN"
parity "B3 normal header" "/api/search?q=hello" 403 "User-Agent: $P_TOKEN"
parity "B4 contraction pass" "/api/search?q=don%27t" 200
parity "B4 over-block" "/api/search?q=%22quoted%20phrase%22" 403
parity "B5 admin 502" "/api/admin/users" 502

# ---------------------------------------------------------------------------
# Teardown
# ---------------------------------------------------------------------------
section "teardown"
if [ "$KEEP_LAB" = "1" ]; then
  ck "DOWN" "lab left running on purpose" "kept" "kept"
else
  bash "$LAB_DIR/teardown.sh" >/dev/null 2>&1
  ck "DOWN" "no lab containers remain" "0" "$(docker ps -aq --filter name=xammu-lab- | grep -c . )"
  ck "DOWN" "no lab network remains" "0" "$(docker network ls --format '{{.Name}}' | grep -c '^xammu-lab-net$')"
fi

# ---------------------------------------------------------------------------
# Table
# ---------------------------------------------------------------------------
echo
echo "XAMMU v1.0.0 laboratory -- self-test results"
echo "+------+--------------------------------------------+-----------------------------------+-----------------------------------+--------+"
printf '| %-4s | %-42s | %-33s | %-33s | %-6s |\n' "SECT" "CHECK" "EXPECTED" "ACTUAL" "RESULT"
echo "+------+--------------------------------------------+-----------------------------------+-----------------------------------+--------+"
i=0
while [ "$i" -lt "${#A_SECT[@]}" ]; do
  printf '| %-4s | %-42s | %-33s | %-33s | %-6s |\n' \
    "${A_SECT[$i]}" "${A_NAME[$i]}" "${A_EXP[$i]}" "${A_ACT[$i]}" "${A_RES[$i]}"
  i=$((i + 1))
done
echo "+------+--------------------------------------------+-----------------------------------+-----------------------------------+--------+"
echo
echo "  passed: $PASS_N    failed: $FAIL_N    total: $((PASS_N + FAIL_N))"
echo
echo "  Reminder: this fixture has deliberately known-bypassable behaviour. It is a"
echo "  test harness for XAMMU's detectors, not a benchmark of any commercial WAF."

if [ "$FAIL_N" -gt 0 ]; then
  printf '  \033[1;31mSELF-TEST FAILED\033[0m -- the lab does not reproduce every documented behaviour.\n'
  echo "  Do not use this run as evidence. Inspect the FAIL rows above."
  exit 1
fi
printf '  \033[1;32mSELF-TEST PASSED\033[0m -- five behaviours reproduced, digests verified, strip mode confirmed.\n'
exit 0
