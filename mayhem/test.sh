#!/usr/bin/env bash
#
# hpn-ssh/mayhem/test.sh — RUN the sshkey golden oracle (built by mayhem/build.sh) and emit a CTRF
# summary. exit 0 iff every oracle case passed.
#
# ORACLE path (NOT the upstream regress suite): hpn-ssh's regress/ suite needs a running sshd +
# loopback networking, which is unavailable at image-build time. Instead we run a self-contained
# known-answer oracle (mayhem/harnesses/sshkey_oracle.c) over the SAME sshkey parser surface that
# pubkey_fuzz fuzzes: it parses real ed25519/ecdsa/rsa public keys and asserts the discriminated
# type + bit length, and asserts that malformed input is REJECTED. A no-op / "accept everything"
# change to the parser cannot pass it. This script only RUNS the pre-built binary; it never compiles.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
cd "$SRC"

ORACLE="$SRC/mayhem-oracle"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

if [ ! -x "$ORACLE" ]; then
  echo "missing $ORACLE — run mayhem/build.sh first" >&2
  emit_ctrf "sshkey-oracle" 0 1 0; exit 2
fi

echo "=== running sshkey golden oracle ==="
out="$("$ORACLE" "$SRC" 2>&1)"; rc=$?
echo "$out"

# Parse the TAP-ish output: count "ok   - " and "FAIL - " lines.
PASSED=$(printf '%s\n' "$out" | grep -c '^ok   - ')
FAILED=$(printf '%s\n' "$out" | grep -c '^FAIL - ')
: "${PASSED:=0}" "${FAILED:=0}"

if [ "$(( PASSED + FAILED ))" -eq 0 ]; then
  echo "could not parse oracle output; using exit code $rc" >&2
  [ "$rc" -eq 0 ] && { emit_ctrf "sshkey-oracle" 1 0 0; exit 0; }
  emit_ctrf "sshkey-oracle" 0 1 0; exit 1
fi

# Belt-and-braces: a non-zero oracle exit with no parsed failures still counts as a failure.
if [ "$rc" -ne 0 ] && [ "$FAILED" -eq 0 ]; then FAILED=1; fi

emit_ctrf "sshkey-oracle" "$PASSED" "$FAILED" 0
