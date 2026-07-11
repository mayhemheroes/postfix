#!/usr/bin/env bash
#
# postfix/mayhem/test.sh — PATCH-grade functional oracle over the FUZZED parse path.
#
# Postfix's upstream `make tests` requires a live MTA (queue spool, master daemon, postdrop set-gid
# privileges) and cannot run in the commit image. Instead we compile mayhem/oracle.c against the
# SAME static libs the fuzzers link (postfix/lib/libglobal.a + libutil.a) and run a set of
# known-answer assertions on the tok822 address tokenizer and the is_header message-header predicate
# — the exact code paths fuzz_tok822 / fuzz_mime drive. Each case asserts a value-exact result, so a
# no-op / "return 0" patch to those parsers changes the answer and fails the suite. Emits a CTRF
# (ctrf.io) summary; exits non-zero iff a case failed.
#
# The postfix static libs were compiled WITH ASan+UBSan+SanitizerCoverage (so the fuzzed parsers are
# instrumented), so the oracle MUST link the matching sanitizer runtime — otherwise the asan/sancov
# symbols are unresolved. We link -fsanitize=address,undefined (the runtime) but NOT
# -fsanitize=fuzzer-no-link, and disable leak detection (the oracle intentionally doesn't free every
# token list); sanitizers only abort on real UB/overflow and never change a parse result, so this
# stays an honest known-answer patch oracle.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

PF="${SRC:-/mayhem}/postfix"
MAYHEM="${SRC:-/mayhem}/mayhem"
CC_BIN="${CC:-clang}"
BIN=/tmp/postfix_oracle

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-${SRC:-/mayhem}/ctrf-report.json}" <<JSON
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

if [ ! -f "$PF/lib/libglobal.a" ] || [ ! -f "$PF/lib/libutil.a" ]; then
  echo "missing postfix static libs — run mayhem/build.sh first" >&2
  emit_ctrf "postfix-oracle" 0 1 0; exit 2
fi

echo "=== compiling oracle.c against libglobal/libutil (asan/ubsan runtime, no fuzzer) ==="
# Link the ASan+UBSan runtime to satisfy the instrumented libs; do NOT pull in libFuzzer.
if ! env -u CFLAGS -u CXXFLAGS \
     "$CC_BIN" -O -g -fsanitize=address,undefined -fno-omit-frame-pointer \
       -DHAS_DEV_URANDOM -DSNAPSHOT -UUSE_DYNAMIC_LIBS -DDEF_SHLIB_DIR='"no"' \
       -UUSE_DYNAMIC_MAPS -DNO_EAI -DDEF_SMTPUTF8_ENABLE='"no"' \
       -DLINUX4 -Wno-comment -fno-common \
       -I"$PF/src/global" -I"$PF/include" \
       "$MAYHEM/oracle.c" "$PF/lib/libglobal.a" "$PF/lib/libutil.a" -ldb -lm -lpthread \
       -o "$BIN" 2>/tmp/oracle-build.log; then
  echo "oracle compile failed:" >&2; cat /tmp/oracle-build.log >&2
  emit_ctrf "postfix-oracle" 0 1 0; exit 2
fi

echo "=== running oracle ==="
# detect_leaks=0: the oracle is a known-answer check, not a leak check; the libs leak token lists.
out="$(ASAN_OPTIONS=detect_leaks=0 "$BIN")"; rc=$?
echo "$out"

PASSED=$(printf '%s\n' "$out" | grep -c '^PASS ')
FAILED=$(printf '%s\n' "$out" | grep -c '^FAIL ')
: "${PASSED:=0}" "${FAILED:=0}"

# Cross-check the program's own exit code (= failure count) against the parsed PASS/FAIL lines.
if [ "$rc" -ne "$FAILED" ]; then
  echo "WARN: oracle exit code ($rc) != parsed FAIL count ($FAILED)" >&2
  [ "$rc" -ne 0 ] && FAILED=$(( FAILED > rc ? FAILED : rc ))
fi

emit_ctrf "postfix-oracle" "$PASSED" "$FAILED"
