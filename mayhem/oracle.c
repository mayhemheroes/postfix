/*
 * postfix/mayhem/oracle.c — golden known-answer oracle over the FUZZED parse path.
 *
 * Postfix's own `make tests` needs a running MTA (queue dirs, master, postdrop privs), so it can't
 * run inside the commit image. Instead this is a small self-contained oracle that links the SAME
 * static libraries the fuzz harnesses link (libglobal.a + libutil.a) and asserts known-answer
 * results of the two fuzzed parsers:
 *
 *   tok822_parse_limit / tok822_internalize  — the RFC 822 address tokenizer (fuzz_tok822)
 *   is_header_buf                              — the message-header predicate on the mime path
 *
 * Each case asserts a BYTE/VALUE-EXACT expectation, so a no-op or "return 0" patch to the parser
 * changes the answer and fails the oracle (PATCH-grade, not a no-op stub). Prints one line per case;
 * main() returns the number of failures (0 == all pass) so test.sh can map it to CTRF.
 */
#include <sys_defs.h>
#include <stdio.h>
#include <string.h>

#include <vstring.h>
#include "lex_822.h"
#include "quote_822_local.h"
#include "tok822.h"
#include "is_header.h"

static int failures = 0;
static int total = 0;

static void check_str(const char *name, const char *got, const char *want)
{
    total++;
    if (got != 0 && strcmp(got, want) == 0) {
        printf("PASS %s\n", name);
    } else {
        printf("FAIL %s: got [%s] want [%s]\n", name, got ? got : "(null)", want);
        failures++;
    }
}

static void check_int(const char *name, long got, long want)
{
    total++;
    if (got == want) {
        printf("PASS %s (=%ld)\n", name, got);
    } else {
        printf("FAIL %s: got %ld want %ld\n", name, got, want);
        failures++;
    }
}

/* Parse an address string and return its internalized form (canonical token text). */
static char *internalize(VSTRING *vp, const char *in)
{
    TOK822 *list = tok822_parse_limit(in, 10);
    tok822_internalize(vp, list, TOK822_STR_DEFL);
    tok822_free_tree(list);
    return vstring_str(vp);
}

int main(void)
{
    VSTRING *vp = vstring_alloc(100);

    /* ---- tok822 address tokenizer (the fuzz_tok822 path) ---- */
    /* A plain mailbox round-trips unchanged. */
    check_str("tok822/plain", internalize(vp, "john@example.com"), "john@example.com");

    /* A display-name + angle-addr internalizes to the bare addr-spec inside <>. */
    check_str("tok822/angle", internalize(vp, "John Doe <john@example.com>"),
              "John Doe <john@example.com>");

    /* Comments are tokenized; the canonical form keeps the comment text in parens. */
    check_str("tok822/comment", internalize(vp, "a@b.c (hi)"), "a@b.c (hi)");

    /* A malformed/truncated address must NOT crash and yields a stable canonical string. */
    check_str("tok822/trailing_at", internalize(vp, "user@"), "user@");

    /* ---- is_header predicate (the mime header path) ---- */
    /* "Subject:" is a valid header start -> returns the length of the label up to the colon. */
    check_int("is_header/valid", is_header("Subject: hi"), (long) strlen("Subject"));

    /* A leading space is NOT a header (it's a body/continuation line) -> 0. */
    check_int("is_header/leading_space", is_header(" not a header"), 0);

    /* A line with no colon and a control char is not a header -> 0. */
    check_int("is_header/no_colon", is_header("just text"), 0);

    /* Content-Type is a valid header label. */
    check_int("is_header/content_type", is_header("Content-Type: text/plain"),
              (long) strlen("Content-Type"));

    vstring_free(vp);

    printf("ORACLE total=%d passed=%d failed=%d\n", total, total - failures, failures);
    return failures;
}
