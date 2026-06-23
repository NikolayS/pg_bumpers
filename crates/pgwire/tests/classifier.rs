//! Read-only classifier acceptance tests (SPEC §4, §7 S1).
//!
//! The classifier is advisory + **fail-closed**: SELECT/read-only-CTE → read;
//! writes/DDL/utility/COPY/volatile → not-read; statement-stacking
//! (`SELECT 1; DROP SCHEMA public`) → not a single read; a parse error →
//! not-read.

use pgb_pgwire::classifier::{Classification, NotReadReason, classify, classify_with_reason};

fn assert_read(sql: &str) {
    assert_eq!(
        classify(sql),
        Classification::Read,
        "expected READ for: {sql}"
    );
}

fn assert_not_read(sql: &str) {
    assert_eq!(
        classify(sql),
        Classification::NotRead,
        "expected NOT-READ for: {sql}"
    );
}

#[test]
fn selects_are_read() {
    assert_read("SELECT 1");
    assert_read("SELECT * FROM accounts WHERE id = 42");
    assert_read("SELECT a, b FROM t JOIN u ON t.id = u.id WHERE u.x > 0 ORDER BY a LIMIT 10");
    assert_read("SELECT count(*) FROM events");
    assert_read("SELECT * FROM (SELECT id FROM t WHERE id < 10) sub");
    assert_read("VALUES (1), (2), (3)");
    assert_read("SELECT 1 UNION SELECT 2");
}

#[test]
fn read_only_cte_is_read() {
    assert_read(
        "WITH recent AS (SELECT id FROM events WHERE ts > now() - interval '1 day') \
         SELECT count(*) FROM recent",
    );
}

#[test]
fn writes_are_not_read() {
    assert_not_read("INSERT INTO t (a) VALUES (1)");
    assert_not_read("UPDATE t SET a = 1 WHERE id = 2");
    assert_not_read("DELETE FROM t WHERE id = 2");
    assert_not_read("INSERT INTO t (a) VALUES (1) RETURNING id");
    assert_not_read("UPDATE t SET a = a + 1 RETURNING a");
}

#[test]
fn ddl_and_utility_are_not_read() {
    assert_not_read("CREATE TABLE t (id int)");
    assert_not_read("DROP TABLE t");
    assert_not_read("DROP SCHEMA public CASCADE");
    assert_not_read("ALTER TABLE t ADD COLUMN c int");
    assert_not_read("TRUNCATE t");
    assert_not_read("CREATE INDEX idx ON t (a)");
    assert_not_read("CREATE VIEW v AS SELECT 1");
}

#[test]
fn copy_is_not_read() {
    assert_not_read("COPY t TO STDOUT");
    assert_not_read("COPY t FROM STDIN");
    assert_not_read("COPY t TO PROGRAM 'cat'");
}

#[test]
fn data_modifying_cte_is_not_read() {
    // The classic exfil/destroy-via-CTE: a write hidden in a WITH clause must
    // never classify as a read.
    assert_not_read("WITH d AS (DELETE FROM t WHERE id = 1 RETURNING *) SELECT * FROM d");
    assert_not_read("WITH i AS (INSERT INTO log (msg) VALUES ('x') RETURNING id) SELECT * FROM i");
}

#[test]
fn select_into_is_not_read() {
    // SELECT ... INTO creates a table — a write.
    assert_not_read("SELECT * INTO new_t FROM t");
}

#[test]
fn statement_stacking_is_not_a_single_read() {
    // The headline bypass: a leading harmless SELECT followed by a destructive
    // statement must be flagged as multiple statements (not a single read).
    let (cls, reason) = classify_with_reason("SELECT 1; DROP SCHEMA public");
    assert_eq!(cls, Classification::NotRead);
    assert_eq!(reason, Some(NotReadReason::MultipleStatements));

    // Even two SELECTs stacked is not a single read.
    let (cls, reason) = classify_with_reason("SELECT 1; SELECT 2");
    assert_eq!(cls, Classification::NotRead);
    assert_eq!(reason, Some(NotReadReason::MultipleStatements));

    // Trailing semicolon on a single statement is still a single read.
    assert_eq!(classify("SELECT 1;"), Classification::Read);
}

#[test]
fn parse_error_is_not_read_fail_closed() {
    let (cls, reason) = classify_with_reason("SELEKT 1 FROM");
    assert_eq!(cls, Classification::NotRead);
    assert_eq!(reason, Some(NotReadReason::ParseError));

    let (cls, reason) = classify_with_reason("this is not sql at all !!!");
    assert_eq!(cls, Classification::NotRead);
    assert_eq!(reason, Some(NotReadReason::ParseError));
}

#[test]
fn empty_input_is_not_read() {
    let (cls, reason) = classify_with_reason("");
    assert_eq!(cls, Classification::NotRead);
    assert_eq!(reason, Some(NotReadReason::Empty));

    let (cls, reason) = classify_with_reason("   -- just a comment\n");
    assert_eq!(cls, Classification::NotRead);
    assert_eq!(reason, Some(NotReadReason::Empty));
}

/// Comment-boundary fidelity with PostgreSQL — the root-cause evidence for the
/// classifier-fuzz-oracle false positive.
///
/// The classifier is byte-for-byte faithful to PostgreSQL's lexer on where a
/// `--` line comment ends: ONLY a newline (`\n`) or carriage return (`\r`)
/// terminates it. A control byte such as `\x05` does NOT end the comment, so
/// everything after `--` (up to the next newline / end of input) is commented
/// out — including a `;`-separated statement appended after it. This is
/// *correct*, fail-closed behavior; the fuzz oracle's old `format!("{base} ; …")`
/// construction wrongly assumed the appended write always became a second
/// statement. These tests pin the classifier behavior so the (unchanged,
/// PG-faithful) classifier cannot silently drift.
#[test]
fn unterminated_line_comment_swallows_appended_text_like_postgres() {
    // The exact bytes that tripped the old fuzz oracle: a complete read whose
    // trailing `-- …\x05` comment runs to end-of-input. This is a single read.
    assert_read("VALUES (1)--\u{05}");

    // Appending `; CREATE TABLE …` after the unterminated comment changes
    // nothing: the whole tail is inside the `--` comment, so it stays a single
    // read — exactly as PostgreSQL would parse it. (This is why the old oracle
    // false-fired; the classifier is right.)
    assert_read("VALUES (1)--\u{05} ; CREATE TABLE t (id int)");

    // A control byte mid-comment does not terminate it either.
    assert_read("SELECT 1 -- note\u{05} still a comment");
}

#[test]
fn newline_terminates_line_comment_restoring_the_stack() {
    // The moment a real newline ends the `--` comment, the appended statement
    // becomes a genuine SECOND statement — caught as statement-stacking. This is
    // the newline the fixed fuzz oracle inserts before `;`.
    let (cls, reason) = classify_with_reason("VALUES (1)--\u{05}\n; CREATE TABLE t (id int)");
    assert_eq!(cls, Classification::NotRead);
    assert_eq!(reason, Some(NotReadReason::MultipleStatements));

    // A carriage return ends a `--` comment too.
    assert_not_read("SELECT 1 -- c\r; DROP TABLE x");
}

#[test]
fn open_block_comment_string_and_dollar_quote_are_not_a_clean_read() {
    // An unterminated `/* … */` block comment, an open string literal, and an
    // open dollar-quote all fail to parse (run past end-of-input) and are
    // fail-closed NOT-READ — so they are never a clean single read that a
    // stacked-write oracle could build on.
    assert_not_read("SELECT 1 /* open block comment");
    assert_not_read("SELECT 'open string literal");
    assert_not_read("SELECT $$open dollar quote");

    // Appending a `;`-stacked write to any of them stays NOT-READ (the open
    // token swallows it / it still fails to parse) — never a Read.
    assert_not_read("SELECT 1 /* open\n; CREATE TABLE t (id int)");
    assert_not_read("SELECT 'open\n; DROP TABLE x");
    assert_not_read("SELECT $$open\n; DELETE FROM accounts");
}
