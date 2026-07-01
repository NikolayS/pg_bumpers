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

// -------------------------------------------------------------------------
// M2a (#114): the read-only classifier fail-closes on NON-ALLOWLISTED function
// calls. Before M2a the classifier was projection-blind — it inspected only the
// statement KIND + FROM/CTE table factors, never the projection/WHERE/etc.
// EXPRESSIONS — so a `SELECT lo_create(0)` / `SELECT setval(...)` /
// `SELECT public.writing_fn()` classified as Read → Allow and the proxy forwarded
// the write to the backend. Now a SELECT is Read ONLY IF every function it
// references (anywhere in the AST) is on the curated read-safe allowlist;
// otherwise NotRead → the proxy floor Blocks it. These are the RED tests.
// -------------------------------------------------------------------------

#[test]
fn select_of_a_non_allowlisted_write_function_is_not_read() {
    // Large-object writers — the catastrophic-FN class (KNOWN_DANGERS B-lo).
    assert_not_read("SELECT lo_create(0)");
    assert_not_read("SELECT lo_creat(-1)");
    assert_not_read("SELECT lowrite(0, 'x')");
    assert_not_read("SELECT lo_from_bytea(0, '\\x00'::bytea)");
    assert_not_read("SELECT lo_truncate(0, 0)");
    assert_not_read("SELECT lo_truncate64(0, 0)");
    assert_not_read("SELECT lo_unlink(0)");
    assert_not_read("SELECT lo_import('/etc/passwd')");
    assert_not_read("SELECT lo_export(0, '/tmp/x')");
    // Sequence mutators.
    assert_not_read("SELECT setval('s', 1)");
    assert_not_read("SELECT nextval('s')");
    // Server-side file/dir readers (exfiltration side-channels).
    assert_not_read("SELECT pg_read_file('/etc/passwd')");
    assert_not_read("SELECT pg_read_binary_file('/etc/passwd')");
    assert_not_read("SELECT pg_stat_file('/etc/passwd')");
    assert_not_read("SELECT pg_ls_dir('/')");
    // Sleep / dblink / and any pg_* not on the allowlist.
    assert_not_read("SELECT pg_sleep(5)");
    assert_not_read("SELECT dblink('dbname=x', 'DELETE FROM t')");
    assert_not_read("SELECT pg_terminate_backend(1)");
}

#[test]
fn select_of_a_user_or_qualified_function_is_not_read_fail_closed() {
    // Any user/unknown/qualified schema.fn() — incl. a SECURITY DEFINER write fn
    // that could be mislabeled STABLE — is NOT on the allowlist → NotRead.
    assert_not_read("SELECT public.writing_fn()");
    assert_not_read("SELECT public.some_security_definer_write_fn()");
    assert_not_read("SELECT my_writing_fn(1, 2)");
    assert_not_read("SELECT app.do_the_thing()");
    // Even a name that *collides* with an allowlisted built-in becomes NotRead once
    // it is schema-qualified (it is no longer the trusted built-in): fail-closed.
    assert_not_read("SELECT public.count(x) FROM t");
}

#[test]
fn write_function_hidden_in_a_nested_call_is_not_read() {
    // A write nested as an ARGUMENT to another (even allowlisted) call must still
    // be caught — the scan walks function arguments recursively.
    assert_not_read("SELECT lo_put(lo_create(0), 0, 'x')");
    assert_not_read("SELECT length(pg_read_file('/etc/passwd'))");
    assert_not_read("SELECT coalesce(setval('s', 1), 0)");
    assert_not_read("SELECT count(*) FROM t WHERE id = nextval('s')");
}

#[test]
fn write_function_hidden_in_where_group_order_having_is_not_read() {
    assert_not_read("SELECT * FROM t WHERE public.writing_fn()");
    assert_not_read("SELECT * FROM t WHERE setval('s', 1) > 0");
    assert_not_read("SELECT a FROM t GROUP BY a HAVING sum(nextval('s')) > 0");
    assert_not_read("SELECT a FROM t ORDER BY lo_create(0)");
    assert_not_read("SELECT a FROM t JOIN u ON writing_fn(t.id) = u.id");
    // In an aggregate's FILTER/ORDER-BY clause.
    assert_not_read("SELECT sum(x) FILTER (WHERE setval('s', 1) > 0) FROM t");
    assert_not_read("SELECT array_agg(x ORDER BY nextval('s')) FROM t");
}

#[test]
fn write_function_hidden_in_cte_or_subquery_is_not_read() {
    // The exfil/destroy-via-CTE / correlated-subquery shape — the scan descends
    // into WITH bodies and nested subqueries.
    assert_not_read("WITH w AS (SELECT lo_create(0)) SELECT * FROM w");
    assert_not_read("SELECT (SELECT setval('s', 1))");
    assert_not_read("SELECT * FROM t WHERE id IN (SELECT nextval('s'))");
    assert_not_read("SELECT * FROM (SELECT lo_create(0)) AS sub");
}

#[test]
fn table_valued_write_function_in_the_from_clause_is_not_read() {
    // Table-valued function calls in FROM/JOIN are NOT `Expr::Function` nodes —
    // they are table factors with args — so they need their own allowlist check.
    // A plain table read (`FROM t`) has no args and stays Read; a table-fn call
    // whose name is non-allowlisted is NotRead.
    assert_not_read("SELECT * FROM my_writing_table_fn(1)");
    assert_not_read("SELECT * FROM lo_import('/etc/passwd')");
    assert_not_read("SELECT * FROM t JOIN dblink('x', 'y') u ON true");
    // A write nested inside a table-fn's args is also caught.
    assert_not_read("SELECT * FROM generate_series(1, lo_create(0))");
}

#[test]
fn explain_of_a_function_call_write_is_not_read() {
    // The explain-hole must not reopen for the function-call write class: an
    // EXPLAIN whose inner read references a non-allowlisted function is NotRead
    // (the scan descends into the EXPLAIN's inner statement). A plan-only EXPLAIN
    // of an allowlisted read stays Read so `explain_plan` keeps working.
    assert_not_read("EXPLAIN SELECT lo_create(0)");
    assert_not_read("EXPLAIN (FORMAT JSON) SELECT public.writing_fn()");
    assert_not_read("EXPLAIN SELECT setval('s', 1)");
    assert_read("EXPLAIN SELECT count(*) FROM t");
    assert_read("EXPLAIN (FORMAT JSON) SELECT now()");
}

#[test]
fn select_of_allowlisted_read_functions_is_read() {
    // The legitimate read built-ins the agent needs — these must stay Read.
    assert_read("SELECT count(*) FROM t");
    assert_read("SELECT max(x), min(x), sum(x), avg(x) FROM t");
    assert_read("SELECT array_agg(x), string_agg(name, ','), jsonb_agg(x) FROM t");
    assert_read("SELECT now()");
    assert_read("SELECT current_timestamp, current_date, current_setting('search_path')");
    assert_read("SELECT date_trunc('day', ts), extract(year FROM ts), age(ts) FROM t");
    assert_read("SELECT jsonb_build_object('a', 1), json_build_array(1, 2)");
    assert_read("SELECT * FROM t WHERE lower(name) = $1");
    assert_read("SELECT upper(name), length(name), trim(name), substr(name, 1, 3) FROM t");
    assert_read("SELECT coalesce(a, 0), nullif(a, b), greatest(a, b), least(a, b) FROM t");
    assert_read("SELECT concat(a, b), replace(a, 'x', 'y') FROM t");
    // Table-valued read functions the tests / agent use.
    assert_read("SELECT * FROM generate_series(1, 5) g");
    // Nested allowlisted calls stay Read.
    assert_read("SELECT count(distinct lower(name)) FROM t");
    assert_read("SELECT max(length(name)) FROM t WHERE upper(name) LIKE 'A%'");
}

// -------------------------------------------------------------------------
// M2a fix round (#115): three more side-effect classes a SELECT could smuggle
// past the projection-blind-era gate, each found by an adversarial run of the
// real classifier. All must fail-closed to NotRead; the corresponding built-in
// (side-effect-free) forms must stay Read.
// -------------------------------------------------------------------------

#[test]
fn qualified_or_custom_operator_is_not_read() {
    // FIX 1 (HIGH): `SELECT a OPERATOR(public.writeop) b` parses to
    // `Expr::BinaryOp { op: PGCustomBinaryOperator([...]) }` — NOT an
    // `Expr::Function` — so the function sweep never saw it. A schema-qualified /
    // custom operator invokes an ARBITRARY backing function (incl. a SECURITY
    // DEFINER write). Fail-closed in EVERY expression position.
    assert_not_read("SELECT a OPERATOR(public.writeop) b FROM t");
    assert_not_read("SELECT * FROM t WHERE a OPERATOR(public.wop) b");
    assert_not_read("SELECT a FROM t GROUP BY a HAVING count(*) OPERATOR(public.wop) 0");
    assert_not_read("SELECT a FROM t ORDER BY a OPERATOR(public.wop) b");
    assert_not_read("WITH w AS (SELECT a OPERATOR(public.wop) b AS c FROM t) SELECT * FROM w");
    assert_not_read("SELECT (SELECT a OPERATOR(public.wop) b FROM t)");
    assert_not_read("SELECT * FROM generate_series(1, 1 OPERATOR(public.wop) 2)");
    // The PREFIX form `OPERATOR(public.wop) b` parses as a Function named
    // `OPERATOR` (non-allowlisted) — already NotRead; pin it so it stays closed.
    assert_not_read("SELECT OPERATOR(public.wop) b FROM t");
}

#[test]
fn builtin_operators_stay_read_no_regression() {
    // FIX 1 guard: bare BUILT-IN operators are side-effect-free and MUST stay
    // Read — only the qualified/custom `OPERATOR(...)` form fails closed.
    assert_read("SELECT a + b");
    assert_read("SELECT a || b FROM t");
    assert_read("SELECT a = b");
    assert_read("SELECT a - b, a * b, a / b, a % b FROM t");
    assert_read("SELECT a < b, a > b, a <= b, a >= b, a <> b FROM t");
    assert_read("SELECT a AND b, a OR b, NOT a FROM t");
    assert_read("SELECT a # b, a & b, a | b, a << b, a >> b FROM t");
    assert_read("SELECT name LIKE 'a%', name ILIKE 'a%' FROM t");
    assert_read("SELECT a IS NULL, a IS NOT NULL FROM t");
    // JSON/array/containment built-in operators.
    assert_read("SELECT jsonb_col ? 'k' FROM t");
    assert_read("SELECT a @> b, a <@ b, a && b FROM t");
    assert_read("SELECT j -> 'k', j ->> 'k', j #> '{a}', j #>> '{a}' FROM t");
    // Unary built-ins.
    assert_read("SELECT -b, +b, ~b FROM t");
}

#[test]
fn for_update_or_share_lock_is_not_read() {
    // FIX 2 (MEDIUM): `SELECT ... FOR UPDATE`/`FOR SHARE` acquire real row locks
    // on the primary (lock-DoS side effect), so they are NOT a pure read.
    // (`FOR NO KEY UPDATE` / `FOR KEY SHARE` do not parse under sqlparser's
    // PostgreSQL dialect and are already fail-closed NotRead via ParseError —
    // pinned here so the whole FOR-lock family stays closed.)
    assert_not_read("SELECT * FROM t FOR UPDATE");
    assert_not_read("SELECT * FROM t FOR SHARE");
    assert_not_read("SELECT * FROM t FOR NO KEY UPDATE");
    assert_not_read("SELECT * FROM t FOR KEY SHARE");
    assert_not_read("SELECT * FROM t FOR UPDATE OF t");
    assert_not_read("SELECT * FROM t FOR UPDATE NOWAIT");
    assert_not_read("SELECT * FROM t FOR UPDATE SKIP LOCKED");
    // A lock buried in a CTE body or subquery is still a lock on the primary.
    assert_not_read("WITH w AS (SELECT id FROM t FOR UPDATE) SELECT * FROM w");
    assert_not_read("SELECT * FROM (SELECT id FROM t FOR SHARE) sub");
    // A plain SELECT with no lock clause stays Read.
    assert_read("SELECT * FROM t");
    assert_read("SELECT id FROM t WHERE id = 1");
}

#[test]
fn cast_to_qualified_or_nonbuiltin_type_is_not_read() {
    // FIX 3 (LOW): `x::public.evil` / `CAST(x AS myschema.t)` invokes the user
    // type's input function (can side-effect). A schema-QUALIFIED cast target
    // fails closed; bare built-in casts stay Read. (Conservative: only the
    // qualified form fails closed, because sqlparser models some bare BUILTIN
    // types — `inet`, `citext` — as `DataType::Custom` too, so blocking all
    // Custom would over-block legitimate builtin reads.)
    assert_not_read("SELECT x::public.evil");
    assert_not_read("SELECT CAST(x AS myschema.t) FROM t");
    assert_not_read("SELECT x::pg_catalog.int4");
    assert_not_read("SELECT * FROM t WHERE x::public.evil = 1");
    assert_not_read("WITH w AS (SELECT x::public.evil AS y FROM t) SELECT * FROM w");
    // TRY_CAST and a chained cast whose FIRST hop is qualified are caught too.
    assert_not_read("SELECT TRY_CAST(x AS public.evil)");
    assert_not_read("SELECT x::public.evil::text");
    // ARRAY cast to a qualified type must NOT slip past the bare-node check —
    // `public.evil[]` nests the qualified `Custom` inside `DataType::Array`.
    assert_not_read("SELECT x::public.evil[]");
    assert_not_read("SELECT ARRAY[x]::public.evil[]");
    // Bare builtin casts stay Read.
    assert_read("SELECT x::int");
    assert_read("SELECT x::text");
    assert_read("SELECT x::timestamptz");
    assert_read("SELECT x::jsonb");
    assert_read("SELECT x::numeric");
    assert_read("SELECT CAST(x AS int) FROM t");
    assert_read("SELECT x::varchar(10)");
    // Builtin ARRAY casts stay Read (element type is a recognized builtin).
    assert_read("SELECT x::int[]");
    assert_read("SELECT x::text[]");
    // A bare (unqualified) user type — array or scalar — stays Read (the
    // conservative qualified-only policy; sqlparser models builtin inet/citext
    // as bare Custom, so we do not over-block bare).
    assert_read("SELECT x::citext");
    assert_read("SELECT x::inet");
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
fn explain_of_a_read_without_analyze_is_a_read() {
    // A plain EXPLAIN only PLANS — it never executes the inner statement — so an
    // EXPLAIN of a read is a read. This is what lets the agent's `explain_plan`
    // tool run THROUGH the proxy (the proxy permits the planned read).
    assert_read("EXPLAIN SELECT 1");
    assert_read("EXPLAIN (FORMAT JSON) SELECT * FROM accounts WHERE id = 1");
    assert_read("EXPLAIN VERBOSE SELECT a FROM t");
    assert_read("EXPLAIN (FORMAT JSON, VERBOSE) SELECT count(*) FROM events");
    // EXPLAIN of a read-only CTE is still a read.
    assert_read("EXPLAIN (FORMAT JSON) WITH r AS (SELECT 1 AS x) SELECT x FROM r");
}

#[test]
fn explain_analyze_executes_so_it_is_not_read() {
    // EXPLAIN ANALYZE actually RUNS the statement (side effects!), so it must NOT
    // be a read — in BOTH the bare and parenthesized forms.
    assert_not_read("EXPLAIN ANALYZE SELECT 1");
    assert_not_read("EXPLAIN (ANALYZE) SELECT 1");
    assert_not_read("EXPLAIN (ANALYZE, FORMAT JSON) SELECT * FROM accounts");
    assert_not_read("EXPLAIN ANALYZE VERBOSE SELECT 1");
}

#[test]
fn explain_analyse_british_spelling_executes_so_it_is_not_read() {
    // REGRESSION (REV bug-hunter, HIGH): `ANALYSE` is a *full* PostgreSQL synonym
    // for `ANALYZE` — live-proven on PG18.4 that `EXPLAIN (ANALYSE) …` EXECUTES:
    // it fires `SELECT bump()` side effects, MUTATES on UPDATE, and DELETEs rows.
    // It must therefore classify NOT-READ, exactly like the American spelling.
    // (Before the fix, the option-name check only matched `"analyze"`, so the
    // British spelling slipped through and classified as a Read.)
    assert_not_read("EXPLAIN (ANALYSE) SELECT 1");
    assert_not_read("EXPLAIN (ANALYSE) SELECT * FROM accounts WHERE id = 1");
    assert_not_read("EXPLAIN (analyse) SELECT 1"); // case-insensitive
    assert_not_read("EXPLAIN (ANALYSE) UPDATE t SET a = 1 WHERE id = 2");
    assert_not_read("EXPLAIN (ANALYSE) DELETE FROM t WHERE id = 1");
    // Mixed with an otherwise-plan-only option, the presence of ANALYSE still
    // executes (proven live) → not-read.
    assert_not_read("EXPLAIN (FORMAT JSON, ANALYSE) SELECT 1");
    assert_not_read("EXPLAIN (ANALYSE, BUFFERS) SELECT 1");
}

#[test]
fn explain_serialize_executes_so_it_is_not_read() {
    // SERIALIZE serializes the *result*, which requires RUNNING the plan — it
    // executes (and PG even rejects it without ANALYZE). Not plan-only → not-read.
    assert_not_read("EXPLAIN (SERIALIZE) SELECT 1");
    assert_not_read("EXPLAIN (SERIALIZE text) SELECT 1");
    assert_not_read("EXPLAIN (ANALYZE, SERIALIZE) SELECT 1");
}

#[test]
fn explain_with_unknown_option_is_not_read_fail_closed() {
    // Fail-closed allowlist: an EXPLAIN is a read ONLY if EVERY option is in the
    // proven plan-only allowlist. An unrecognized/unknown option — a typo, a
    // future PG option, or an injected token — is NOT proven plan-only, so the
    // whole EXPLAIN is not-read.
    assert_not_read("EXPLAIN (FROBNICATE) SELECT 1");
    assert_not_read("EXPLAIN (FORMAT JSON, FROBNICATE) SELECT 1");
    assert_not_read("EXPLAIN (WAL) SELECT 1"); // WAL is meaningful only with ANALYZE
    assert_not_read("EXPLAIN (TIMING) SELECT 1"); // TIMING is meaningful only with ANALYZE
}

#[test]
fn explain_with_only_plan_only_options_stays_read() {
    // GREEN guard: the legitimate, proven plan-only options keep `explain_plan`
    // (and the proxy gate) working — PR2's read e2e must still pass.
    assert_read("EXPLAIN SELECT 1");
    assert_read("EXPLAIN (FORMAT JSON) SELECT 1");
    assert_read("EXPLAIN VERBOSE SELECT a FROM t");
    assert_read("EXPLAIN (VERBOSE) SELECT 1");
    assert_read("EXPLAIN (COSTS) SELECT 1");
    assert_read("EXPLAIN (COSTS false) SELECT 1");
    assert_read("EXPLAIN (SETTINGS) SELECT 1");
    assert_read("EXPLAIN (GENERIC_PLAN) SELECT 1");
    assert_read("EXPLAIN (SUMMARY) SELECT 1");
    assert_read("EXPLAIN (MEMORY) SELECT 1");
    assert_read("EXPLAIN (BUFFERS) SELECT 1");
    assert_read("EXPLAIN (BUFFERS true) SELECT 1");
    assert_read("EXPLAIN (FORMAT JSON, VERBOSE, COSTS, BUFFERS) SELECT count(*) FROM events");
}

#[test]
fn bare_explain_analyse_does_not_parse_so_it_is_not_read() {
    // The bare (non-parenthesized) British form `EXPLAIN ANALYSE …` is not a
    // keyword sqlparser recognizes, so it fails to parse and is fail-closed
    // not-read. Pin it so a future parser change cannot silently let it through.
    assert_not_read("EXPLAIN ANALYSE SELECT 1");
    assert_not_read("EXPLAIN ANALYSE VERBOSE SELECT 1");
}

#[test]
fn explain_of_a_write_is_not_read() {
    // The explain-hole guard: EXPLAIN of a WRITE/DDL plans a write — refuse it, so
    // `explain_plan` can never be a back-door to a write (even without ANALYZE, the
    // intent is a write and several writes have side effects at plan time).
    assert_not_read("EXPLAIN DELETE FROM accounts WHERE id = 1");
    assert_not_read("EXPLAIN (FORMAT JSON) UPDATE accounts SET balance = 0");
    assert_not_read("EXPLAIN INSERT INTO t VALUES (1)");
    assert_not_read("EXPLAIN DROP TABLE accounts");
    assert_not_read("EXPLAIN (FORMAT JSON) TRUNCATE accounts");
    // EXPLAIN of a data-modifying CTE is a planned write → not-read.
    assert_not_read("EXPLAIN (FORMAT JSON) WITH d AS (DELETE FROM t RETURNING id) SELECT * FROM d");
}

#[test]
fn explain_then_stacked_write_is_not_a_single_read() {
    // The TS explain-hole shape: an EXPLAIN of a read followed by a stacked write.
    // It is multiple statements → never a single read (statement-stacking).
    let (cls, reason) = classify_with_reason("EXPLAIN (FORMAT JSON) SELECT 1; DROP TABLE victim");
    assert_eq!(cls, Classification::NotRead);
    assert_eq!(reason, Some(NotReadReason::MultipleStatements));
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
