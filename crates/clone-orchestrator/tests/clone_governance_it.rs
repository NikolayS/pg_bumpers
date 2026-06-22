//! Real-PG18 integration tests for the **clone provider + governance** (SPEC §4,
//! §10.7, §12). Env-gated behind `PG_BUMPERS_IT=1`. Run with:
//!
//! ```sh
//! PG_BUMPERS_IT=1 cargo test -p pgb-clone-orchestrator --test clone_governance_it -- --nocapture
//! ```
//!
//! These prove the moat + the blocking clone governance:
//!
//! - **MARQUEE / zero-prod-impact:** provision a `local` `pg_basebackup` clone
//!   from a seeded primary, run the no-`WHERE` `UPDATE … SET balance = 0` dry_run
//!   **on the clone**, and assert (a) the blast radius is reported, and (b) the
//!   **PRIMARY rows + state are byte-identical before/after** — the rehearsal
//!   never touched prod. Teardown leaves no clone.
//! - **Orphan-reaper (§10.7):** spawn a separate orchestrator process that
//!   provisions a clone and is then **SIGKILLed mid-rehearsal** (its teardown
//!   never runs); the reaper, driven from the shared ledger, destroys the
//!   orphan — **no clone cluster / process / dir survives**.
//! - **BLOCKER fix — SIGKILL *during* `pg_basebackup` (§10.7):** an orchestrator
//!   is killed while the (throttled) base backup is still streaming; the
//!   ledger-FIRST breadcrumb means the reaper still finds and destroys the
//!   half-written prod-PII datadir — no dir/process survives.
//! - **Ledger-independent sweep (§10.7):** a prod-PII datadir on disk with **no**
//!   ledger entry (lost ledger) is reaped by the filesystem sweep alone.
//! - **RLS/column-grant parity (§4):** capture `pg_policies` + column grants from
//!   prod and from the clone and assert full parity (the clone enforces the same
//!   RLS + column grants as prod).
//!
//! ⚠️ Every cluster here uses dedicated high ports (5436x / 5437x), loopback
//! only, under a git-ignored dir. The founder's 5432 is never touched.

mod common;

use std::path::Path;
use std::process::Command;

use common::cluster::{pg_bin, scratch_root, Primary, GOV_SEED_SQL};
use common::PgRehearsal;
use pgb_clone_orchestrator::provider::local::{LocalCloneConfig, LocalCloneProvider, PrimaryRef};
use pgb_clone_orchestrator::{
    check_parity, dry_run, propose, reap_orphans, reap_orphans_with_sweep, with_clone,
    write_owner_marker, CloneError, CloneLedger, ColumnGrant, OwnerIdentity, ProviderKind,
    RlsPolicy,
};
use pgb_core::SystemClock;
use postgres::{Client, NoTls};

const IT_ENV: &str = "PG_BUMPERS_IT";

fn it_enabled() -> bool {
    std::env::var(IT_ENV).map(|v| v == "1").unwrap_or(false)
}

fn skip(tag: &str) -> bool {
    if !it_enabled() {
        eprintln!("[skip] {tag}: set PG_BUMPERS_IT=1 to run the clone-governance IT");
        return true;
    }
    false
}

fn connect(dsn: &str) -> Client {
    Client::connect(dsn, NoTls).expect("connect")
}

/// A `local` provider over a freshly-started primary, with its own scratch dir +
/// ledger. Ports: primary `primary_port`, clone `clone_port`.
fn provider_for(
    root: &Path,
    primary: &Primary,
    clone_port: u16,
    ledger: CloneLedger,
) -> LocalCloneProvider {
    let cfg = LocalCloneConfig {
        pg_bin: pg_bin(),
        clone_root: root.join("clones"),
        clone_port,
        primary: PrimaryRef {
            host: "127.0.0.1".into(),
            port: primary.port,
            repl_user: primary.repl_user.clone(),
            dbname: primary.dbname.clone(),
        },
        owner: "data-platform@pg-bumpers".into(),
    };
    LocalCloneProvider::new(cfg, ledger)
}

// ===========================================================================
//  MARQUEE — rehearse on the isolated clone; PRIMARY is byte-identical (the moat)
// ===========================================================================

#[test]
fn marquee_rehearses_on_clone_with_zero_primary_impact() {
    if skip("marquee_clone") {
        return;
    }
    let root = scratch_root("marquee");
    let primary = Primary::start(&root, 54360, "prod", GOV_SEED_SQL);

    // Golden pre-state on the PRIMARY (the thing that must NOT change).
    let mut prim = connect(&primary.dsn());
    let before = account_balances(&mut prim);
    eprintln!("[marquee] PRIMARY pre-state: {before:?}");
    assert_eq!(before.len(), 8);
    assert!(before.values().all(|&b| b != 0));
    let prim_pid = backend_pid(&mut prim);

    let ledger = CloneLedger::open(root.join("ledger")).unwrap();
    let mut provider = provider_for(&root, &primary, 54370, ledger);

    // Provision → rehearse ON THE CLONE → mandatory teardown, via with_clone.
    let clock = SystemClock::new();
    let statement = "UPDATE public.accounts SET balance = 0";
    let proposal = propose(statement, Some(8), &clock);

    let mut clone_conn_seen = String::new();
    let br = with_clone(
        &mut provider,
        |handle| {
            assert_eq!(handle.provider, ProviderKind::Local);
            clone_conn_seen = handle.conn.clone();
            eprintln!(
                "[marquee] clone provisioned: id={} conn={} lsn={} access_log={}",
                handle.clone_id, handle.conn, handle.lsn, handle.governance.access_log
            );
            // The rehearsal runs against the CLONE's DSN — not the primary.
            let mut clone_client = Client::connect(&handle.conn, NoTls)
                .map_err(|e| CloneError::Provision(e.to_string()))?;
            let inner = SystemClock::new();
            let mut backend = PgRehearsal::new(&mut clone_client, &inner);
            dry_run(&proposal, &mut backend, &clock)
                .map_err(|e| CloneError::Provision(format!("dry_run on clone: {e}")))
        },
        |te| panic!("teardown error: {te}"),
    )
    .expect("clone rehearsal must succeed");

    eprintln!(
        "[marquee] BLAST-RADIUS (measured on the CLONE):\n{}",
        serde_json::to_string_pretty(&br).unwrap()
    );

    // (1) Blast radius reported: a no-WHERE update touches all 8 rows.
    assert_eq!(br.affected.by_table["public.accounts"], 8);
    assert_eq!(br.affected.total_rows, 8);
    let checksum = &br.affected.pk_set_checksum["public.accounts"];
    assert!(checksum.starts_with("sha256:"));
    assert!(br
        .triggers_fired
        .iter()
        .any(|t| t.name == "accounts_audit_aud"));
    assert!(br.reversible);

    // (2) THE MOAT — the PRIMARY is byte-identical before/after, AND the same
    //     primary backend served both reads (the clone is a different cluster).
    let after = account_balances(&mut prim);
    eprintln!("[marquee] PRIMARY post-rehearsal: {after:?}");
    assert_eq!(
        before, after,
        "ZERO PROD IMPACT: primary balances must be byte-identical (rehearsal ran on the clone)"
    );
    assert!(
        after.values().all(|&b| b != 0),
        "no balance was zeroed on prod"
    );
    assert_eq!(
        prim_pid,
        backend_pid(&mut prim),
        "same primary session — the rehearsal never opened a txn on the primary"
    );

    // (3) Teardown left no clone (with_clone already destroyed it): the ledger is
    //     empty and the clone datadir is gone.
    let leftover = provider.ledger().entries().unwrap();
    assert!(
        leftover.is_empty(),
        "mandatory teardown must leave no clone in the ledger; got {leftover:?}"
    );
    assert!(
        !clone_conn_seen.is_empty(),
        "sanity: the rehearsal ran against a clone DSN"
    );
    assert_no_cluster_on_port(54370);

    drop(prim);
    drop(primary);
    cleanup(&root);
}

// ===========================================================================
//  ORPHAN-REAPER — a clone must NOT survive a killed orchestrator (§10.7)
// ===========================================================================

#[test]
fn killed_orchestrator_leaves_no_surviving_clone() {
    if skip("orphan_reaper") {
        return;
    }
    let root = scratch_root("orphan");
    let primary = Primary::start(&root, 54361, "prod", GOV_SEED_SQL);

    let ledger_dir = root.join("ledger");
    let clone_root = root.join("clones");
    let clone_port = 54371u16;

    // Spawn a SEPARATE orchestrator process that provisions a clone and then
    // blocks (mid-rehearsal). We compile + run the example as a child.
    let exe = build_example("orphan_orchestrator");
    let mut child = Command::new(&exe)
        .arg(pg_bin())
        .arg(&clone_root)
        .arg(&ledger_dir)
        .arg("127.0.0.1")
        .arg(primary.port.to_string())
        .arg(&primary.repl_user)
        .arg(&primary.dbname)
        .arg(clone_port.to_string())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("spawn orphan orchestrator");

    // Wait for the child to print READY (its clone is up + recorded in ledger).
    let ready = read_ready_line(&mut child);
    eprintln!("[orphan] child reported: {ready}");
    let clone_id = ready
        .split_whitespace()
        .nth(1)
        .expect("clone_id")
        .to_string();

    // The clone is genuinely up: a backend answers on its dedicated port.
    assert!(
        cluster_alive_on_port(clone_port),
        "precondition: the orphan clone must be running before we kill its owner"
    );
    let ledger = CloneLedger::open(&ledger_dir).unwrap();
    assert_eq!(
        ledger.entries().unwrap().len(),
        1,
        "the clone must be recorded in the ledger before the orchestrator dies"
    );
    let datadir = ledger.entries().unwrap()[0].datadir.clone();
    assert!(datadir.exists(), "clone datadir exists pre-kill");

    // === KILL the orchestrator with SIGKILL — its Drop/teardown NEVER runs. ===
    let child_pid = child.id();
    let _ = Command::new("kill")
        .arg("-KILL")
        .arg(child_pid.to_string())
        .output();
    let _ = child.wait();
    eprintln!("[orphan] orchestrator pid {child_pid} SIGKILLed (no teardown ran)");
    // The clone is now an ORPHAN: its owner is dead but the cluster is still up
    // and the datadir (unencrypted prod-PII copy) still on disk.
    assert!(
        datadir.exists(),
        "orphan datadir survives the killed orchestrator (pre-reap)"
    );

    // === REAP — the backstop. Driven purely from the shared ledger. ===
    let outcome = reap_orphans(&ledger).expect("reaper pass");
    eprintln!("[orphan] reaper outcome: {outcome:?}");

    // An alarm was raised for exactly this orphan, and it was reaped.
    assert_eq!(outcome.alarms.len(), 1, "exactly one orphan-clone alarm");
    let alarm = &outcome.alarms[0];
    assert_eq!(alarm.clone_id, clone_id);
    assert_eq!(alarm.port, clone_port);
    assert!(alarm.reaped, "the orphan must be reaped");

    // === THE ASSERTION: no clone cluster / process / dir survives. ===
    assert!(
        !datadir.exists(),
        "the orphan clone DATADIR must be gone after the reaper"
    );
    assert!(
        !cluster_alive_on_port(clone_port),
        "the orphan clone PROCESS/CLUSTER must be gone after the reaper"
    );
    assert!(
        ledger.entries().unwrap().is_empty(),
        "the reaped clone must be removed from the ledger"
    );

    drop(primary);
    cleanup(&root);
}

// ===========================================================================
//  BLOCKER FIX — SIGKILL *DURING* pg_basebackup leaves NO surviving clone (§10.7)
// ===========================================================================
//
//  The headline regression for the #33 review: the prod-PII datadir is written by
//  pg_basebackup BEFORE the ledger breadcrumb under the old ordering, so a crash
//  mid-backup left a PII datadir the ledger-only reaper could not see. With the
//  ledger-FIRST ordering the breadcrumb always precedes the PII, so killing the
//  orchestrator while basebackup is still streaming still leaves a reapable
//  orphan. We throttle basebackup so the kill reliably lands mid-stream.

#[test]
fn sigkill_during_basebackup_leaves_no_surviving_clone() {
    if skip("sigkill_during_basebackup") {
        return;
    }
    let root = scratch_root("crash-bb");
    let primary = Primary::start(&root, 54363, "prod", GOV_SEED_SQL);

    let ledger_dir = root.join("ledger");
    let clone_root = root.join("clones");
    let clone_port = 54373u16;

    // Spawn an orchestrator that records the ledger entry (ledger-FIRST), starts a
    // THROTTLED pg_basebackup, and blocks while it streams.
    let exe = build_example("crash_during_basebackup");
    let mut child = Command::new(&exe)
        .arg(pg_bin())
        .arg(&clone_root)
        .arg(&ledger_dir)
        .arg("127.0.0.1")
        .arg(primary.port.to_string())
        .arg(&primary.repl_user)
        .arg(&primary.dbname)
        .arg(clone_port.to_string())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("spawn crash_during_basebackup");

    let ready = read_ready_line(&mut child);
    eprintln!("[sigkill-bb] child reported: {ready}");
    let clone_id = ready
        .split_whitespace()
        .nth(1)
        .expect("clone_id")
        .to_string();
    let datadir = clone_root.join(&clone_id);

    // The ledger breadcrumb exists BEFORE the basebackup finished (the fix). The
    // datadir is a PARTIAL prod-PII copy still being written.
    let ledger = CloneLedger::open(&ledger_dir).unwrap();
    assert_eq!(
        ledger.entries().unwrap().len(),
        1,
        "ledger-first: the breadcrumb must exist before/while basebackup runs"
    );
    assert!(
        datadir.exists(),
        "a (partial) prod-PII datadir is on disk while basebackup streams"
    );

    // === SIGKILL the orchestrator WHILE basebackup is still streaming. ===
    let child_pid = child.id();
    let _ = Command::new("kill")
        .arg("-KILL")
        .arg(child_pid.to_string())
        .output();
    let _ = child.wait();
    eprintln!("[sigkill-bb] orchestrator pid {child_pid} SIGKILLed mid-basebackup (no teardown)");
    assert!(
        datadir.exists(),
        "the half-written prod-PII datadir survives the killed orchestrator (pre-reap)"
    );

    // === REAP — ledger-first breadcrumb means the reaper finds it; the sweep is
    //     the belt-and-suspenders backstop. ===
    let outcome = reap_orphans_with_sweep(&ledger, &clone_root).expect("reaper pass");
    eprintln!("[sigkill-bb] reaper outcome: {outcome:?}");
    assert!(
        outcome
            .alarms
            .iter()
            .any(|a| a.clone_id == clone_id && a.reaped),
        "the mid-basebackup orphan must be reaped: {outcome:?}"
    );

    // === THE ASSERTION: no clone dir / process survives the killed orchestrator. ===
    assert!(
        !datadir.exists(),
        "BLOCKER FIX: the mid-basebackup prod-PII datadir must be GONE after the reaper"
    );
    assert!(
        !cluster_alive_on_port(clone_port),
        "no clone process/cluster may survive on port {clone_port}"
    );
    assert!(
        ledger.entries().unwrap().is_empty(),
        "the reaped clone must be removed from the ledger"
    );

    drop(primary);
    cleanup(&root);
}

// ===========================================================================
//  LEDGER-INDEPENDENT SWEEP — an UNRECORDED prod-PII datadir is reaped (§10.7)
// ===========================================================================
//
//  Defence-in-depth: even with NO ledger entry at all (the ledger write failed or
//  was lost), a clone datadir under clone_root whose owner is not live is found by
//  the filesystem sweep and destroyed. We materialise a real prod-PII clone via
//  pg_basebackup, then DELETE its ledger entry to model a lost ledger, then prove
//  the sweep alone reaps it.

#[test]
fn ledger_independent_sweep_reaps_unrecorded_datadir() {
    if skip("ledger_independent_sweep") {
        return;
    }
    let root = scratch_root("sweep");
    let primary = Primary::start(&root, 54364, "prod", GOV_SEED_SQL);

    let clone_root = root.join("clones");
    let ledger_dir = root.join("ledger");
    let ledger = CloneLedger::open(&ledger_dir).unwrap();

    // Make a real prod-PII clone datadir on disk via pg_basebackup (the same op
    // provision uses), then stamp a DEAD owner marker and ensure there is NO
    // ledger entry — the exact "datadir exists, ledger can't see it" condition.
    let clone_id = "local-clone-UNRECORDED-1";
    let datadir = clone_root.join(clone_id);
    std::fs::create_dir_all(&clone_root).unwrap();
    let status = Command::new(pg_bin().join("pg_basebackup"))
        .arg("--pgdata")
        .arg(&datadir)
        .arg("--wal-method=stream")
        .arg("--checkpoint=fast")
        .arg("--no-sync")
        .arg("--host")
        .arg("127.0.0.1")
        .arg("--port")
        .arg(primary.port.to_string())
        .arg("--username")
        .arg(&primary.repl_user)
        .arg("--no-password")
        .status()
        .expect("spawn pg_basebackup");
    assert!(status.success(), "pg_basebackup for the unrecorded clone");
    assert!(
        datadir.join("PG_VERSION").exists(),
        "real PG datadir on disk"
    );

    // Stamp a DEAD owner-identity marker (pid that cannot be alive). NO ledger
    // entry is written — the reaper is blind to it via the ledger.
    write_owner_marker(
        &datadir,
        &OwnerIdentity {
            pid: 2_147_483_647, // effectively never a live pid
            start: String::new(),
        },
    )
    .unwrap();
    assert!(
        ledger.entries().unwrap().is_empty(),
        "premise: there is NO ledger entry for this datadir"
    );

    // The ledger-only pass sees nothing (proves the original BLOCKER).
    let ledger_only = reap_orphans(&ledger).expect("ledger-only pass");
    assert!(
        ledger_only.alarms.is_empty(),
        "the ledger-only reaper cannot see an unrecorded datadir (the BLOCKER)"
    );
    assert!(datadir.exists(), "still on disk after the ledger-only pass");

    // The full pass (ledger + filesystem sweep) reaps it.
    let outcome = reap_orphans_with_sweep(&ledger, &clone_root).expect("full reaper pass");
    eprintln!("[sweep] reaper outcome: {outcome:?}");
    assert!(
        outcome
            .alarms
            .iter()
            .any(|a| a.clone_id == clone_id && a.reaped),
        "the sweep must reap the unrecorded prod-PII datadir: {outcome:?}"
    );
    assert!(
        !datadir.exists(),
        "the unrecorded prod-PII datadir must be GONE after the sweep"
    );

    drop(primary);
    cleanup(&root);
}

// ===========================================================================
//  RLS / COLUMN-GRANT PARITY — the clone enforces the same as prod (§4)
// ===========================================================================

#[test]
fn clone_has_rls_and_column_grant_parity_with_prod() {
    if skip("rls_parity") {
        return;
    }
    let root = scratch_root("parity");
    let primary = Primary::start(&root, 54362, "prod", GOV_SEED_SQL);

    // Capture prod's RLS + column grants.
    let mut prim = connect(&primary.dsn());
    let prod_rls = capture_rls(&mut prim);
    let prod_grants = capture_column_grants(&mut prim);
    eprintln!(
        "[parity] prod: {} RLS policies, {} column grants",
        prod_rls.len(),
        prod_grants.len()
    );
    assert!(
        !prod_rls.is_empty(),
        "premise: prod must have RLS policies to compare"
    );
    assert!(
        !prod_grants.is_empty(),
        "premise: prod must have column grants to compare"
    );

    let ledger = CloneLedger::open(root.join("ledger")).unwrap();
    let mut provider = provider_for(&root, &primary, 54372, ledger);

    let report = with_clone(
        &mut provider,
        |handle| {
            let mut clone = Client::connect(&handle.conn, NoTls)
                .map_err(|e| CloneError::Provision(e.to_string()))?;
            let clone_rls = capture_rls(&mut clone);
            let clone_grants = capture_column_grants(&mut clone);
            eprintln!(
                "[parity] clone: {} RLS policies, {} column grants",
                clone_rls.len(),
                clone_grants.len()
            );
            Ok(check_parity(
                &prod_rls,
                &clone_rls,
                &prod_grants,
                &clone_grants,
            ))
        },
        |te| panic!("teardown error: {te}"),
    )
    .expect("parity check on clone");

    eprintln!("[parity] {}", report.summary());
    assert!(
        report.is_parity(),
        "the clone must enforce the SAME RLS + column grants as prod: {}",
        report.summary()
    );

    drop(prim);
    drop(primary);
    cleanup(&root);
}

// ===========================================================================
//  Helpers
// ===========================================================================

fn account_balances(client: &mut Client) -> std::collections::BTreeMap<i32, i64> {
    client
        .query("SELECT id, balance FROM public.accounts ORDER BY id", &[])
        .expect("balances")
        .iter()
        .map(|r| (r.get::<_, i32>(0), r.get::<_, i64>(1)))
        .collect()
}

fn backend_pid(client: &mut Client) -> i32 {
    client
        .query_one("SELECT pg_backend_pid()", &[])
        .unwrap()
        .get(0)
}

/// Capture every RLS policy + its table's rls-enabled flag from `pg_policies`.
fn capture_rls(client: &mut Client) -> Vec<RlsPolicy> {
    let rows = client
        .query(
            r#"
            SELECT p.schemaname, p.tablename, p.policyname,
                   p.permissive, p.roles::text, p.cmd,
                   COALESCE(p.qual, '')       AS using_expr,
                   COALESCE(p.with_check, '') AS check_expr,
                   c.relrowsecurity
            FROM pg_policies p
            JOIN pg_class c   ON c.relname = p.tablename
            JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = p.schemaname
            ORDER BY 1,2,3
            "#,
            &[],
        )
        .expect("query pg_policies");
    rows.iter()
        .map(|r| RlsPolicy {
            schema: r.get(0),
            table: r.get(1),
            policy: r.get(2),
            permissive: r.get(3),
            roles: r.get(4),
            cmd: r.get(5),
            using_expr: r.get(6),
            check_expr: r.get(7),
            rls_enabled: r.get(8),
        })
        .collect()
}

/// Capture per-column SELECT/UPDATE/... grants to the agent role.
fn capture_column_grants(client: &mut Client) -> Vec<ColumnGrant> {
    let rows = client
        .query(
            r#"
            SELECT grantee, table_schema, table_name, column_name, privilege_type
            FROM information_schema.column_privileges
            WHERE grantee = 'pgb_agent' AND table_schema = 'public'
            ORDER BY 1,2,3,4,5
            "#,
            &[],
        )
        .expect("query column_privileges");
    rows.iter()
        .map(|r| ColumnGrant {
            grantee: r.get(0),
            schema: r.get(1),
            table: r.get(2),
            column: r.get(3),
            privilege: r.get(4),
        })
        .collect()
}

/// Whether a postmaster answers `SELECT 1` on `127.0.0.1:port`.
fn cluster_alive_on_port(port: u16) -> bool {
    let dsn = format!("host=127.0.0.1 port={port} user=postgres dbname=postgres connect_timeout=2");
    match Client::connect(&dsn, NoTls) {
        Ok(mut c) => c.simple_query("SELECT 1").is_ok(),
        Err(_) => false,
    }
}

fn assert_no_cluster_on_port(port: u16) {
    assert!(
        !cluster_alive_on_port(port),
        "no clone cluster must remain on port {port} after teardown"
    );
}

/// Compile the named example once and return its executable path. We invoke
/// `cargo build --example <name>` and locate the binary next to the test
/// artifacts (target/debug/examples/<name>).
fn build_example(name: &str) -> std::path::PathBuf {
    let status = Command::new(env!("CARGO"))
        .arg("build")
        .arg("--example")
        .arg(name)
        .arg("-p")
        .arg("pgb-clone-orchestrator")
        .status()
        .expect("cargo build --example");
    assert!(status.success(), "building example {name} failed");

    // The test binary lives in target/<profile>/deps; examples in
    // target/<profile>/examples. Derive from the current_exe path.
    let exe = std::env::current_exe().expect("current_exe");
    // .../target/<profile>/deps/<test>-<hash>
    let deps = exe.parent().expect("deps dir");
    let profile = deps.parent().expect("profile dir");
    let candidate = profile.join("examples").join(name);
    assert!(
        candidate.exists(),
        "example binary not found at {}",
        candidate.display()
    );
    candidate
}

/// Read lines from the child's stdout until one starts with `READY`.
fn read_ready_line(child: &mut std::process::Child) -> String {
    use std::io::{BufRead, BufReader};
    let stdout = child.stdout.take().expect("child stdout");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line).expect("read child stdout");
        assert!(n > 0, "child exited before reporting READY");
        if line.starts_with("READY") {
            return line.trim().to_string();
        }
        eprintln!("[orphan][child] {}", line.trim_end());
    }
}

fn cleanup(root: &Path) {
    std::fs::remove_dir_all(root).ok();
}
