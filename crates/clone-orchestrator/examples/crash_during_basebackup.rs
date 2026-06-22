//! A throwaway "orchestrator" that crashes **DURING `pg_basebackup`** — the
//! BLOCKER scenario from the #33 review (SPEC §10.7).
//!
//! It reproduces the *exact* ledger-first ordering of
//! [`LocalCloneProvider::provision`](pgb_clone_orchestrator::provider::local::LocalCloneProvider):
//!
//! 1. record the [`LedgerEntry`] (clone id, owner identity, datadir, port)
//!    **BEFORE** any prod PII exists on disk, then
//! 2. start a **throttled** `pg_basebackup` (so it stays in flight long enough for
//!    the parent test to SIGKILL this process mid-stream), printing
//!    `READY <clone_id> <datadir> <port>` once the partial datadir is on disk and
//!    the ledger entry is committed.
//!
//! The parent test then SIGKILLs this process **while the base backup is still
//! running** (no teardown, no owner-marker written yet — the worst case) and
//! asserts the reaper, driven from the shared ledger, destroys the half-written
//! prod-PII datadir: no cluster / process / dir survives.
//!
//! Under the OLD ordering (datadir-then-ledger) this window had a prod-PII datadir
//! on disk with **no** ledger entry, and the ledger-only reaper could not see it.
//! Under the fixed ordering the breadcrumb is always present, so it reaps.
//!
//! Usage (argv): `crash_during_basebackup <pg_bin> <clone_root> <ledger_dir>
//! <primary_host> <primary_port> <repl_user> <dbname> <clone_port>`
//!
//! Not production code; it exists only to be killed mid-backup. It deliberately
//! does NOT use `provision()` directly because it must hand control back to the
//! parent *while basebackup is in flight*; it instead replays provision's public
//! ledger-first ordering verbatim.

use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

use pgb_clone_orchestrator::{CloneLedger, LedgerEntry, OwnerIdentity};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 9 {
        eprintln!(
            "usage: {} <pg_bin> <clone_root> <ledger_dir> <primary_host> \
             <primary_port> <repl_user> <dbname> <clone_port>",
            args[0]
        );
        std::process::exit(2);
    }
    let pg_bin = PathBuf::from(&args[1]);
    let clone_root = PathBuf::from(&args[2]);
    let ledger_dir = PathBuf::from(&args[3]);
    let primary_host = args[4].clone();
    let primary_port: u16 = args[5].parse().expect("primary_port");
    let repl_user = args[6].clone();
    let dbname = args[7].clone();
    let clone_port: u16 = args[8].parse().expect("clone_port");
    let _ = dbname; // not needed before the crash

    let ledger = CloneLedger::open(&ledger_dir).expect("open ledger");
    let clone_id = format!("local-clone-{}-crash", std::process::id());
    let datadir = clone_root.join(&clone_id);
    std::fs::create_dir_all(&clone_root).expect("clone root");

    // (1) LEDGER-FIRST: record the breadcrumb BEFORE any PII exists on disk — the
    //     fixed ordering. This is exactly what `provision()` now does.
    let owner = OwnerIdentity::current();
    ledger
        .record(&LedgerEntry {
            clone_id: clone_id.clone(),
            datadir: datadir.clone(),
            port: clone_port,
            owner_pid: owner.pid,
            owner_start: owner.start,
        })
        .expect("record ledger entry before basebackup");

    // (2) Start a THROTTLED pg_basebackup as a child so it stays in flight while
    //     the parent SIGKILLs us. --max-rate=32k keeps it streaming for seconds on
    //     even a small seed DB, guaranteeing the kill lands mid-backup. We do NOT
    //     wait for it; we report READY as soon as the datadir starts filling, then
    //     block forever (the parent kills us, killing this child too — leaving a
    //     PARTIAL prod-PII datadir with a ledger breadcrumb).
    let mut child = Command::new(pg_bin.join("pg_basebackup"))
        .arg("--pgdata")
        .arg(&datadir)
        .arg("--wal-method=stream")
        .arg("--checkpoint=fast")
        .arg("--no-sync")
        .arg("--max-rate=32k")
        .arg("--host")
        .arg(&primary_host)
        .arg("--port")
        .arg(primary_port.to_string())
        .arg("--username")
        .arg(&repl_user)
        .arg("--no-password")
        .spawn()
        .expect("spawn pg_basebackup");

    // Wait until the datadir actually exists on disk (basebackup has started
    // writing the prod-PII copy) before telling the parent it may kill us.
    for _ in 0..600 {
        if datadir.join("PG_VERSION").exists() || datadir.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    println!("READY {clone_id} {} {clone_port}", datadir.display());
    std::io::stdout().flush().ok();

    // Block forever WITH the basebackup still streaming. The parent SIGKILLs us
    // here — teardown never runs and no owner-marker is ever written. The child
    // basebackup is left orphaned mid-stream; the reaper must clean it all up.
    loop {
        // If basebackup somehow finishes, keep blocking — we want to be killed
        // mid-window regardless.
        let _ = child.try_wait();
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}
