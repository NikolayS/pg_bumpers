//! A throwaway "orchestrator" used by the orphan-reaper integration test
//! (`tests/clone_governance_it.rs`, SPEC §10.7). It is spawned as a **separate
//! process** that:
//!
//! 1. provisions a `local` clone (recording it in the shared [`CloneLedger`]),
//! 2. prints `READY <clone_id> <datadir> <port>` to stdout,
//! 3. sleeps forever — simulating an orchestrator that is **mid-rehearsal**.
//!
//! The parent test then **SIGKILLs this process** (so its `Drop`/teardown never
//! runs — the worst case) and asserts the orphan-reaper, driven from the same
//! ledger, destroys the leaked clone: no cluster / process / dir survives.
//!
//! Usage (argv): `orphan_orchestrator <pg_bin> <clone_root> <ledger_dir>
//! <primary_host> <primary_port> <repl_user> <dbname> <clone_port>`
//!
//! Not production code; it exists only to be killed. It is an example (not a
//! test) so the harness can `cargo run --example` it as a real child process.

use std::io::Write;
use std::path::PathBuf;

use pgb_clone_orchestrator::provider::local::{LocalCloneConfig, LocalCloneProvider, PrimaryRef};
use pgb_clone_orchestrator::{CloneLedger, CloneProvider};

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

    let ledger = CloneLedger::open(&ledger_dir).expect("open ledger");
    let cfg = LocalCloneConfig {
        pg_bin,
        clone_root,
        clone_port,
        primary: PrimaryRef {
            host: primary_host,
            port: primary_port,
            repl_user,
            dbname,
        },
        owner: "orphan-test@pg-bumpers".into(),
    };
    let mut provider = LocalCloneProvider::new(cfg, ledger);

    // Provision the clone — this records it in the ledger BEFORE returning, which
    // is exactly the window the reaper protects.
    let handle = provider.provision().expect("provision clone");

    // Tell the parent the clone is up, then flush so it is observed promptly.
    println!(
        "READY {} {} {}",
        handle.clone_id, handle.governance.location, handle.provider
    );
    std::io::stdout().flush().ok();

    // Simulate being mid-rehearsal: block forever. The parent SIGKILLs us here,
    // so `destroy` is NEVER called — the clone is leaked and the reaper must
    // clean it up from the ledger alone.
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}
