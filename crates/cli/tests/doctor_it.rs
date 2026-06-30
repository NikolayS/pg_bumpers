//! Env-gated **real Postgres** integration test for `pgb-cli doctor` — the
//! fail-closed BYO preflight (issue #103, SPEC §0.5/§3/§4).
//!
//! Proves the doctor's headline behavior end-to-end against a real cluster:
//!   * GREEN — after applying `deploy/sql/10_hardened_role.sql` (the WALL +
//!     applier hardening) the doctor exits **0** (preflight passed);
//!   * RED — once the agent role is UN-hardened (made SUPERUSER) the same doctor
//!     exits **non-zero** (fail-closed: do not point an agent at this DB).
//!
//! Runs only when `PG_BRAKES_IT=1`. Run with:
//!
//! ```sh
//! PG_BRAKES_IT=1 cargo test -p pgb-cli --test doctor_it -- --nocapture
//! ```
//!
//! It stands up its OWN throwaway cluster (any supported major 14-18) on a
//! dedicated high port via the shared PG-bin resolver. NEVER 5432.

use std::process::Command;

use postgres::{Client, NoTls};

fn it_enabled() -> bool {
    std::env::var("PG_BRAKES_IT")
        .map(|v| v == "1")
        .unwrap_or(false)
}

/// The PG bin dir via the ONE shared resolver (issues #44, #102) — version-agnostic
/// across PG 14-18.
fn pgbin() -> String {
    pgb_test_support::resolve_pg_bin("PG_BRAKES_PGBIN")
        .to_string_lossy()
        .into_owned()
}

/// Read a `deploy/sql/*.sql` file, stripping the psql meta-commands the `-f` path
/// tolerates but the `simple_query`/`batch_execute` path here does not (`\set`).
fn deploy_sql(name: &str) -> String {
    let path = format!("{}/../../deploy/sql/{name}", env!("CARGO_MANIFEST_DIR"));
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    raw.lines()
        .filter(|l| !l.trim_start().starts_with("\\set"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The canonical AGENT-ROLE-ONLY hardening (the role hardening only; #103 split the
/// demo seed into 20_demo_seed.sql; #108 split the strict PUBLIC lockdown into
/// 21_public_lockdown.sql — the doctor checks hardening, not the seed).
fn hardened_role_sql() -> String {
    deploy_sql("10_hardened_role.sql")
}

/// The OPT-IN strict PUBLIC lockdown (#108). The agent-only default (10_hardened_role.sql)
/// NEVER mutates PUBLIC, so on PG14 — where PUBLIC still has CREATE on schema public by
/// default — the applier inherits CREATE-on-public via PUBLIC and the doctor's
/// `applier_no_ddl` check correctly fails-closed. The fully-contained posture a dedicated
/// deployment runs is agent-only + this lockdown; the doctor IT (a throwaway DEDICATED test
/// cluster) applies BOTH, matching the fixture path (local-stack.sh / wall_matrix.sh). A
/// real BYO user on a shared DB does not apply the lockdown — and the doctor would honestly
/// flag the PG14 applier-CREATE residual for them to remediate.
fn public_lockdown_sql() -> String {
    deploy_sql("21_public_lockdown.sql")
}

// --------------------------------------------------------------------------
// Throwaway cluster harness — a dedicated high port; NEVER 5432.
// --------------------------------------------------------------------------
struct ThrowawayCluster {
    datadir: std::path::PathBuf,
    port: u16,
}

impl ThrowawayCluster {
    fn up() -> (Self, String) {
        let port: u16 = 54363; // dedicated doctor IT port (never 5432)
        let datadir = std::env::temp_dir().join(format!("pgb-doctor-it-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&datadir);
        std::fs::create_dir_all(&datadir).unwrap();
        let bin = pgbin();
        let status = Command::new(format!("{bin}/initdb"))
            .args([
                "-D",
                datadir.to_str().unwrap(),
                "-U",
                "postgres",
                "--auth=trust",
                "--no-sync",
            ])
            .status()
            .expect("run initdb");
        assert!(status.success(), "initdb failed");
        let status = Command::new(format!("{bin}/pg_ctl"))
            .args([
                "-D",
                datadir.to_str().unwrap(),
                "-o",
                &format!("-p {port} -c listen_addresses=127.0.0.1 -c unix_socket_directories=''"),
                "-w",
                "-l",
                datadir.join("server.log").to_str().unwrap(),
                "start",
            ])
            .status()
            .expect("run pg_ctl start");
        assert!(status.success(), "pg_ctl start failed");
        let dsn = format!("host=127.0.0.1 port={port} user=postgres dbname=postgres");
        (ThrowawayCluster { datadir, port }, dsn)
    }
}

impl Drop for ThrowawayCluster {
    fn drop(&mut self) {
        let bin = pgbin();
        let _ = Command::new(format!("{bin}/pg_ctl"))
            .args([
                "-D",
                self.datadir.to_str().unwrap(),
                "-m",
                "immediate",
                "-w",
                "stop",
            ])
            .status();
        let _ = std::fs::remove_dir_all(&self.datadir);
        eprintln!(
            "[doctor-it] torn down throwaway cluster on port {} (NEVER touched 5432)",
            self.port
        );
    }
}

/// Run the `pgb-cli doctor` binary against the throwaway primary on `port`,
/// connecting (with trust auth) as `postgres` so it can read the catalogs. Returns
/// the process exit status (the fail-closed contract: zero iff every load-bearing
/// check passed) plus the captured stdout for assertions.
fn run_doctor(port: u16) -> (bool, String) {
    // A minimal BYO policy.yaml pointing `primary:` at the throwaway cluster.
    let policy = format!(
        "version: 1\nroles:\n  app:\n    autonomy: L0\n    budget:\n      max_bytes: 1\n      \
         max_rows: 1\n      per_window: {{ window_secs: 1, max_bytes: 1, max_rows: 1 }}\n\
         primary:\n  host: 127.0.0.1\n  port: {port}\n  database: postgres\n  role: postgres\n"
    );
    let policy_path =
        std::env::temp_dir().join(format!("pgb-doctor-it-policy-{}.yaml", std::process::id()));
    std::fs::write(&policy_path, policy).unwrap();

    let exe = env!("CARGO_BIN_EXE_pgb-cli");
    let out = Command::new(exe)
        .arg("doctor")
        .env("PGB_POLICY_PATH", &policy_path)
        // Connect as the trust-auth superuser `postgres` to read the catalogs; the
        // ROLE override makes the doctor connect as postgres while still CHECKING the
        // pgb_agent / pgb_applier hardening (their names are the defaults).
        .env("PGB_BACKEND_ROLE", "postgres")
        .env("PGB_DOCTOR_PASSWORD", "unused-trust-auth")
        .output()
        .expect("run pgb-cli doctor");
    let _ = std::fs::remove_file(&policy_path);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    eprintln!("[doctor-it] doctor stdout:\n{stdout}");
    (out.status.success(), stdout)
}

#[test]
fn doctor_fails_closed_then_passes_when_hardened() {
    if !it_enabled() {
        eprintln!("[skip] doctor_it: set PG_BRAKES_IT=1 to run against a real cluster");
        return;
    }
    let (_cluster, admin_dsn) = ThrowawayCluster::up();
    let mut admin = Client::connect(&admin_dsn, NoTls).expect("admin connect");

    // GREEN: apply the canonical AGENT-ROLE-ONLY hardening (creates + hardens pgb_agent +
    // pgb_applier), THEN the opt-in strict PUBLIC lockdown. This throwaway cluster is a
    // DEDICATED test DB, so it runs the FULL hardened posture a dedicated deployment uses
    // (agent-only default + lockdown) — the lockdown is what denies the applier CREATE-on-
    // public on PG14, where PUBLIC still grants it by default and the agent-only file alone
    // cannot subtract a PUBLIC grant (issue #108). After both the doctor must PASS (exit 0).
    admin
        .batch_execute(&hardened_role_sql())
        .expect("apply 10_hardened_role.sql");
    admin
        .batch_execute(&public_lockdown_sql())
        .expect("apply 21_public_lockdown.sql");
    let (passed, out) = run_doctor(_cluster.port);
    assert!(
        passed,
        "doctor must PASS against a hardened cluster (exit 0). stdout:\n{out}"
    );
    assert!(out.contains("PREFLIGHT PASSED"), "stdout:\n{out}");
    assert!(out.contains("primary_reachable"), "stdout:\n{out}");

    // RED #1: UN-harden the agent role (make it SUPERUSER). The doctor must now FAIL
    // CLOSED (non-zero exit) — a superuser agent is exactly what the WALL forbids.
    admin
        .batch_execute("ALTER ROLE pgb_agent SUPERUSER;")
        .expect("un-harden pgb_agent");
    let (passed, out) = run_doctor(_cluster.port);
    assert!(
        !passed,
        "doctor must FAIL CLOSED (non-zero) against a SUPERUSER pgb_agent. stdout:\n{out}"
    );
    assert!(out.contains("PREFLIGHT FAILED"), "stdout:\n{out}");
    assert!(
        out.contains("pgb_agent_not_superuser") && out.contains("FAIL"),
        "the failing check must name the superuser violation. stdout:\n{out}"
    );

    // Re-harden the agent (clear the superuser bit) so the next RED leg isolates a
    // DIFFERENT failure mode — a stray WRITE GRANT — not the lingering superuser one.
    admin
        .batch_execute("ALTER ROLE pgb_agent NOSUPERUSER;")
        .expect("re-harden pgb_agent");
    let (passed, _out) = run_doctor(_cluster.port);
    assert!(
        passed,
        "sanity: with the superuser bit cleared the doctor passes again before the grant leg"
    );

    // RED #2 (a SECOND, orthogonal failure mode): the WALL's "no write grant
    // anywhere" invariant. Create a demo table and GRANT INSERT on it to pgb_agent —
    // the read WALL must hold ZERO write grant on any user table, so the doctor must
    // FAIL CLOSED and the failing check must be `agent_no_write_grant` (NOT the
    // superuser check, which now passes). This proves the doctor's write-grant check
    // is load-bearing, not just the superuser one.
    admin
        .batch_execute(
            "CREATE TABLE IF NOT EXISTS public.doctor_it_writable (id int PRIMARY KEY); \
             GRANT INSERT ON public.doctor_it_writable TO pgb_agent;",
        )
        .expect("grant a write to pgb_agent");
    let (passed, out) = run_doctor(_cluster.port);
    assert!(
        !passed,
        "doctor must FAIL CLOSED (non-zero) when pgb_agent holds a write grant. stdout:\n{out}"
    );
    assert!(out.contains("PREFLIGHT FAILED"), "stdout:\n{out}");
    assert!(
        out.contains("agent_no_write_grant") && out.contains("FAIL"),
        "the failing check must name the WRITE-GRANT violation (not the superuser one). \
         stdout:\n{out}"
    );
    // The superuser check must be PASSing here — proving this RED leg isolates the
    // write-grant failure and is not masked by the prior superuser failure.
    assert!(
        out.contains("pgb_agent_not_superuser: `pgb_agent` is NOSUPERUSER"),
        "the superuser check must PASS in the write-grant leg (isolated failure). stdout:\n{out}"
    );

    // Reset the grant (and drop the demo table) so the cluster is left clean — the
    // doctor passes once more after the write grant is revoked.
    admin
        .batch_execute(
            "REVOKE INSERT ON public.doctor_it_writable FROM pgb_agent; \
             DROP TABLE IF EXISTS public.doctor_it_writable;",
        )
        .expect("revoke the write grant");
    let (passed, out) = run_doctor(_cluster.port);
    assert!(
        passed,
        "doctor must PASS again once the write grant is revoked (reset). stdout:\n{out}"
    );
}
