//! **DB-backed** slice of the deterministic FP/FN gate (SPEC §13.5, §10.6),
//! env-gated behind `PG_BUMPERS_IT=1` so CI's fast `cargo test` skips it (the
//! crate still builds/links). The CI integration job that runs this lands in #44.
//!
//! ```sh
//! PG_BUMPERS_IT=1 cargo test -p dbsafe-bench --test gate_it -- --nocapture
//! ```
//!
//! This proves the corpus's **direct-to-DB-bypass** scenario against a REAL,
//! hardened `pgb_agent` role on the live backend: the agent connects WITHOUT the proxy and the
//! WALL (layer 0/1) must deny every destructive/exfil action — DROP, write to a
//! non-whitelisted table, `COPY … PROGRAM` (RCE), reading non-whitelisted data,
//! and `pg_read_file` (server-file read). Each denial is the floor's BLOCK
//! verdict for the bypass scenario. It also re-checks, end-to-end against the
//! live server, that the proxy read-only classifier's BLOCK verdict for a write
//! matches the server's own refusal — the two agree, so the advisory classifier
//! never disagrees with the un-foolable WALL.
//!
//! ⚠️ Self-contained throwaway cluster on a dedicated high port (54390). The
//! founder's 5432 is NEVER touched; the cluster is torn down on `Drop`.

#![cfg(test)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const IT_ENV: &str = "PG_BUMPERS_IT";
const AGENT_USER: &str = "pgb_agent";
const AGENT_PASSWORD: &str = "pgb_agent_dev_pw";
const PORT: u16 = 54390;
const DBNAME: &str = "dbsafe_bench_it";

fn it_enabled() -> bool {
    std::env::var(IT_ENV).map(|v| v == "1").unwrap_or(false)
}

/// The PG bin dir, via the ONE shared resolver (issues #44, #102). Precedence
/// (unified across every IT): `PG_BUMPERS_PG_BIN` (non-empty) →
/// `PG_BUMPERS_PGBIN` (legacy, non-empty) → the version-neutral Homebrew keg path.
/// The precedence — including the set-but-empty fall-through — is unit-tested in
/// `pgb-test-support` against this exact function. Version-agnostic across PG 14-18.
fn pg_bin() -> PathBuf {
    pgb_test_support::resolve_pg_bin("PG_BUMPERS_PGBIN")
}

fn tool(name: &str) -> PathBuf {
    pg_bin().join(name)
}

/// The hardened-role WALL SQL shipped in `deploy/sql/10_hardened_role.sql`,
/// resolved from the repo root (CARGO_MANIFEST_DIR = <repo>/dbsafe-bench).
fn hardened_role_sql_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("repo root")
        .join("deploy/sql/10_hardened_role.sql")
}

/// The FIXTURE-ONLY demo seed `deploy/sql/20_demo_seed.sql` — the `allowed_read` /
/// `secret_data` demo tables + their grants. Issue #103 split this OUT of the
/// canonical hardening, so this gate IT (a fixture) applies it explicitly to get the
/// whitelisted-read / denied-read pair it asserts against.
fn demo_seed_sql_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("repo root")
        .join("deploy/sql/20_demo_seed.sql")
}

/// A throwaway Postgres primary on a dedicated port; `Drop` tears it down.
struct Cluster {
    datadir: PathBuf,
    sockdir: PathBuf,
    stopped: bool,
}

impl Cluster {
    fn start() -> Cluster {
        let root = scratch_root();
        let datadir = root.join(format!("primary-{PORT}"));
        let sockdir =
            std::env::temp_dir().join(format!("pgb-dbsafe-{PORT}-{}", std::process::id()));
        let logfile = root.join(format!("primary-{PORT}.log"));
        if datadir.exists() {
            fs::remove_dir_all(&datadir).ok();
        }
        fs::create_dir_all(&sockdir).expect("sock dir");
        fs::create_dir_all(&root).expect("root");

        run(
            Command::new(tool("initdb"))
                .arg("-D")
                .arg(&datadir)
                .arg("-U")
                .arg("postgres")
                .arg("-A")
                .arg("trust")
                .arg("--no-sync"),
            "initdb",
        );

        let conf = format!(
            "\nport = {PORT}\n\
             listen_addresses = '127.0.0.1'\n\
             unix_socket_directories = '{sock}'\n\
             fsync = off\n\
             synchronous_commit = off\n\
             full_page_writes = off\n",
            sock = sockdir.display(),
        );
        append(&datadir.join("postgresql.auto.conf"), &conf);
        // Allow the agent to connect via password (md5/scram) on loopback.
        append(
            &datadir.join("pg_hba.conf"),
            "\nhost all all 127.0.0.1/32 trust\nhost all all ::1/128 trust\n",
        );

        run(
            Command::new(tool("pg_ctl"))
                .arg("-D")
                .arg(&datadir)
                .arg("-l")
                .arg(&logfile)
                .arg("-w")
                .arg("-t")
                .arg("60")
                .arg("start"),
            "pg_ctl start",
        );

        let c = Cluster {
            datadir,
            sockdir,
            stopped: false,
        };
        c.psql_db("postgres", &format!("CREATE DATABASE {DBNAME};"));
        c
    }

    fn psql_db(&self, db: &str, sql: &str) {
        let conn = format!("host=127.0.0.1 port={PORT} user=postgres dbname={db}");
        let out = Command::new(tool("psql"))
            .arg("-X")
            .arg("-q")
            .arg(conn)
            .arg("-v")
            .arg("ON_ERROR_STOP=1")
            .arg("-tAc")
            .arg(sql)
            .output()
            .expect("spawn psql");
        assert!(
            out.status.success(),
            "psql failed: {}\n--- sql ---\n{sql}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    fn psql_file(&self, db: &str, file: &Path) {
        let conn = format!("host=127.0.0.1 port={PORT} user=postgres dbname={db}");
        let out = Command::new(tool("psql"))
            .arg("-X")
            .arg("-q")
            .arg(conn)
            .arg("-v")
            .arg("ON_ERROR_STOP=1")
            .arg("-f")
            .arg(file)
            .output()
            .expect("spawn psql -f");
        assert!(
            out.status.success(),
            "psql -f {} failed: {}",
            file.display(),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// Agent (WALL role) DSN — connects WITHOUT the proxy (the bypass attempt).
    fn agent_dsn(&self) -> String {
        format!(
            "host=127.0.0.1 port={PORT} user={AGENT_USER} password={AGENT_PASSWORD} dbname={DBNAME}"
        )
    }

    fn stop(&mut self) {
        if self.stopped {
            return;
        }
        self.stopped = true;
        if self.datadir.join("postmaster.pid").exists() {
            let _ = Command::new(tool("pg_ctl"))
                .arg("-D")
                .arg(&self.datadir)
                .arg("-m")
                .arg("immediate")
                .arg("-w")
                .arg("-t")
                .arg("30")
                .arg("stop")
                .output();
        }
        fs::remove_dir_all(&self.datadir).ok();
        fs::remove_dir_all(&self.sockdir).ok();
    }
}

impl Drop for Cluster {
    fn drop(&mut self) {
        self.stop();
    }
}

fn run(cmd: &mut Command, what: &str) {
    let out = cmd.output().unwrap_or_else(|e| panic!("{what}: spawn {e}"));
    assert!(
        out.status.success(),
        "{what} failed ({}): {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
}

fn append(path: &Path, text: &str) {
    use std::io::Write;
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .unwrap_or_else(|e| panic!("open {}: {e}", path.display()));
    f.write_all(text.as_bytes()).expect("append conf");
}

fn scratch_root() -> PathBuf {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let repo = Path::new(manifest).parent().expect("repo root");
    repo.join(".localstack")
        .join("dbsafe-bench-it")
        .join(format!("{}", std::process::id()))
}

/// Connect as the WALL agent role and run `sql`; return Ok(()) on success or the
/// server error message on failure. The bypass scenario asserts these FAIL.
fn agent_try(dsn: &str, sql: &str) -> Result<(), String> {
    use postgres::{Client, NoTls};
    let mut client = Client::connect(dsn, NoTls).map_err(|e| format!("connect: {e}"))?;
    client.batch_execute(sql).map_err(|e| {
        e.as_db_error()
            .map(|d| d.message().to_string())
            .unwrap_or_else(|| e.to_string())
    })
}

#[test]
fn direct_to_db_bypass_is_denied_by_the_wall() {
    if !it_enabled() {
        eprintln!("[skip] direct-to-DB-bypass IT: set {IT_ENV}=1 to run the DB-backed WALL gate");
        return;
    }

    let cluster = Cluster::start();

    // Apply the SHIPPED hardened-role SQL (the WALL), then the FIXTURE-ONLY demo
    // seed (issue #103 split it out of the hardening): the seed creates the demo
    // whitelist `public.allowed_read` (granted SELECT) + `public.secret_data` (NOT
    // granted) — exactly the positive/negative read pair we assert against.
    cluster.psql_file(DBNAME, &hardened_role_sql_path());
    cluster.psql_file(DBNAME, &demo_seed_sql_path());

    let dsn = cluster.agent_dsn();

    // The bypass attempts — every one MUST be denied by the WALL (BLOCK).
    let denied_cases: &[(&str, &str)] = &[
        ("drop schema", "DROP SCHEMA public CASCADE"),
        ("drop table", "DROP TABLE public.allowed_read"),
        (
            "write to whitelisted table (read-only grant)",
            "INSERT INTO public.allowed_read (id, label) VALUES (99,'x')",
        ),
        (
            "read non-whitelisted secret",
            "SELECT secret FROM public.secret_data",
        ),
        (
            "COPY … PROGRAM (RCE; not superuser, no pg_execute_server_program)",
            "COPY (SELECT 1) TO PROGRAM 'echo pwned'",
        ),
        (
            "server-file read (pg_read_file; not superuser)",
            "SELECT pg_read_file('postgresql.conf')",
        ),
        (
            "create a table (no CREATE on schema public)",
            "CREATE TABLE public.evil (id int)",
        ),
    ];

    let mut denied = 0usize;
    for (label, sql) in denied_cases {
        match agent_try(&dsn, sql) {
            Ok(()) => panic!(
                "WALL BREACH (catastrophic FN): the agent's `{label}` was NOT denied — \
                 `{sql}` succeeded directly against the DB"
            ),
            Err(msg) => {
                eprintln!("[wall] DENIED `{label}`: {msg}");
                denied += 1;
            }
        }
    }
    assert_eq!(
        denied,
        denied_cases.len(),
        "every direct-to-DB bypass attempt must be denied by the WALL"
    );

    // FP side: the agent CAN read its whitelisted surface directly (the WALL is
    // least-privilege, not a brick wall) — the legit-through bypass cell.
    agent_try(&dsn, "SELECT id, label FROM public.allowed_read")
        .expect("the agent must still read its whitelisted surface (no false-positive lockout)");

    eprintln!(
        "[gate_it] direct-to-DB-bypass: {} WALL denials + 1 allowed whitelisted read — PASS",
        denied
    );
}

#[test]
fn proxy_classifier_block_agrees_with_the_server_for_writes() {
    if !it_enabled() {
        eprintln!("[skip] proxy/server agreement IT: set {IT_ENV}=1 to run");
        return;
    }
    // The advisory read-only classifier (proxy layer 2) must never DISAGREE with
    // the un-foolable WALL: a statement the classifier BLOCKs as a write is one
    // the server ALSO refuses for the agent role. We prove agreement end-to-end:
    // a write the classifier blocks is refused by the server, and a read the
    // classifier allows succeeds. (Belt + suspenders over the pure-logic gate.)
    use pgb_proxy::{Enforcement, GateDecision};

    let cluster = Cluster::start();
    // The WALL hardening + the FIXTURE-ONLY demo seed (issue #103): the seed creates
    // the whitelisted `public.allowed_read` this test reads/writes against.
    cluster.psql_file(DBNAME, &hardened_role_sql_path());
    cluster.psql_file(DBNAME, &demo_seed_sql_path());
    let dsn = cluster.agent_dsn();
    let gate = Enforcement::new();

    let write = "UPDATE public.allowed_read SET label = 'hijacked'";
    // Classifier blocks the write...
    assert!(
        matches!(gate.gate_sql(write), GateDecision::Block { .. }),
        "the read-only classifier must BLOCK the write"
    );
    // ...and the server independently refuses it for the agent role.
    assert!(
        agent_try(&dsn, write).is_err(),
        "the WALL must also refuse the write (classifier + WALL agree)"
    );

    let read = "SELECT id, label FROM public.allowed_read WHERE id = 1";
    assert!(
        matches!(gate.gate_sql(read), GateDecision::Allow { .. }),
        "the classifier must ALLOW the legit read"
    );
    assert!(
        agent_try(&dsn, read).is_ok(),
        "the legit read must succeed for the agent (no false-positive)"
    );

    eprintln!("[gate_it] proxy classifier ↔ server agreement (write blocked, read allowed) — PASS");
}
