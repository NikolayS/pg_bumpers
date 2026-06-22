//! Self-contained throwaway PG18 **primary** cluster for the clone-governance
//! integration tests (env-gated `PG_BUMPERS_IT=1`).
//!
//! Unlike `common::create_seeded_db` (which assumes a server is already up on a
//! port), the clone-governance tests must own a real *primary cluster* on disk so
//! the `local` provider can `pg_basebackup` it into an isolated clone. This module
//! `initdb`s + starts a primary on a **dedicated high port** under a git-ignored
//! dir, configured replication-ready, and tears it down cleanly.
//!
//! ⚠️ Dedicated ports far from the founder's 5432 (and from local-stack's
//! 54321-3): the primary uses **54360 + offset**, the clone **54370 + offset**.
//! Loopback-only, trust auth on loopback, private socket dir.
#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The PG18 bin dir (override via `PG_BUMPERS_PGBIN`).
pub fn pg_bin() -> PathBuf {
    PathBuf::from(
        std::env::var("PG_BUMPERS_PGBIN")
            .unwrap_or_else(|_| "/opt/homebrew/opt/postgresql@18/bin".to_string()),
    )
}

fn tool(name: &str) -> PathBuf {
    pg_bin().join(name)
}

/// A running throwaway primary cluster. `Drop` tears it down (stop + rm).
pub struct Primary {
    pub datadir: PathBuf,
    pub port: u16,
    pub sockdir: PathBuf,
    pub repl_user: String,
    pub dbname: String,
    stopped: bool,
}

impl Primary {
    /// `initdb` + start a primary on `port`, under `root` (git-ignored), seeding
    /// the given SQL into a fresh database `dbname`. Replication-ready so
    /// `pg_basebackup` works.
    pub fn start(root: &Path, port: u16, dbname: &str, seed_sql: &str) -> Primary {
        let datadir = root.join(format!("primary-{port}"));
        // The Unix-socket dir MUST be short: macOS caps the socket path at 103
        // bytes and our git-ignored scratch root is long. Connections are all TCP
        // loopback anyway, so the socket is only for `pg_ctl`'s own readiness
        // probe. Put it under the system tempdir keyed by port (short path).
        let sockdir = short_sockdir(&format!("pgb-prim-{port}"));
        let logfile = root.join(format!("primary-{port}.log"));
        if datadir.exists() {
            fs::remove_dir_all(&datadir).ok();
        }
        fs::create_dir_all(&sockdir).expect("sock dir");

        // initdb: trust auth (loopback throwaway), no fsync for speed.
        run(
            Command::new(tool("initdb"))
                .arg("-D")
                .arg(&datadir)
                .arg("-U")
                .arg("postgres")
                .arg("-A")
                .arg("trust")
                .arg("--no-sync"),
            "initdb primary",
        );

        // Pin to a dedicated port + loopback + replication-ready.
        let conf = format!(
            "\nport = {port}\n\
             listen_addresses = '127.0.0.1'\n\
             unix_socket_directories = '{sock}'\n\
             wal_level = replica\n\
             max_wal_senders = 8\n\
             max_replication_slots = 8\n\
             fsync = off\n\
             synchronous_commit = off\n\
             full_page_writes = off\n",
            sock = sockdir.display(),
        );
        append(&datadir.join("postgresql.auto.conf"), &conf);

        // Allow replication connections on loopback (trust).
        append(
            &datadir.join("pg_hba.conf"),
            "\nhost replication postgres 127.0.0.1/32 trust\n\
             host replication postgres ::1/128 trust\n\
             local replication postgres trust\n",
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
            "pg_ctl start primary",
        );

        let mut p = Primary {
            datadir,
            port,
            sockdir,
            repl_user: "postgres".into(),
            dbname: dbname.into(),
            stopped: false,
        };
        p.create_and_seed(dbname, seed_sql);
        p
    }

    fn create_and_seed(&mut self, dbname: &str, seed_sql: &str) {
        // CREATE DATABASE on the default `postgres` db, then seed into it.
        self.psql_db("postgres", &format!("CREATE DATABASE {dbname};"));
        self.psql_db(dbname, seed_sql);
    }

    /// A libpq DSN (TCP, loopback) for `self.dbname`.
    pub fn dsn(&self) -> String {
        format!(
            "host=127.0.0.1 port={} user={} dbname={}",
            self.port, self.repl_user, self.dbname
        )
    }

    /// Run SQL against database `db` via the keg `psql` (not on PATH).
    pub fn psql_db(&self, db: &str, sql: &str) {
        let conn = format!(
            "host=127.0.0.1 port={} user={} dbname={}",
            self.port, self.repl_user, db
        );
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

    /// Run a query and return its single scalar text result (trimmed).
    pub fn psql_scalar(&self, sql: &str) -> String {
        let out = Command::new(tool("psql"))
            .arg("-X")
            .arg("-q")
            .arg(self.dsn())
            .arg("-tAc")
            .arg(sql)
            .output()
            .expect("spawn psql");
        assert!(
            out.status.success(),
            "psql scalar failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    /// Explicit teardown (also runs on `Drop`).
    pub fn stop(&mut self) {
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

impl Drop for Primary {
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

/// A short Unix-socket dir under the system tempdir (macOS caps the socket path
/// at 103 bytes; our scratch root is far longer). Unique per `tag`.
fn short_sockdir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("{tag}-{}", std::process::id()));
    fs::create_dir_all(&dir).expect("sock dir");
    dir
}

/// A git-ignored scratch root for a test's clusters (under the repo's
/// `.localstack/` so `.gitignore` covers it; falls back to the system tempdir).
pub fn scratch_root(tag: &str) -> PathBuf {
    let base = repo_localstack_dir().unwrap_or_else(std::env::temp_dir);
    base.join("clone-governance-it").join(format!(
        "{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

/// `<repo>/.localstack` if we can locate the repo root from `CARGO_MANIFEST_DIR`.
fn repo_localstack_dir() -> Option<PathBuf> {
    // CARGO_MANIFEST_DIR = <repo>/crates/clone-orchestrator.
    let manifest = std::env::var("CARGO_MANIFEST_DIR").ok()?;
    let repo = Path::new(&manifest).parent()?.parent()?;
    Some(repo.join(".localstack"))
}

/// The deterministic seed for the clone-governance tests: the same accounts /
/// entries / trigger schema as the dry-run IT, **plus** RLS policies + per-column
/// grants on a dedicated agent role, so the RLS/column-grant parity check has
/// something real to compare across prod↔clone.
pub const GOV_SEED_SQL: &str = r#"
    CREATE TABLE public.accounts (
        id       int    PRIMARY KEY,
        owner    text   NOT NULL,
        balance  bigint NOT NULL
    );

    CREATE TABLE public.entries (
        account_id int  NOT NULL REFERENCES public.accounts(id) ON DELETE CASCADE,
        line_no    int  NOT NULL,
        memo       text NOT NULL,
        amount     bigint NOT NULL,
        PRIMARY KEY (account_id, line_no)
    );

    CREATE TABLE public.account_audit (
        audit_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        account_id int  NOT NULL,
        op       text  NOT NULL
    );

    CREATE FUNCTION public.accounts_audit() RETURNS trigger
    LANGUAGE plpgsql AS $$
    BEGIN
        IF (TG_OP = 'DELETE') THEN
            INSERT INTO public.account_audit(account_id, op) VALUES (OLD.id, TG_OP);
            RETURN OLD;
        ELSE
            INSERT INTO public.account_audit(account_id, op) VALUES (NEW.id, TG_OP);
            RETURN NEW;
        END IF;
    END;
    $$;

    CREATE TRIGGER accounts_audit_aud
        AFTER UPDATE OR DELETE ON public.accounts
        FOR EACH ROW EXECUTE FUNCTION public.accounts_audit();

    -- A prod-classified agent role with RLS + column grants (the parity surface).
    CREATE ROLE pgb_agent NOLOGIN;

    -- Row-level security: the agent only sees its own tenant's rows.
    ALTER TABLE public.accounts ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.accounts FORCE ROW LEVEL SECURITY;
    CREATE POLICY accounts_tenant_isolation ON public.accounts
        FOR ALL TO pgb_agent
        USING (owner = current_setting('app.tenant', true));

    -- Column-level grants: the agent may read owner but NOT balance (PII).
    GRANT SELECT (id, owner) ON public.accounts TO pgb_agent;
    GRANT SELECT (account_id, line_no, memo) ON public.entries TO pgb_agent;

    INSERT INTO public.accounts(id, owner, balance)
    SELECT g, 'owner-' || g, (g * 1000)::bigint
    FROM generate_series(1, 8) AS g;

    INSERT INTO public.entries(account_id, line_no, memo, amount)
    SELECT a.id, ln, 'memo-' || a.id || '-' || ln, (a.id * 10 + ln)::bigint
    FROM public.accounts a, generate_series(1, 2) AS ln;
"#;
