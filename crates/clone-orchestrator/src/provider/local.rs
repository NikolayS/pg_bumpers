//! The `local` clone provider — an **isolated `pg_basebackup` clone cluster**
//! (SPEC §12, the founder-approved local-PG18 stand-in for DBLab; the moat).
//!
//! Where the baseline (`none`) rehearses in a rolled-back txn **on the primary**
//! — holding the primary's locks for the rehearsal's duration (SPEC §12) — this
//! provider takes a **physical base backup** of the primary into a **separate
//! PG18 data directory on a dedicated port** and runs the rehearsal *there*. The
//! rehearsal therefore has **zero write/lock impact on the primary**: that
//! isolation is the moat the product sells ("clone rehearsal — pre-flight
//! blast-radius preview on an isolated clone, zero prod impact", SPEC §12 table).
//!
//! # Lifecycle
//!
//! - [`LocalCloneProvider::provision`] (**ledger-first, fail-closed ordering**):
//!   1. allocate a clone id + datadir path under the git-ignored clone root + a
//!      dedicated port;
//!   2. **record the clone in the [`CloneLedger`] BEFORE any prod PII exists on
//!      disk** — the breadcrumb (clone id, owner identity, datadir, port) precedes
//!      `pg_basebackup`, so a SIGKILL anywhere from here on (including during the
//!      whole, minutes-long base backup) leaves a *reapable* orphan record (SPEC
//!      §10.7). This is the BLOCKER fix: the old ordering wrote the datadir first
//!      and the ledger entry only afterward, leaving a window where a prod-PII
//!      datadir existed with no ledger entry the reaper could see;
//!   3. `pg_basebackup -D <datadir> -X stream` from the primary (a consistent
//!      physical copy — it inherits prod's catalog, RLS policies, and column
//!      grants **byte-for-byte**, which is what makes RLS/column-grant parity
//!      *inherent*, SPEC §4);
//!   4. stamp the owner-identity marker inside the datadir (for the
//!      ledger-independent filesystem sweep) and `chmod 0700`;
//!   5. pin the clone to its dedicated port + loopback-only + a private socket
//!      dir (so it can never collide with the primary or 5432);
//!   6. `pg_ctl start` the clone and wait until it accepts connections;
//!   7. return a governance-compliant [`CloneHandle`] pointing at the clone DSN.
//! - [`LocalCloneProvider::destroy`]: `pg_ctl stop -m immediate`, delete the
//!   datadir, and forget the ledger entry — idempotent (mandatory teardown,
//!   SPEC §4).
//!
//! # Governance posture (SPEC §4)
//!
//! - **prod-classified PII** — a physical copy of prod *is* prod data.
//! - **encryption-at-rest** — the clone root is created `0700` under the
//!   git-ignored `/.localstack`-style dir; production deployment mounts it on an
//!   encrypted volume (documented in the PR / [`CloneGovernance`]). The handle
//!   reports `encryption_at_rest: true` to reflect the documented deployment
//!   posture; the on-disk-permissions tightening is enforced here.
//! - **access-logged** — the clone is started with `log_connections=on` +
//!   `log_statement=all` into its own logfile, so every access to the prod-PII
//!   copy is recorded; the handle's `access_log` names that file.
//! - **documented owner + location** — carried on the handle's governance.
//! - **mandatory teardown + orphan-reaper** — see [`destroy`](LocalCloneProvider::destroy)
//!   and [`super::ledger`].

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::ledger::{CloneLedger, LedgerEntry, OwnerIdentity, write_owner_marker};
use super::{
    CloneError, CloneGovernance, CloneHandle, CloneProvider, DataClassification, ProviderKind,
};

/// How to reach the primary the clone is taken from (a base-backup needs a
/// replication-capable connection, not just a SQL one).
#[derive(Debug, Clone)]
pub struct PrimaryRef {
    /// Primary host (loopback for the local substrate).
    pub host: String,
    /// Primary port (a dedicated high port — **never** 5432).
    pub port: u16,
    /// A user with the `REPLICATION` attribute (for `pg_basebackup`).
    pub repl_user: String,
    /// The database to connect to for the post-backup parity/seed checks.
    pub dbname: String,
}

impl PrimaryRef {
    /// A libpq DSN for an ordinary SQL connection to the primary.
    pub fn sql_dsn(&self) -> String {
        format!(
            "host={} port={} user={} dbname={}",
            self.host, self.port, self.repl_user, self.dbname
        )
    }
}

/// Configuration for the [`LocalCloneProvider`].
#[derive(Debug, Clone)]
pub struct LocalCloneConfig {
    /// PG18 bin dir holding `pg_basebackup` / `pg_ctl` (`/opt/homebrew/opt/postgresql@18/bin`).
    pub pg_bin: PathBuf,
    /// The git-ignored root under which clone datadirs are created (e.g.
    /// `<repo>/.localstack/clones`). Created `0700`.
    pub clone_root: PathBuf,
    /// The dedicated TCP port for the clone postmaster (**never** 5432, and
    /// distinct from the primary + any other live cluster).
    pub clone_port: u16,
    /// How to reach the primary.
    pub primary: PrimaryRef,
    /// The documented owner of the clone (SPEC §4).
    pub owner: String,
}

/// The `local` clone provider (SPEC §12). Holds its config + ledger; each
/// `provision` makes one isolated clone, each `destroy` tears one down.
pub struct LocalCloneProvider {
    cfg: LocalCloneConfig,
    ledger: CloneLedger,
    /// Monotonic suffix so repeated provisions get distinct datadirs/ids.
    seq: u32,
}

impl LocalCloneProvider {
    /// Build a provider with an explicit ledger (so the reaper and the provider
    /// share one out-of-process ledger).
    pub fn new(cfg: LocalCloneConfig, ledger: CloneLedger) -> Self {
        LocalCloneProvider {
            cfg,
            ledger,
            seq: 0,
        }
    }

    /// The ledger this provider records its clones in (shared with the reaper).
    pub fn ledger(&self) -> &CloneLedger {
        &self.ledger
    }

    fn tool(&self, name: &str) -> PathBuf {
        self.cfg.pg_bin.join(name)
    }

    fn run(&self, cmd: &mut Command, what: &str) -> Result<String, CloneError> {
        let out = cmd
            .output()
            .map_err(|e| CloneError::Tooling(format!("{what}: spawn failed: {e}")))?;
        if !out.status.success() {
            return Err(CloneError::Provision(format!(
                "{what} failed ({}): {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }
}

impl CloneProvider for LocalCloneProvider {
    fn provision(&mut self) -> Result<CloneHandle, CloneError> {
        self.seq += 1;
        let clone_id = format!("local-clone-{}-{}", std::process::id(), self.seq);

        // (0) The git-ignored clone root, 0700 (at-rest tightening).
        fs::create_dir_all(&self.cfg.clone_root).map_err(|e| {
            CloneError::Tooling(format!("clone root {}: {e}", self.cfg.clone_root.display()))
        })?;
        set_mode_0700(&self.cfg.clone_root)?;

        let datadir = self.cfg.clone_root.join(&clone_id);
        if datadir.exists() {
            fs::remove_dir_all(&datadir).ok();
        }
        let logfile = self.cfg.clone_root.join(format!("{clone_id}.log"));
        // A private socket dir for the clone. It MUST be short: macOS caps the
        // Unix-socket path at 103 bytes and the git-ignored clone root is long.
        // The clone is reached over TCP (loopback, dedicated port) anyway, so the
        // socket is only for the postmaster's own use; we put it under the system
        // tempdir keyed by the clone port (a short, unique path).
        let sockdir = std::env::temp_dir().join(format!("pgb-clone-{}", self.cfg.clone_port));
        if sockdir.exists() {
            fs::remove_dir_all(&sockdir).ok();
        }
        fs::create_dir_all(&sockdir).map_err(|e| CloneError::Tooling(format!("sock dir: {e}")))?;

        // (1) RECORD IN THE LEDGER **before any prod PII exists on disk** — the
        //     fail-closed ordering (SPEC §10.7, the BLOCKER fix). The breadcrumb
        //     (clone id, owner identity, datadir, port) is written BEFORE
        //     pg_basebackup runs, so a SIGKILL anywhere in the (minutes-long) base
        //     backup leaves a reapable orphan record. `destroy_orphan` tolerates a
        //     missing/partial datadir and absent postmaster.pid, so an early entry
        //     reaps cleanly whether the crash hits during basebackup, conf, or
        //     start. The owner identity (pid + start-time) defeats pid reuse.
        let owner = OwnerIdentity::current();
        let entry = LedgerEntry {
            clone_id: clone_id.clone(),
            datadir: datadir.clone(),
            port: self.cfg.clone_port,
            owner_pid: owner.pid,
            owner_start: owner.start.clone(),
        };
        self.ledger.record(&entry)?;

        // (2) pg_basebackup — a consistent physical copy of the primary. -X
        //     stream pulls the needed WAL so the clone is self-consistent; -R is
        //     omitted so the clone comes up as a normal (non-standby) cluster we
        //     can write a rolled-back rehearsal txn against.
        self.run(
            Command::new(self.tool("pg_basebackup"))
                .arg("--pgdata")
                .arg(&datadir)
                .arg("--wal-method=stream")
                .arg("--checkpoint=fast")
                .arg("--progress")
                .arg("--no-sync")
                .arg("--host")
                .arg(&self.cfg.primary.host)
                .arg("--port")
                .arg(self.cfg.primary.port.to_string())
                .arg("--username")
                .arg(&self.cfg.primary.repl_user)
                .arg("--no-password"),
            "pg_basebackup",
        )?;
        set_mode_0700(&datadir)?;

        // (2b) Stamp the owner-identity marker INSIDE the datadir, now that it
        //      exists (pg_basebackup requires an empty/absent target, so this must
        //      follow it). This lets the ledger-independent filesystem sweep
        //      attribute the datadir to its owner even if the ledger entry is ever
        //      lost — a clone whose marker names a dead/recycled owner (or whose
        //      marker is missing, e.g. a crash mid-basebackup) is reaped
        //      fail-closed.
        write_owner_marker(&datadir, &owner)?;

        // (4) Pin the clone to its dedicated port + loopback + private socket +
        //     access logging (every read of the prod-PII copy is logged, §4).
        //     Written to postgresql.auto.conf so it overrides the inherited conf.
        let auto_conf = datadir.join("postgresql.auto.conf");
        let conf = format!(
            "\n# pg_bumpers local clone — isolated rehearsal target (SPEC §12)\n\
             port = {port}\n\
             listen_addresses = '127.0.0.1'\n\
             unix_socket_directories = '{sock}'\n\
             # access-logging the prod-PII clone (SPEC §4 clone governance)\n\
             log_connections = on\n\
             log_disconnections = on\n\
             log_statement = 'all'\n\
             logging_collector = off\n",
            port = self.cfg.clone_port,
            sock = sockdir.display(),
        );
        append_file(&auto_conf, &conf)?;

        // A standby.signal could be left by some backup modes; ensure the clone
        // is a normal read-write cluster (we rehearse + roll back on it).
        let _ = fs::remove_file(datadir.join("standby.signal"));
        let _ = fs::remove_file(datadir.join("recovery.signal"));

        // (5) Start the clone postmaster and wait for it to accept connections.
        self.run(
            Command::new(self.tool("pg_ctl"))
                .arg("-D")
                .arg(&datadir)
                .arg("-l")
                .arg(&logfile)
                .arg("-w")
                .arg("-t")
                .arg("60")
                .arg("start"),
            "pg_ctl start",
        )?;

        // (6) The clone DSN (over TCP on the dedicated port; loopback only).
        let conn = format!(
            "host=127.0.0.1 port={} user={} dbname={}",
            self.cfg.clone_port, self.cfg.primary.repl_user, self.cfg.primary.dbname
        );

        // The clone LSN at provision time (read from the freshly-started clone).
        let lsn = read_clone_lsn(&self.tool("psql"), &conn).unwrap_or_else(|_| "0/0".to_string());

        Ok(CloneHandle {
            provider: ProviderKind::Local,
            clone_id,
            conn,
            lsn,
            // Staleness from prod is bounded by the backup point; we report 0
            // here because the rehearsal does not depend on real-time currency
            // (the apply path re-checks the PK set against the live primary).
            staleness_lsn_bytes: 0,
            governance: CloneGovernance {
                // The clone root is 0700 and (in production) on an encrypted
                // volume — documented at-rest posture.
                encryption_at_rest: true,
                access_log: logfile.display().to_string(),
                owner: self.cfg.owner.clone(),
                location: datadir.display().to_string(),
                classification: DataClassification::ProdPii,
            },
        })
    }

    fn destroy(&mut self, handle: &CloneHandle) -> Result<(), CloneError> {
        let datadir = self.cfg.clone_root.join(&handle.clone_id);

        // Stop the postmaster (immediate — no checkpoint needed, it's throwaway).
        // Ignore failure: a missing/already-stopped cluster is fine; the dir
        // removal + ledger forget below complete the teardown.
        if datadir.join("postmaster.pid").exists() {
            let _ = Command::new(self.tool("pg_ctl"))
                .arg("-D")
                .arg(&datadir)
                .arg("-m")
                .arg("immediate")
                .arg("-w")
                .arg("-t")
                .arg("30")
                .arg("stop")
                .output();
        }

        // Delete the on-disk prod-PII copy + the private socket dir + log.
        if datadir.exists() {
            fs::remove_dir_all(&datadir).map_err(|e| {
                CloneError::Teardown(format!("rm datadir {}: {e}", datadir.display()))
            })?;
        }
        let _ = fs::remove_dir_all(
            std::env::temp_dir().join(format!("pgb-clone-{}", self.cfg.clone_port)),
        );
        let _ = fs::remove_file(self.cfg.clone_root.join(format!("{}.log", handle.clone_id)));

        // Forget the ledger entry only now that the cluster is physically gone.
        self.ledger.forget(&handle.clone_id)?;
        Ok(())
    }
}

/// Read `pg_current_wal_lsn()` from the clone via a one-shot `psql` (from the
/// configured PG18 bin dir, since `psql` is keg-only / not on PATH here). We
/// avoid adding a runtime `postgres` dep to the library by shelling out for this
/// single read; failure is non-fatal (the LSN is informational on the handle).
fn read_clone_lsn(psql: &Path, conn: &str) -> Result<String, CloneError> {
    // conn is "host=.. port=.. user=.. dbname=..": psql accepts it as a single
    // connection string argument.
    // -X skips any ~/.psqlrc (which can print banners/timing that would pollute
    // the scalar output); -q quiets; -tA gives an unaligned, header-less scalar.
    let out = Command::new(psql)
        .arg("-X")
        .arg("-q")
        .arg(conn)
        .arg("-tAc")
        .arg("SELECT pg_current_wal_lsn()")
        .output()
        .map_err(|e| CloneError::Tooling(format!("psql lsn: {e}")))?;
    if !out.status.success() {
        return Err(CloneError::Tooling("psql lsn query failed".into()));
    }
    let lsn = String::from_utf8_lossy(&out.stdout).trim().to_string();
    // Defensive: only accept something that looks like an LSN (`hi/lo`); the
    // field is informational, so fall back rather than store noise.
    if lsn.split_once('/').is_some_and(|(h, l)| {
        !h.is_empty()
            && !l.is_empty()
            && h.chars().all(|c| c.is_ascii_hexdigit())
            && l.chars().all(|c| c.is_ascii_hexdigit())
    }) {
        Ok(lsn)
    } else {
        Err(CloneError::Tooling(format!(
            "unexpected lsn output: {lsn:?}"
        )))
    }
}

/// `chmod 0700` a path (at-rest tightening of the prod-PII clone dir, SPEC §4).
fn set_mode_0700(path: &Path) -> Result<(), CloneError> {
    use std::os::unix::fs::PermissionsExt;
    let perms = fs::Permissions::from_mode(0o700);
    fs::set_permissions(path, perms)
        .map_err(|e| CloneError::Tooling(format!("chmod 0700 {}: {e}", path.display())))
}

/// Append `text` to `path` (creating it if needed).
fn append_file(path: &Path, text: &str) -> Result<(), CloneError> {
    use std::io::Write;
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| CloneError::Tooling(format!("open {}: {e}", path.display())))?;
    f.write_all(text.as_bytes())
        .map_err(|e| CloneError::Tooling(format!("append {}: {e}", path.display())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primary_ref_builds_sql_dsn() {
        let p = PrimaryRef {
            host: "127.0.0.1".into(),
            port: 54351,
            repl_user: "postgres".into(),
            dbname: "prod".into(),
        };
        assert_eq!(
            p.sql_dsn(),
            "host=127.0.0.1 port=54351 user=postgres dbname=prod"
        );
    }

    #[test]
    fn append_and_chmod_helpers_work() {
        let dir = std::env::temp_dir().join(format!("pgb-local-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        set_mode_0700(&dir).unwrap();
        let f = dir.join("c.conf");
        append_file(&f, "port = 1\n").unwrap();
        append_file(&f, "x = 2\n").unwrap();
        let body = fs::read_to_string(&f).unwrap();
        assert!(body.contains("port = 1"));
        assert!(body.contains("x = 2"));
        fs::remove_dir_all(&dir).ok();
    }
}
