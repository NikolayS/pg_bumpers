//! The clone ledger + orphan-reaper (SPEC §10.7 "teardown-failure handling =
//! reaper/GC + orphan-clone alarm + test asserting no clone survives a killed
//! orchestrator").
//!
//! An orphaned clone is **unencrypted prod PII left running** — the CISO veto we
//! sell against. So a clone must NOT survive the orchestrator that made it. The
//! mechanism, mirroring the local-stack's out-of-tree PID ledger:
//!
//! 1. **Before** handing a [`CloneHandle`](super::CloneHandle) out, the provider
//!    appends a [`LedgerEntry`] (datadir, port, pidfile, owner pid) to an
//!    **out-of-process ledger file** — a directory of one JSON file per live
//!    clone. The file survives the orchestrator's death (even SIGKILL).
//! 2. On clean teardown the provider removes the entry once the cluster is gone.
//! 3. If the orchestrator dies mid-rehearsal, the entry is left behind. A
//!    [`reap_orphans`] pass — run by a sidecar/cron, or by the next orchestrator
//!    start — destroys every clone whose owning pid is no longer alive
//!    (stop the postmaster, delete the datadir) and raises an [`OrphanAlarm`].
//!
//! The reaper is **pure-Rust** (no shell) so it works even when the orchestrator
//! that wrote the entry is gone: it reads the pidfile, signals the postmaster,
//! waits for it to exit, then removes the datadir. The integration test kills an
//! orchestrator mid-rehearsal and asserts the reaper leaves no cluster / process
//! / dir.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};

use super::CloneError;

/// One live clone recorded in the ledger. Carries everything the reaper needs to
/// destroy the clone **without** the provider that made it — it is the contract
/// that lets a fresh process clean up a dead orchestrator's orphan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerEntry {
    /// The clone's stable id (matches [`CloneHandle::clone_id`](super::CloneHandle::clone_id)).
    pub clone_id: String,
    /// The clone cluster's data directory (to delete on reap).
    pub datadir: PathBuf,
    /// The clone postmaster's TCP port (for diagnostics / the alarm).
    pub port: u16,
    /// The pid of the orchestrator process that owns this clone. The reaper
    /// treats the clone as an orphan once this pid is no longer alive.
    pub owner_pid: u32,
}

impl LedgerEntry {
    /// The clone postmaster's pidfile inside its datadir.
    pub fn pidfile(&self) -> PathBuf {
        self.datadir.join("postmaster.pid")
    }
}

/// An out-of-process ledger of live clones (SPEC §10.7). It is a directory
/// holding one JSON file per clone, so concurrent providers never clobber each
/// other and a crash leaves a readable record. The directory lives **outside**
/// the clone datadirs (it must survive `rm -rf <datadir>`).
#[derive(Debug, Clone)]
pub struct CloneLedger {
    dir: PathBuf,
}

impl CloneLedger {
    /// Open (creating if needed) a ledger rooted at `dir`.
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self, CloneError> {
        let dir = dir.into();
        fs::create_dir_all(&dir)
            .map_err(|e| CloneError::Tooling(format!("ledger dir {}: {e}", dir.display())))?;
        Ok(CloneLedger { dir })
    }

    /// The ledger directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn entry_path(&self, clone_id: &str) -> PathBuf {
        // clone_id is provider-generated (a sanitized token), but be defensive.
        let safe: String = clone_id
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        self.dir.join(format!("{safe}.json"))
    }

    /// Record a live clone (called by the provider **before** the handle is used,
    /// so a crash leaves a reapable orphan record).
    pub fn record(&self, entry: &LedgerEntry) -> Result<(), CloneError> {
        let json = serde_json::to_vec_pretty(entry)
            .map_err(|e| CloneError::Tooling(format!("ledger encode: {e}")))?;
        let path = self.entry_path(&entry.clone_id);
        fs::write(&path, json)
            .map_err(|e| CloneError::Tooling(format!("ledger write {}: {e}", path.display())))?;
        Ok(())
    }

    /// Remove a clone's ledger entry (called by the provider once the cluster is
    /// physically gone). Removing an absent entry is `Ok` (idempotent).
    pub fn forget(&self, clone_id: &str) -> Result<(), CloneError> {
        let path = self.entry_path(clone_id);
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(CloneError::Tooling(format!(
                "ledger forget {}: {e}",
                path.display()
            ))),
        }
    }

    /// All clones currently recorded in the ledger.
    pub fn entries(&self) -> Result<Vec<LedgerEntry>, CloneError> {
        let mut out = Vec::new();
        let rd = match fs::read_dir(&self.dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(CloneError::Tooling(format!("ledger read: {e}"))),
        };
        for ent in rd {
            let ent = ent.map_err(|e| CloneError::Tooling(format!("ledger entry: {e}")))?;
            let path = ent.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            let bytes = fs::read(&path)
                .map_err(|e| CloneError::Tooling(format!("ledger read {}: {e}", path.display())))?;
            let entry: LedgerEntry = serde_json::from_slice(&bytes).map_err(|e| {
                CloneError::Tooling(format!("ledger decode {}: {e}", path.display()))
            })?;
            out.push(entry);
        }
        Ok(out)
    }
}

/// An orphan-clone alarm (SPEC §10.7). Raised whenever the reaper finds a clone
/// whose owning orchestrator is dead — the condition the product treats as a
/// security incident (unencrypted prod PII left running). In production this is
/// emitted to the alerting sink; here it is a structured value the test asserts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrphanAlarm {
    /// The orphaned clone's id.
    pub clone_id: String,
    /// Its datadir (now reaped).
    pub datadir: PathBuf,
    /// Its port.
    pub port: u16,
    /// The dead owner pid.
    pub owner_pid: u32,
    /// Whether the reaper successfully destroyed it.
    pub reaped: bool,
}

/// The result of one reaper pass.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReapOutcome {
    /// Alarms raised (one per orphan found).
    pub alarms: Vec<OrphanAlarm>,
    /// Clones the reaper left alone because their owner is still alive.
    pub live_skipped: Vec<String>,
}

/// Whether a process id is currently alive. Uses the POSIX `kill -0 <pid>` probe
/// via the system `kill` command: signal 0 delivers nothing and only checks
/// existence/permission, so a 0 exit ⇒ the process exists. Shelling out (rather
/// than raw `libc::kill`) keeps the crate `#![forbid(unsafe_code)]`-clean and
/// works without the orchestrator that made the clone (the reaper's whole point).
fn pid_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    // `kill -0` exits 0 if the process exists *and* we may signal it. If it
    // exists but we lack permission, `kill` prints "Operation not permitted" and
    // exits non-zero — that case does not arise for our own clones (same uid), so
    // a non-zero exit here means "gone", which is the fail-safe direction (the
    // reaper would then try to destroy it; a no-op if already gone).
    matches!(
        Command::new("kill")
            .arg("-0")
            .arg(pid.to_string())
            .output(),
        Ok(out) if out.status.success()
    )
}

/// Send signal `sig` (e.g. "INT", "QUIT") to `pid` via the system `kill`. Best
/// effort; errors are ignored (the datadir removal is the backstop).
fn signal(pid: u32, sig: &str) {
    let _ = Command::new("kill")
        .arg(format!("-{sig}"))
        .arg(pid.to_string())
        .output();
}

/// Read the postmaster pid from a `postmaster.pid` file (its first line).
fn postmaster_pid(pidfile: &Path) -> Option<u32> {
    let text = fs::read_to_string(pidfile).ok()?;
    text.lines().next()?.trim().parse::<u32>().ok()
}

/// Stop the clone's postmaster (if running) and delete its datadir — the reaper's
/// destroy primitive, usable without the provider that made the clone.
///
/// It signals the postmaster from its `postmaster.pid` (SIGINT = fast shutdown,
/// then SIGQUIT = immediate if it lingers), waits for the port/datadir to clear,
/// and finally removes the datadir. Returns `true` if the clone is gone
/// afterward.
pub fn destroy_orphan(entry: &LedgerEntry) -> bool {
    // 1. Stop the postmaster if its pidfile names a live process.
    if let Some(pm_pid) = postmaster_pid(&entry.pidfile()) {
        if pid_alive(pm_pid) {
            // SIGINT = fast shutdown (rollback in-flight, exit).
            signal(pm_pid, "INT");
            if !wait_pid_gone(pm_pid, 50, 100) {
                // SIGQUIT = immediate shutdown (no checkpoint) — last resort.
                signal(pm_pid, "QUIT");
                wait_pid_gone(pm_pid, 50, 100);
            }
        }
    }
    // 2. Remove the datadir (the on-disk prod-PII copy). Absent ⇒ already gone.
    if entry.datadir.exists() {
        let _ = fs::remove_dir_all(&entry.datadir);
    }
    !entry.datadir.exists()
}

/// Poll until `pid` is gone, up to `tries` × `sleep_ms`. Returns whether it left.
fn wait_pid_gone(pid: u32, tries: u32, sleep_ms: u64) -> bool {
    for _ in 0..tries {
        if !pid_alive(pid) {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(sleep_ms));
    }
    !pid_alive(pid)
}

/// Run one orphan-reaper pass over `ledger` (SPEC §10.7).
///
/// For every recorded clone: if its **owning orchestrator pid is dead**, the
/// clone is an orphan — destroy it (stop postmaster + delete datadir), raise an
/// [`OrphanAlarm`], and forget the ledger entry. If the owner is still alive the
/// clone is in active use and left untouched (recorded in
/// [`ReapOutcome::live_skipped`]).
pub fn reap_orphans(ledger: &CloneLedger) -> Result<ReapOutcome, CloneError> {
    let mut outcome = ReapOutcome::default();
    for entry in ledger.entries()? {
        if pid_alive(entry.owner_pid) {
            outcome.live_skipped.push(entry.clone_id.clone());
            continue;
        }
        // Orphan: the orchestrator that owned this clone is gone.
        let reaped = destroy_orphan(&entry);
        outcome.alarms.push(OrphanAlarm {
            clone_id: entry.clone_id.clone(),
            datadir: entry.datadir.clone(),
            port: entry.port,
            owner_pid: entry.owner_pid,
            reaped,
        });
        // Forget only once it's actually gone; a failed reap stays in the ledger
        // so the next pass retries it.
        if reaped {
            ledger.forget(&entry.clone_id)?;
        }
    }
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir(tag: &str) -> PathBuf {
        let base = std::env::temp_dir().join(format!(
            "pgb-ledger-test-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        base
    }

    #[test]
    fn ledger_record_list_forget_roundtrip() {
        let dir = tmp_dir("rt");
        let ledger = CloneLedger::open(&dir).unwrap();
        let e = LedgerEntry {
            clone_id: "clone-abc".into(),
            datadir: dir.join("data-abc"),
            port: 54361,
            owner_pid: std::process::id(),
        };
        ledger.record(&e).unwrap();
        let listed = ledger.entries().unwrap();
        assert_eq!(listed, vec![e.clone()]);
        ledger.forget("clone-abc").unwrap();
        assert!(ledger.entries().unwrap().is_empty());
        // Idempotent forget.
        ledger.forget("clone-abc").unwrap();
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn reaper_skips_live_owner_and_reaps_dead_owner() {
        let dir = tmp_dir("reap");
        let ledger = CloneLedger::open(&dir).unwrap();

        // A clone owned by THIS (alive) process → must be skipped (in use).
        let live_datadir = dir.join("live-data");
        fs::create_dir_all(&live_datadir).unwrap();
        ledger
            .record(&LedgerEntry {
                clone_id: "live-clone".into(),
                datadir: live_datadir.clone(),
                port: 54371,
                owner_pid: std::process::id(),
            })
            .unwrap();

        // A clone owned by a DEAD pid → orphan. Pick a pid that cannot be alive.
        // pid 0 is never a normal process owner; use a very high unused pid.
        let dead_datadir = dir.join("dead-data");
        fs::create_dir_all(&dead_datadir).unwrap();
        // No postmaster.pid → destroy_orphan just removes the dir.
        let dead_pid = pick_dead_pid();
        ledger
            .record(&LedgerEntry {
                clone_id: "dead-clone".into(),
                datadir: dead_datadir.clone(),
                port: 54372,
                owner_pid: dead_pid,
            })
            .unwrap();

        let outcome = reap_orphans(&ledger).unwrap();

        assert_eq!(outcome.live_skipped, vec!["live-clone".to_string()]);
        assert_eq!(outcome.alarms.len(), 1, "exactly one orphan alarm");
        let alarm = &outcome.alarms[0];
        assert_eq!(alarm.clone_id, "dead-clone");
        assert!(alarm.reaped, "the dead-owner clone must be reaped");
        assert!(!dead_datadir.exists(), "orphan datadir must be deleted");
        assert!(live_datadir.exists(), "in-use clone must be left alone");

        // The orphan's ledger entry is gone; the live one remains.
        let remaining: Vec<String> = ledger
            .entries()
            .unwrap()
            .into_iter()
            .map(|e| e.clone_id)
            .collect();
        assert_eq!(remaining, vec!["live-clone".to_string()]);

        fs::remove_dir_all(&dir).ok();
    }

    /// Find a pid that is not currently alive (so the reaper treats it as dead).
    fn pick_dead_pid() -> u32 {
        // Scan downward from a high pid for one that isn't alive.
        for pid in (90_000..99_999).rev() {
            if !pid_alive(pid) {
                return pid;
            }
        }
        // Fallback: pid 2^31-1 is effectively never a live process.
        2_147_483_647
    }

    #[test]
    fn pid_alive_is_true_for_self_false_for_zero() {
        assert!(pid_alive(std::process::id()));
        assert!(!pid_alive(0));
    }
}
