//! The clone ledger + orphan-reaper (SPEC §10.7 "teardown-failure handling =
//! reaper/GC + orphan-clone alarm + test asserting no clone survives a killed
//! orchestrator").
//!
//! An orphaned clone is **unencrypted prod PII left running** — the CISO veto we
//! sell against. So a clone must NOT survive the orchestrator that made it. The
//! mechanism, mirroring the local-stack's out-of-tree PID ledger:
//!
//! 1. **Before creating the datadir / running `pg_basebackup`**, the provider
//!    writes a [`LedgerEntry`] (datadir, port, owner pid + boot-unique owner
//!    identity) to an **out-of-process ledger file** — a directory of one JSON
//!    file per live clone. The file survives the orchestrator's death (even
//!    SIGKILL). The breadcrumb therefore **always precedes any prod PII on disk**
//!    (fail-closed ordering, SPEC §10.7).
//! 2. On clean teardown the provider removes the entry once the cluster is gone.
//! 3. If the orchestrator dies mid-rehearsal (including mid-`pg_basebackup`), the
//!    entry is left behind. A [`reap_orphans`] pass — run by a sidecar/cron, or by
//!    the next orchestrator start — destroys every clone whose owning orchestrator
//!    is no longer alive (stop the postmaster, delete the datadir) and raises an
//!    [`OrphanAlarm`].
//!
//! # Defence-in-depth: two independent backstops
//!
//! - **Ledger-driven reap** — the primary path: a recorded clone whose owner is
//!   dead is destroyed (above).
//! - **Filesystem sweep** — [`reap_orphans_with_sweep`] **also** scans `clone_root`
//!   and treats **every child directory** (the provider owns `clone_root`
//!   exclusively and names each clone `local-clone-*`) as a reap candidate *even
//!   with no ledger entry at all* — reaping it **unless a LIVE owner is proven** for
//!   it (a ledger entry matched by path, or an in-dir [`OWNER_MARKER`] whose owner
//!   [`is_live`](OwnerIdentity::is_live)). Crucially it does **not** key on datadir
//!   *content* (`PG_VERSION`/`postmaster.pid`/marker), so a **partial or empty**
//!   mid-`pg_basebackup` datadir — which has none of those tell-tales — is reaped
//!   too. This closes the leaked-PII window even when the ledger write is
//!   lost/relocated and a crash lands mid-basebackup: the on-disk prod-PII copy is
//!   still found and reaped.
//!
//! # PID-reuse hardening (fail-closed liveness)
//!
//! The reaper treats a clone as live only when its owner pid is alive **and** the
//! live process's start-time matches the [`LedgerEntry::owner_start`] recorded at
//! provision. A recycled pid (the orchestrator died and the OS handed its pid to
//! an unrelated process) has a *different* start-time, so it no longer masks the
//! orphan — the clone is reaped. Combined with the filesystem sweep (which is
//! pid-independent), a reused pid can never hide a leaked prod-PII clone.
//!
//! The reaper is **pure-Rust + `kill`/`ps`** (no `unsafe`) so it works even when
//! the orchestrator that wrote the entry is gone: it reads the pidfile, signals
//! the postmaster, waits for it to exit, then removes the datadir. The integration
//! tests kill an orchestrator mid-rehearsal (and mid-`pg_basebackup`) and assert
//! the reaper leaves no cluster / process / dir.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};

use super::CloneError;

/// The basename of the **owner-identity marker** written inside every clone
/// datadir (before any PII is copied in). It pins the clone to the orchestrator
/// that made it, so the ledger-independent filesystem sweep can decide ownership
/// without any ledger entry. JSON: `{ "owner_pid": u32, "owner_start": "..." }`.
pub const OWNER_MARKER: &str = ".pgb_clone_owner.json";

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
    /// The owning orchestrator's process **start-time**, captured at provision —
    /// a boot-unique discriminator that survives PID reuse. The reaper treats the
    /// owner as live only when `owner_pid` is alive **and** the live process's
    /// start-time still equals this; a recycled pid has a different start-time, so
    /// it is reaped rather than mistaken for the original owner (fail-closed).
    ///
    /// `#[serde(default)]` keeps entries written by older orchestrators
    /// deserializable; an empty token means "no identity recorded", which the
    /// reaper treats fail-closed (owner considered dead unless proven live).
    #[serde(default)]
    pub owner_start: String,
}

impl LedgerEntry {
    /// The clone postmaster's pidfile inside its datadir.
    pub fn pidfile(&self) -> PathBuf {
        self.datadir.join("postmaster.pid")
    }

    /// This clone's owner identity (pid + start-time discriminator).
    pub fn owner(&self) -> OwnerIdentity {
        OwnerIdentity {
            pid: self.owner_pid,
            start: self.owner_start.clone(),
        }
    }
}

/// A boot-unique identity for the orchestrator process that owns a clone:
/// `(pid, start-time)`. The pid alone is insufficient — pids are recycled — so
/// the start-time pins the identity to one specific process incarnation. Stored
/// in both the ledger entry and the in-datadir [`OWNER_MARKER`] so the reaper can
/// decide liveness from either source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnerIdentity {
    /// The orchestrator process id.
    pub pid: u32,
    /// Its start-time as reported by `ps -o lstart=` (1s resolution; combined
    /// with the pid this uniquely identifies one process incarnation).
    pub start: String,
}

impl OwnerIdentity {
    /// The identity of the **current** process (the orchestrator provisioning a
    /// clone). `start` is best-effort: an empty string still records the pid, and
    /// liveness then falls back to a bare pid check (degraded, but never a panic).
    pub fn current() -> Self {
        let pid = std::process::id();
        OwnerIdentity {
            pid,
            start: process_start_time(pid).unwrap_or_default(),
        }
    }

    /// Whether this owner is still a live, *matching* process — fail-closed.
    ///
    /// Requires the pid to be alive **and**, when a start-time was recorded, the
    /// live process's current start-time to match it. A recycled pid (different
    /// start-time) ⇒ not live ⇒ the clone is an orphan to reap. If no start-time
    /// was recorded (legacy entry) we fall back to the bare pid probe.
    pub fn is_live(&self) -> bool {
        if !pid_alive(self.pid) {
            return false;
        }
        match process_start_time(self.pid) {
            // pid alive but start-time differs ⇒ the pid was recycled.
            Some(now) if !self.start.is_empty() => now == self.start,
            // pid alive, no recorded identity to compare ⇒ legacy fall-back.
            _ => true,
        }
    }
}

/// The wall-clock start-time of process `pid` via `ps -o lstart=` (a portable
/// POSIX keyword on macOS + Linux). Trimmed; `None` if the pid is gone or `ps`
/// fails. Combined with the pid this is a boot-unique process discriminator that
/// survives pid reuse — and it needs no `unsafe` (keeps the crate
/// `#![forbid(unsafe_code)]`-clean), matching the `kill`-based liveness probe.
fn process_start_time(pid: u32) -> Option<String> {
    if pid == 0 {
        return None;
    }
    let out = Command::new("ps")
        .arg("-o")
        .arg("lstart=")
        .arg("-p")
        .arg(pid.to_string())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() { None } else { Some(s) }
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
    ///
    /// Prefer [`CloneLedger::canonical`] in production: a caller-supplied path that
    /// points at a tmp-clearable / per-process directory would make orphans
    /// undetectable across orchestrator restarts (every orchestrator and the
    /// reaper sidecar **must** share one durable ledger). An explicit `dir` is for
    /// tests and for advanced deployments that pin their own durable path.
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self, CloneError> {
        let dir = dir.into();
        fs::create_dir_all(&dir)
            .map_err(|e| CloneError::Tooling(format!("ledger dir {}: {e}", dir.display())))?;
        Ok(CloneLedger { dir })
    }

    /// Open the **canonical, durable** ledger location all orchestrators and the
    /// reaper share (SPEC §10.7). This is **not** caller-supplied and **not** under
    /// the system tempdir (which a deployment / reboot can clear, orphaning prod
    /// PII undetectably): it is pinned to a stable XDG state dir,
    /// `$PGB_CLONE_LEDGER_DIR` (deployment override) or
    /// `$XDG_STATE_HOME/pg_bumpers/clone-ledger`, falling back to
    /// `$HOME/.local/state/pg_bumpers/clone-ledger`. Co-locating the ledger with
    /// the durable clone storage is the documented production posture.
    pub fn canonical() -> Result<Self, CloneError> {
        Self::open(Self::canonical_dir())
    }

    /// The canonical durable ledger directory (see [`CloneLedger::canonical`]).
    pub fn canonical_dir() -> PathBuf {
        // Read the three env inputs here, then resolve via the pure helper. Keeping
        // the resolution pure (no env access) lets the unit test drive it directly,
        // so this crate never has to mutate the process environment — which under
        // Rust 2024 is `unsafe` and would breach the crate's `#![forbid(unsafe_code)]`.
        Self::canonical_dir_from(
            std::env::var_os("PGB_CLONE_LEDGER_DIR"),
            std::env::var_os("XDG_STATE_HOME"),
            std::env::var_os("HOME"),
        )
    }

    /// Pure resolution of [`canonical_dir`](Self::canonical_dir) from its env
    /// inputs (override, `XDG_STATE_HOME`, `HOME`). Factored out so it is testable
    /// without touching the process environment.
    fn canonical_dir_from(
        explicit: Option<std::ffi::OsString>,
        xdg_state: Option<std::ffi::OsString>,
        home: Option<std::ffi::OsString>,
    ) -> PathBuf {
        if let Some(explicit) = explicit {
            return PathBuf::from(explicit);
        }
        let state_base = xdg_state
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .or_else(|| home.map(|h| PathBuf::from(h).join(".local").join("state")))
            // Last resort only if even $HOME is unset (should not happen on a real
            // host); the tempdir is documented as non-durable but is better than
            // panicking, and the filesystem sweep is the backstop.
            .unwrap_or_else(std::env::temp_dir);
        state_base.join("pg_bumpers").join("clone-ledger")
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

/// Write the owner-identity [`OWNER_MARKER`] into a clone datadir. Called by the
/// provider **before** any prod PII is copied in, so the ledger-independent sweep
/// can attribute the datadir to a (possibly dead) owner even with no ledger entry.
pub fn write_owner_marker(datadir: &Path, owner: &OwnerIdentity) -> Result<(), CloneError> {
    let json = serde_json::to_vec_pretty(owner)
        .map_err(|e| CloneError::Tooling(format!("owner marker encode: {e}")))?;
    let path = datadir.join(OWNER_MARKER);
    fs::write(&path, json)
        .map_err(|e| CloneError::Tooling(format!("owner marker {}: {e}", path.display())))
}

/// Read the owner identity from a clone datadir's [`OWNER_MARKER`], if present and
/// parseable. `None` ⇒ no/garbled marker, which the sweep treats fail-closed (an
/// unattributable clone datadir is a reap candidate).
fn read_owner_marker(datadir: &Path) -> Option<OwnerIdentity> {
    let bytes = fs::read(datadir.join(OWNER_MARKER)).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Whether `name` is a clone-datadir name the provider creates under its
/// exclusively-owned `clone_root`. Every clone datadir is named `local-clone-*`
/// (see [`LocalCloneProvider::provision`](super::local::LocalCloneProvider::provision)),
/// so the sweep gates on the **name**, not on datadir *content*.
///
/// This is deliberately *not* a content fingerprint (`PG_VERSION` /
/// `postmaster.pid` / [`OWNER_MARKER`]): a **partial** mid-`pg_basebackup` datadir
/// has none of those (early on it holds only `backup_label` / `pg_wal/`, and in the
/// earliest window it is completely empty), so a content gate would miss exactly
/// the leaked-PII orphan the sweep is the backstop for (SPEC §10.7). Keying on the
/// owned name reaps partial/empty clone datadirs too, while still ignoring any
/// stray non-clone directory a deployment might place under `clone_root`.
fn is_clone_datadir_name(name: &str) -> bool {
    name.starts_with("local-clone-")
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
    if let Some(pm_pid) = postmaster_pid(&entry.pidfile())
        && pid_alive(pm_pid)
    {
        // SIGINT = fast shutdown (rollback in-flight, exit).
        signal(pm_pid, "INT");
        if !wait_pid_gone(pm_pid, 50, 100) {
            // SIGQUIT = immediate shutdown (no checkpoint) — last resort.
            signal(pm_pid, "QUIT");
            wait_pid_gone(pm_pid, 50, 100);
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

/// Run one **ledger-driven** orphan-reaper pass over `ledger` (SPEC §10.7).
///
/// For every recorded clone: if its **owning orchestrator is no longer live**
/// (pid gone, or pid recycled to a different process — see [`OwnerIdentity`]), the
/// clone is an orphan — destroy it (stop postmaster + delete datadir), raise an
/// [`OrphanAlarm`], and forget the ledger entry. If the owner is still live the
/// clone is in active use and left untouched (recorded in
/// [`ReapOutcome::live_skipped`]).
///
/// This is the primary backstop. In production, prefer
/// [`reap_orphans_with_sweep`], which additionally sweeps the clone-storage root
/// so a clone with **no** ledger entry (lost/failed ledger write) is still caught.
pub fn reap_orphans(ledger: &CloneLedger) -> Result<ReapOutcome, CloneError> {
    let mut outcome = ReapOutcome::default();
    reap_from_ledger(ledger, &mut outcome)?;
    Ok(outcome)
}

/// Run a **full** orphan-reaper pass: the ledger-driven reap (see [`reap_orphans`])
/// **plus** a ledger-independent sweep of `clone_root` (SPEC §10.7,
/// defence-in-depth).
///
/// The sweep closes the leaked-PII window for a lost/relocated ledger: the
/// provider owns `clone_root` exclusively and names every clone `local-clone-*`,
/// so **every such child directory** is destroyed **unless a LIVE owner is proven**
/// for it (a ledger entry matched by path, or an in-dir [`OWNER_MARKER`] whose
/// owner is live) — **even if it has no ledger entry at all**. Because it gates on
/// the owned *name* and not on datadir *content*, it reaps **partial or empty**
/// mid-`pg_basebackup` datadirs too (they have no `PG_VERSION`/`postmaster.pid`/
/// marker) — exactly the orphan the original content-keyed sweep missed. An orphan
/// caught by *both* paths is reaped once and alarmed once.
pub fn reap_orphans_with_sweep(
    ledger: &CloneLedger,
    clone_root: &Path,
) -> Result<ReapOutcome, CloneError> {
    let mut outcome = ReapOutcome::default();
    reap_from_ledger(ledger, &mut outcome)?;
    sweep_clone_root(clone_root, ledger, &mut outcome)?;
    Ok(outcome)
}

/// The ledger-driven half of a reaper pass (records into `outcome`).
fn reap_from_ledger(ledger: &CloneLedger, outcome: &mut ReapOutcome) -> Result<(), CloneError> {
    for entry in ledger.entries()? {
        if entry.owner().is_live() {
            outcome.live_skipped.push(entry.clone_id.clone());
            continue;
        }
        // Orphan: the orchestrator that owned this clone is gone (or its pid was
        // recycled to an unrelated process — see `OwnerIdentity::is_live`).
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
    Ok(())
}

/// The ledger-independent half: scan `clone_root` and reap **every child
/// directory** (the owned `local-clone-*` name set) for which **no LIVE owner is
/// proven** — **even with no ledger entry and no datadir content** (records into
/// `outcome`). Proof of life is a ledger entry matched by path, or an in-dir
/// [`OWNER_MARKER`] whose owner [`is_live`](OwnerIdentity::is_live); anything else
/// (dead owner, recycled pid, absent/garbled marker, partial/empty datadir) is an
/// orphan and is reaped (fail-closed). Datadirs already reaped/alarmed by the
/// ledger pass are skipped.
fn sweep_clone_root(
    clone_root: &Path,
    ledger: &CloneLedger,
    outcome: &mut ReapOutcome,
) -> Result<(), CloneError> {
    let rd = match fs::read_dir(clone_root) {
        Ok(rd) => rd,
        // No clone root yet ⇒ nothing on disk to sweep.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            return Err(CloneError::Tooling(format!(
                "sweep read {clone_root:?}: {e}"
            )));
        }
    };
    // Snapshot the ledger once: any datadir owned by a *live* ledger entry is in
    // active use and must be left alone.
    let ledger_entries = ledger.entries()?;
    for ent in rd {
        let ent = ent.map_err(|e| CloneError::Tooling(format!("sweep entry: {e}")))?;
        let path = ent.path();
        let name = match path.file_name().and_then(|s| s.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };
        // The provider OWNS clone_root exclusively and names every clone datadir
        // `local-clone-*`. We gate on the NAME, never on datadir content — a
        // partial/empty mid-basebackup datadir has no `PG_VERSION`/`postmaster.pid`
        // /marker, and that is exactly the leaked-PII orphan we must reap. Any
        // child dir with the owned name is a reap candidate **unless a LIVE owner
        // is proven** for it (ledger-by-path, then in-dir marker); see below.
        if !path.is_dir() || !is_clone_datadir_name(&name) {
            continue;
        }
        // Already alarmed by the ledger pass this run (e.g. dead-owner entry whose
        // datadir survived the destroy attempt) ⇒ don't double-process.
        if outcome.alarms.iter().any(|a| a.datadir == path) {
            continue;
        }
        // PROOF OF LIFE #1 — a ledger entry matched BY PATH whose owner is live ⇒
        // this is an in-progress provision or an in-use clone; leave it. (A
        // legitimately in-flight provision wrote its ledger entry first, so it is
        // proven live here and skipped — race-safe.)
        if ledger_entries
            .iter()
            .any(|e| e.datadir == path && e.owner().is_live())
        {
            outcome.live_skipped.push(name);
            continue;
        }

        // PROOF OF LIFE #2 — an in-dir owner marker naming a live, matching owner ⇒
        // in active use; leave it. Otherwise (dead owner, recycled pid, or no/
        // garbled/absent marker — including a partial/empty datadir) NO live owner
        // is proven, so it is an orphan and we reap it (fail-closed toward PII
        // safety: reaping a possibly-orphaned dir is correct per SPEC §10.7, which
        // prioritises no-leaked-PII over a provision retry).
        let owner = read_owner_marker(&path);
        let clone_id = name;
        if matches!(&owner, Some(o) if o.is_live()) {
            outcome.live_skipped.push(clone_id);
            continue;
        }

        // Orphaned, unrecorded (or recorded-but-dead) prod-PII datadir: reap it.
        let entry = LedgerEntry {
            clone_id: clone_id.clone(),
            datadir: path.clone(),
            // Port unknown from the filesystem alone; the postmaster.pid stop +
            // datadir removal in `destroy_orphan` does not need it.
            port: 0,
            owner_pid: owner.as_ref().map(|o| o.pid).unwrap_or(0),
            owner_start: owner.as_ref().map(|o| o.start.clone()).unwrap_or_default(),
        };
        let reaped = destroy_orphan(&entry);
        outcome.alarms.push(OrphanAlarm {
            clone_id: entry.clone_id.clone(),
            datadir: entry.datadir.clone(),
            port: entry.port,
            owner_pid: entry.owner_pid,
            reaped,
        });
        // If the ledger happened to have an entry for this datadir, forget it now.
        if reaped {
            ledger.forget(&entry.clone_id)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "pgb-ledger-test-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
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
            owner_start: OwnerIdentity::current().start,
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
                owner_start: OwnerIdentity::current().start,
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
                owner_start: String::new(),
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

    #[test]
    fn process_start_time_is_some_for_self_none_for_dead() {
        assert!(process_start_time(std::process::id()).is_some());
        assert!(process_start_time(0).is_none());
        assert!(process_start_time(pick_dead_pid()).is_none());
    }

    #[test]
    fn owner_identity_pid_reuse_is_not_live() {
        // The exact red-team scenario: the orchestrator died and the OS recycled
        // its pid to an UNRELATED live process. The bare-pid check would say
        // "alive" and skip the orphan forever; the start-time discriminator makes
        // it fail-closed. We model the recycled pid as *this* live process with a
        // DIFFERENT recorded start-time — pid is alive, identity does not match.
        let recycled = OwnerIdentity {
            pid: std::process::id(),
            start: "Thu Jan  1 00:00:00 1970".to_string(), // not our real start
        };
        assert!(
            pid_alive(recycled.pid),
            "precondition: the (recycled) pid is alive"
        );
        assert!(
            !recycled.is_live(),
            "a live pid with a mismatched start-time must NOT count as the original owner"
        );

        // The genuine current identity is live (pid alive + start-time matches).
        assert!(OwnerIdentity::current().is_live());

        // A dead pid is never live regardless of recorded start-time.
        assert!(
            !OwnerIdentity {
                pid: pick_dead_pid(),
                start: String::new()
            }
            .is_live()
        );
    }

    #[test]
    fn ledger_pass_reaps_recycled_pid_owner() {
        // A ledger entry whose owner pid is alive but whose recorded start-time no
        // longer matches (pid reuse) must be reaped, not skipped as live.
        let dir = tmp_dir("recycle");
        let ledger = CloneLedger::open(&dir).unwrap();
        let datadir = dir.join("recycled-data");
        fs::create_dir_all(&datadir).unwrap();
        ledger
            .record(&LedgerEntry {
                clone_id: "recycled-clone".into(),
                datadir: datadir.clone(),
                port: 54390,
                owner_pid: std::process::id(), // alive…
                owner_start: "Thu Jan  1 00:00:00 1970".into(), // …but recycled
            })
            .unwrap();

        let outcome = reap_orphans(&ledger).unwrap();
        assert!(
            outcome.live_skipped.is_empty(),
            "a recycled-pid owner must not be treated as live: {outcome:?}"
        );
        assert_eq!(outcome.alarms.len(), 1, "the recycled-pid clone is reaped");
        assert!(!datadir.exists(), "the orphan datadir must be deleted");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn sweep_reaps_unrecorded_datadir_with_no_ledger_entry() {
        // The BLOCKER's belt-and-suspenders: a clone datadir on disk with NO
        // ledger entry (and a dead/garbage owner marker) is still reaped by the
        // filesystem sweep.
        let dir = tmp_dir("sweep");
        let ledger = CloneLedger::open(dir.join("ledger")).unwrap();
        let clone_root = dir.join("clones");
        let orphan = clone_root.join("local-clone-CRASHED-1");
        fs::create_dir_all(&orphan).unwrap();
        // Make it look like a PG datadir and stamp a DEAD owner marker.
        fs::write(orphan.join("PG_VERSION"), b"18\n").unwrap();
        write_owner_marker(
            &orphan,
            &OwnerIdentity {
                pid: pick_dead_pid(),
                start: String::new(),
            },
        )
        .unwrap();
        assert!(ledger.entries().unwrap().is_empty(), "no ledger entry");

        let outcome = reap_orphans_with_sweep(&ledger, &clone_root).unwrap();
        assert_eq!(
            outcome.alarms.len(),
            1,
            "the unrecorded orphan must raise exactly one alarm: {outcome:?}"
        );
        assert_eq!(outcome.alarms[0].clone_id, "local-clone-CRASHED-1");
        assert!(outcome.alarms[0].reaped);
        assert!(
            !orphan.exists(),
            "the unrecorded orphan datadir must be gone"
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn sweep_leaves_live_owner_datadir_alone() {
        // A datadir whose in-datadir owner marker names THIS live process is in
        // active use → the sweep must not touch it.
        let dir = tmp_dir("sweep-live");
        let ledger = CloneLedger::open(dir.join("ledger")).unwrap();
        let clone_root = dir.join("clones");
        let live = clone_root.join("local-clone-live-1");
        fs::create_dir_all(&live).unwrap();
        fs::write(live.join("PG_VERSION"), b"18\n").unwrap();
        write_owner_marker(&live, &OwnerIdentity::current()).unwrap();

        let outcome = reap_orphans_with_sweep(&ledger, &clone_root).unwrap();
        assert!(
            outcome.alarms.is_empty(),
            "a live-owner datadir must not be reaped: {outcome:?}"
        );
        assert!(live.exists(), "the in-use clone datadir must survive");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn sweep_skips_non_clone_directories() {
        // A stray directory under clone_root whose name is NOT in the owned
        // `local-clone-*` set is ignored — even though it has content. The sweep
        // gates on the owned NAME (the provider owns clone_root exclusively), not
        // on datadir content.
        let dir = tmp_dir("sweep-stray");
        let ledger = CloneLedger::open(dir.join("ledger")).unwrap();
        let clone_root = dir.join("clones");
        let stray = clone_root.join("not-a-clone");
        fs::create_dir_all(&stray).unwrap();
        fs::write(stray.join("readme.txt"), b"hi").unwrap();

        let outcome = reap_orphans_with_sweep(&ledger, &clone_root).unwrap();
        assert!(outcome.alarms.is_empty());
        assert!(
            stray.exists(),
            "a non-clone-named dir must be left untouched"
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn sweep_reaps_markerless_partial_datadir_with_no_ledger_entry() {
        // THE RESIDUAL LEAK (re-review of #33): a PARTIAL mid-`pg_basebackup`
        // datadir under clone_root has NO `PG_VERSION`/`postmaster.pid`/marker — it
        // holds only `backup_label` + `pg_wal/` — AND no ledger entry. The old
        // content-keyed `looks_like_clone_datadir` gate missed it, so the prod-PII
        // partial survived the full sweep. With name-gating + reap-unless-live-owner
        // it is reaped.
        let dir = tmp_dir("sweep-partial");
        let ledger = CloneLedger::open(dir.join("ledger")).unwrap();
        let clone_root = dir.join("clones");
        let partial = clone_root.join("local-clone-99999-1");
        fs::create_dir_all(partial.join("pg_wal")).unwrap();
        fs::write(partial.join("backup_label"), b"START WAL LOCATION: 0/0\n").unwrap();
        // Sanity: none of the old content tell-tales are present, and no marker.
        assert!(!partial.join("PG_VERSION").exists());
        assert!(!partial.join("postmaster.pid").exists());
        assert!(!partial.join(OWNER_MARKER).exists());
        assert!(ledger.entries().unwrap().is_empty(), "no ledger entry");

        let outcome = reap_orphans_with_sweep(&ledger, &clone_root).unwrap();
        assert_eq!(
            outcome.alarms.len(),
            1,
            "the markerless partial datadir must raise exactly one alarm: {outcome:?}"
        );
        assert_eq!(outcome.alarms[0].clone_id, "local-clone-99999-1");
        assert!(outcome.alarms[0].reaped);
        assert!(
            !partial.exists(),
            "the markerless partial prod-PII datadir must be GONE after the sweep"
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn sweep_reaps_empty_earliest_window_datadir() {
        // The earliest crash window: the clone datadir exists but is COMPLETELY
        // empty (pg_basebackup created the target but copied nothing yet). No
        // content, no marker, no ledger entry — it must still be reaped.
        let dir = tmp_dir("sweep-empty");
        let ledger = CloneLedger::open(dir.join("ledger")).unwrap();
        let clone_root = dir.join("clones");
        let empty = clone_root.join("local-clone-88888-1");
        fs::create_dir_all(&empty).unwrap();
        assert!(
            fs::read_dir(&empty).unwrap().next().is_none(),
            "precondition: the datadir is empty"
        );

        let outcome = reap_orphans_with_sweep(&ledger, &clone_root).unwrap();
        assert_eq!(
            outcome.alarms.len(),
            1,
            "the empty earliest-window datadir must be reaped: {outcome:?}"
        );
        assert!(outcome.alarms[0].reaped);
        assert!(!empty.exists(), "the empty clone datadir must be GONE");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn sweep_skips_partial_datadir_with_live_ledger_owner() {
        // Race-safety: a legitimately in-progress provision wrote its ledger entry
        // FIRST (fix #1), so even a partial/empty datadir with no in-dir marker yet
        // is proven LIVE by the ledger-by-path match and must NOT be reaped.
        let dir = tmp_dir("sweep-inflight");
        let ledger = CloneLedger::open(dir.join("ledger")).unwrap();
        let clone_root = dir.join("clones");
        let inflight = clone_root.join("local-clone-inflight-1");
        // Partial, markerless datadir — mid-basebackup, marker not stamped yet.
        fs::create_dir_all(inflight.join("pg_wal")).unwrap();
        // …but the ledger entry exists, owned by THIS (live) process.
        ledger
            .record(&LedgerEntry {
                clone_id: "local-clone-inflight-1".into(),
                datadir: inflight.clone(),
                port: 54399,
                owner_pid: std::process::id(),
                owner_start: OwnerIdentity::current().start,
            })
            .unwrap();

        let outcome = reap_orphans_with_sweep(&ledger, &clone_root).unwrap();
        assert!(
            outcome.alarms.is_empty(),
            "an in-progress provision proven live by its ledger entry must NOT be reaped: {outcome:?}"
        );
        assert!(
            inflight.exists(),
            "the in-flight clone datadir must survive"
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn canonical_dir_honors_explicit_override() {
        // Drive the PURE resolver (no process-env mutation) so this stays
        // `#![forbid(unsafe_code)]`-clean: under Rust 2024 `std::env::set_var` is
        // `unsafe`, and faking the override through it would breach that crate gate.

        // The pinned canonical location is deployment-overridable and NOT tmp.
        let want = std::env::temp_dir().join("pgb-canonical-test-override");
        assert_eq!(
            CloneLedger::canonical_dir_from(Some(want.clone().into_os_string()), None, None),
            want
        );

        // Without the override it is anchored under a state dir, never bare tmp:
        // an absolute $XDG_STATE_HOME wins, …
        let xdg = std::path::Path::new("/var/lib/pgb-state");
        assert_eq!(
            CloneLedger::canonical_dir_from(None, Some(xdg.as_os_str().to_owned()), None),
            xdg.join("pg_bumpers").join("clone-ledger")
        );
        // … else it falls back under $HOME/.local/state, …
        let home = std::path::Path::new("/home/pgb");
        assert_eq!(
            CloneLedger::canonical_dir_from(None, None, Some(home.as_os_str().to_owned())),
            home.join(".local")
                .join("state")
                .join("pg_bumpers")
                .join("clone-ledger")
        );
        // … and a non-absolute $XDG_STATE_HOME is rejected (HOME wins instead).
        assert_eq!(
            CloneLedger::canonical_dir_from(
                None,
                Some(std::ffi::OsString::from("relative/dir")),
                Some(home.as_os_str().to_owned()),
            ),
            home.join(".local")
                .join("state")
                .join("pg_bumpers")
                .join("clone-ledger")
        );
    }
}
