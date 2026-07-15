//! # yb-reqlog
//!
//! DuckDB-backed request/response logging for training-data capture.
//!
//! The gateway only sees [`yb_core::RequestLogger`]; this crate provides the
//! concrete [`DuckLogger`] sink. DuckDB is a synchronous C library, so it must
//! never be touched from a Tokio worker: [`DuckLogger`] owns a dedicated
//! [`std::thread`] that is the *sole* holder of the DuckDB [`Connection`].
//!
//! ## Data path
//! [`DuckLogger::log`] redacts nothing itself; it boxes the record and pushes it
//! onto a bounded [`std::sync::mpsc::sync_channel`] with a non-blocking
//! `try_send`. When the queue is full the record is dropped and a counter is
//! incremented ([`DuckLogger::dropped`]) — the request path is never blocked.
//!
//! ## Storage path
//! The worker opens `dir/wal.duckdb`, creates the `turns` table, and
//! batch-inserts buffered records (truncating bodies to `max_body_bytes`). It
//! rotates the WAL into a compressed Parquet shard under `dir/shards/` when any
//! of these fire:
//! - the [`ReqlogConfig::rotate_interval`] timer elapses,
//! - the UTC calendar date changes, or
//! - `wal.duckdb` grows past [`ReqlogConfig::shard_max_bytes`].
//!
//! Rotation is `COPY (SELECT * FROM turns) TO '<shard>.parquet' (FORMAT parquet,
//! COMPRESSION zstd)` followed by `DELETE FROM turns; CHECKPOINT;` and a prune of
//! shards older than [`ReqlogConfig::retention_days`].

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use chrono::{NaiveDate, SecondsFormat, Utc};
use duckdb::{params, Connection};

use yb_core::{Error, RequestLogRecord, RequestLogger, Result};

/// Tunables for the DuckDB logging sink.
#[derive(Debug, Clone)]
pub struct ReqlogConfig {
    /// Root directory. `wal.duckdb` and a `shards/` subdir live here.
    pub dir: PathBuf,
    /// Bounded in-flight queue depth. Records beyond this are dropped + counted.
    pub queue_size: usize,
    /// Rotate once `wal.duckdb` exceeds this many bytes.
    pub shard_max_bytes: u64,
    /// Rotate at least this often, regardless of size.
    pub rotate_interval: Duration,
    /// Delete Parquet shards older than this many days (`0` = keep forever).
    pub retention_days: u32,
    /// Truncate each captured body to this many bytes (`0` = no truncation).
    pub max_body_bytes: usize,
    /// Optional shell command run once after each shard is sealed — e.g. to back
    /// the shard up to object storage. Run via `sh -c`; the placeholders
    /// `{shard}` (the sealed shard's path) and `{dir}` (the reqlog directory) are
    /// substituted into the string before it runs. Failures are logged, never
    /// fatal. Keep it quick (it runs on the log worker thread); background
    /// long-running uploads yourself. Example:
    /// `on_roll = "aws s3 cp {shard} s3://my-bucket/gateway/"`.
    pub on_roll: Option<String>,
}

impl Default for ReqlogConfig {
    fn default() -> Self {
        Self {
            dir: PathBuf::from("reqlog"),
            queue_size: 4096,
            shard_max_bytes: 256 * 1024 * 1024,
            rotate_interval: Duration::from_secs(3600),
            retention_days: 30,
            max_body_bytes: 256 * 1024,
            on_roll: None,
        }
    }
}

/// `CREATE TABLE` for the capture buffer (schema fixed by the contract).
const CREATE_TURNS: &str = "\
CREATE TABLE IF NOT EXISTS turns (
    id                 UBIGINT,
    ts                 TIMESTAMP,
    log_date           DATE,
    request_id         VARCHAR,
    trace_id           VARCHAR,
    installation_id    VARCHAR,
    surface            VARCHAR,
    requested_model    VARCHAR,
    decision_model     VARCHAR,
    decision_provider  VARCHAR,
    upstream_status    INTEGER,
    is_error           BOOLEAN,
    request_bytes      INTEGER,
    response_bytes     INTEGER,
    response_truncated BOOLEAN,
    request_body       BLOB,
    response_body      BLOB
)";

/// Parameterised insert. Strings are CAST into the temporal / unsigned columns so
/// we do not need DuckDB's optional `chrono` feature enabled.
const INSERT_TURN: &str = "\
INSERT INTO turns VALUES (
    CAST(? AS UBIGINT), CAST(? AS TIMESTAMP), CAST(? AS DATE),
    ?, ?, ?, ?, ?, ?, ?, ?, ?,
    CAST(? AS INTEGER), CAST(? AS INTEGER), ?, ?, ?
)";

/// Acknowledgement channel for a control message: `Ok(())`/`Err(detail)`.
type Ack = mpsc::Sender<std::result::Result<(), String>>;

/// Messages the worker thread consumes. Records arrive via `try_send`; control
/// messages via blocking `send` so they are never dropped under load.
enum Msg {
    Record(Box<RequestLogRecord>),
    Flush(Ack),
    Rotate(Ack),
    Count(mpsc::Sender<std::result::Result<u64, String>>),
    Shutdown(Ack),
}

/// A non-blocking, DuckDB-backed [`RequestLogger`].
///
/// Cloning is intentionally not provided; share via `Arc<DuckLogger>`.
pub struct DuckLogger {
    tx: SyncSender<Msg>,
    dropped: Arc<AtomicU64>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl DuckLogger {
    /// Open (or create) the log directory and spawn the worker thread.
    ///
    /// Returns once the worker has successfully opened `dir/wal.duckdb` and
    /// created the `turns` table, so connection/setup failures surface here
    /// rather than silently on the background thread.
    pub fn new(cfg: ReqlogConfig) -> Result<Self> {
        let (tx, rx) = mpsc::sync_channel::<Msg>(cfg.queue_size.max(1));
        let (start_tx, start_rx) = mpsc::channel::<std::result::Result<(), String>>();
        let dropped = Arc::new(AtomicU64::new(0));

        let handle = std::thread::Builder::new()
            .name("yb-reqlog".to_string())
            .spawn(move || match Worker::open(cfg) {
                Ok(mut worker) => {
                    // Setup succeeded; unblock `new` then serve until shutdown.
                    let _ = start_tx.send(Ok(()));
                    worker.run(rx);
                }
                Err(e) => {
                    let _ = start_tx.send(Err(e.to_string()));
                }
            })
            .map_err(|e| Error::Internal(format!("reqlog: spawn worker: {e}")))?;

        match start_rx.recv() {
            Ok(Ok(())) => Ok(Self {
                tx,
                dropped,
                worker: Mutex::new(Some(handle)),
            }),
            Ok(Err(detail)) => {
                let _ = handle.join();
                Err(Error::Storage(format!("reqlog: {detail}")))
            }
            Err(_) => {
                let _ = handle.join();
                Err(Error::Internal("reqlog: worker exited during startup".into()))
            }
        }
    }

    /// Number of records dropped so far because the queue was full.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Force an immediate rotation (flush buffer, write a shard if non-empty,
    /// truncate `turns`, prune). Blocks until the worker completes it.
    pub fn force_rotate(&self) -> Result<()> {
        self.control(Msg::Rotate)
    }

    /// Flush any buffered records to `turns`. Blocks until persisted.
    pub fn flush(&self) -> Result<()> {
        self.control(Msg::Flush)
    }

    /// Current row count of the `turns` buffer (flushes first). Mainly for tests.
    pub fn turns_count(&self) -> Result<u64> {
        let (atx, arx) = mpsc::channel();
        self.tx
            .send(Msg::Count(atx))
            .map_err(|_| Error::Internal("reqlog: worker gone".into()))?;
        arx.recv()
            .map_err(|_| Error::Internal("reqlog: worker dropped ack".into()))?
            .map_err(Error::Storage)
    }

    /// Flush, stop the worker, and join its thread. Idempotent.
    pub fn shutdown(&self) -> Result<()> {
        let handle = {
            let mut guard = self.worker.lock().expect("reqlog worker mutex poisoned");
            guard.take()
        };
        let Some(handle) = handle else {
            return Ok(()); // already shut down
        };
        let res = self.control(Msg::Shutdown);
        let _ = handle.join();
        res
    }

    /// Send a control message and wait for its acknowledgement.
    fn control(&self, make: fn(Ack) -> Msg) -> Result<()> {
        let (atx, arx) = mpsc::channel();
        self.tx
            .send(make(atx))
            .map_err(|_| Error::Internal("reqlog: worker gone".into()))?;
        arx.recv()
            .map_err(|_| Error::Internal("reqlog: worker dropped ack".into()))?
            .map_err(Error::Storage)
    }
}

impl RequestLogger for DuckLogger {
    fn log(&self, record: RequestLogRecord) {
        match self.tx.try_send(Msg::Record(Box::new(record))) {
            Ok(()) => {}
            // Full queue, or worker already gone (post-shutdown). Either way we
            // drop and count — never block or panic on the request path.
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

impl Drop for DuckLogger {
    fn drop(&mut self) {
        // Best-effort flush + join so buffered records aren't lost on teardown.
        let _ = self.shutdown();
    }
}

/// Flush once the buffer reaches this many rows (bounds insert-batch size).
const BATCH_FLUSH: usize = 256;

/// Owns the DuckDB connection and all rotation state. Lives entirely on the
/// dedicated worker thread.
struct Worker {
    conn: Connection,
    cfg: ReqlogConfig,
    db_path: PathBuf,
    shards_dir: PathBuf,
    buf: Vec<RequestLogRecord>,
    next_id: u64,
    last_rotate: Instant,
    last_date: NaiveDate,
}

impl Worker {
    /// Open the WAL database and prepare the directory layout.
    fn open(cfg: ReqlogConfig) -> Result<Self> {
        let shards_dir = cfg.dir.join("shards");
        std::fs::create_dir_all(&shards_dir)
            .map_err(|e| Error::Storage(format!("reqlog: create dir: {e}")))?;

        let db_path = cfg.dir.join("wal.duckdb");
        let conn = Connection::open(&db_path).map_err(map_db)?;
        conn.execute_batch(CREATE_TURNS).map_err(map_db)?;

        // Resume the surrogate id sequence past any rows left from a prior run.
        let max_id: i64 = conn
            .query_row("SELECT COALESCE(MAX(id), 0) FROM turns", [], |r| r.get(0))
            .map_err(map_db)?;

        Ok(Self {
            conn,
            cfg,
            db_path,
            shards_dir,
            buf: Vec::new(),
            next_id: max_id as u64 + 1,
            last_rotate: Instant::now(),
            last_date: Utc::now().date_naive(),
        })
    }

    /// Main loop: drain records into batched inserts and honour control / timer
    /// driven rotation until the channel closes or a shutdown arrives.
    fn run(&mut self, rx: Receiver<Msg>) {
        // Wake often enough to notice the timer / date / size triggers even when
        // no records are flowing, but never less often than the rotate interval.
        let poll = self
            .cfg
            .rotate_interval
            .min(Duration::from_secs(1))
            .max(Duration::from_millis(50));

        loop {
            match rx.recv_timeout(poll) {
                Ok(Msg::Record(rec)) => {
                    self.buf.push(*rec);
                    if self.buf.len() >= BATCH_FLUSH {
                        self.flush_logged();
                        self.maybe_rotate();
                    }
                }
                Ok(Msg::Flush(ack)) => {
                    let _ = ack.send(self.flush().map_err(|e| e.to_string()));
                }
                Ok(Msg::Rotate(ack)) => {
                    let _ = ack.send(self.rotate().map_err(|e| e.to_string()));
                }
                Ok(Msg::Count(ack)) => {
                    let r = self.flush().and_then(|()| self.count());
                    let _ = ack.send(r.map_err(|e| e.to_string()));
                }
                Ok(Msg::Shutdown(ack)) => {
                    let _ = ack.send(self.flush().map_err(|e| e.to_string()));
                    break;
                }
                Err(RecvTimeoutError::Timeout) => {
                    self.flush_logged();
                    self.maybe_rotate();
                }
                Err(RecvTimeoutError::Disconnected) => {
                    self.flush_logged();
                    break;
                }
            }
        }
    }

    /// Flush, logging (but not propagating) any error — used on the timer and
    /// batch-threshold paths where there is no caller to receive a `Result`.
    fn flush_logged(&mut self) {
        if let Err(e) = self.flush() {
            tracing::error!(error = %e, "reqlog: flush failed");
        }
    }

    /// Persist all buffered records in a single transaction. Bodies are
    /// truncated to `max_body_bytes`; over-long responses set `response_truncated`.
    fn flush(&mut self) -> Result<()> {
        if self.buf.is_empty() {
            return Ok(());
        }
        let records = std::mem::take(&mut self.buf);

        self.conn.execute_batch("BEGIN TRANSACTION").map_err(map_db)?;
        let insert = (|| -> Result<()> {
            let mut stmt = self.conn.prepare(INSERT_TURN).map_err(map_db)?;
            let max = self.cfg.max_body_bytes;
            for rec in &records {
                let id = self.next_id;
                self.next_id += 1;

                let ts = rec.ts.format("%Y-%m-%d %H:%M:%S%.6f").to_string();
                let log_date = rec.ts.format("%Y-%m-%d").to_string();

                let req_body = truncate(&rec.request_body, max);
                let resp_body = truncate(&rec.response_body, max);
                let truncated =
                    rec.response_truncated || (max > 0 && rec.response_body.len() > max);

                stmt.execute(params![
                    id,
                    ts,
                    log_date,
                    rec.request_id,
                    rec.trace_id,
                    rec.installation_id,
                    rec.surface,
                    rec.requested_model,
                    rec.decision_model,
                    rec.decision_provider,
                    rec.upstream_status,
                    rec.is_error,
                    rec.request_bytes,
                    rec.response_bytes,
                    truncated,
                    req_body,
                    resp_body,
                ])
                .map_err(map_db)?;
            }
            Ok(())
        })();

        match insert {
            Ok(()) => {
                self.conn.execute_batch("COMMIT").map_err(map_db)?;
                Ok(())
            }
            Err(e) => {
                let _ = self.conn.execute_batch("ROLLBACK");
                Err(e)
            }
        }
    }

    /// Rows currently in the `turns` buffer.
    fn count(&self) -> Result<u64> {
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM turns", [], |r| r.get(0))
            .map_err(map_db)?;
        Ok(n.max(0) as u64)
    }

    /// Evaluate the timer / date / size triggers and rotate if any fired.
    fn maybe_rotate(&mut self) {
        let today = Utc::now().date_naive();
        let interval_elapsed = self.last_rotate.elapsed() >= self.cfg.rotate_interval;
        let date_changed = today != self.last_date;
        let oversize = self.wal_size() > self.cfg.shard_max_bytes;

        if interval_elapsed || date_changed || oversize {
            if let Err(e) = self.rotate() {
                tracing::error!(error = %e, "reqlog: rotate failed");
            }
        }
    }

    /// Current size of `wal.duckdb` in bytes (0 if it cannot be stat'd).
    fn wal_size(&self) -> u64 {
        std::fs::metadata(&self.db_path).map(|m| m.len()).unwrap_or(0)
    }

    /// Flush, write a compressed Parquet shard if `turns` is non-empty, truncate
    /// the buffer, checkpoint the WAL, prune expired shards, and finally invoke
    /// the optional roll hook on the freshly-sealed shard.
    fn rotate(&mut self) -> Result<()> {
        self.flush()?;

        let mut sealed: Option<PathBuf> = None;
        if self.count()? > 0 {
            let path = self.shards_dir.join(format!("{}.parquet", shard_stamp()));
            let path_sql = path.to_string_lossy().replace('\'', "''");
            self.conn
                .execute_batch(&format!(
                    "COPY (SELECT * FROM turns) TO '{path_sql}' (FORMAT parquet, COMPRESSION zstd)"
                ))
                .map_err(map_db)?;
            sealed = Some(path);
        }

        self.conn
            .execute_batch("DELETE FROM turns; CHECKPOINT")
            .map_err(map_db)?;

        self.prune();
        self.last_rotate = Instant::now();
        self.last_date = Utc::now().date_naive();

        // Run the backup/roll hook last, so rotation bookkeeping is already
        // consistent even if the hook is slow or fails.
        if let Some(path) = sealed {
            self.run_roll_hook(&path);
        }
        Ok(())
    }

    /// Run the optional `on_roll` command against a freshly-sealed `shard`.
    /// The `{shard}` and `{dir}` placeholders in the configured command are
    /// substituted before it runs (no environment variables are involved).
    /// Best-effort: a missing/empty command is a no-op, and spawn/exit failures
    /// are logged but never propagated (a failed backup must not stall logging).
    fn run_roll_hook(&self, shard: &Path) {
        let Some(cmd) = self.cfg.on_roll.as_deref() else {
            return;
        };
        if cmd.trim().is_empty() {
            return;
        }
        let script = cmd
            .replace("{shard}", &shard.to_string_lossy())
            .replace("{dir}", &self.cfg.dir.to_string_lossy());

        match std::process::Command::new("sh").arg("-c").arg(&script).status() {
            Ok(s) if s.success() => {
                tracing::info!(shard = %shard.display(), "reqlog: roll hook ok")
            }
            Ok(s) => tracing::error!(
                shard = %shard.display(),
                code = ?s.code(),
                "reqlog: roll hook exited non-zero"
            ),
            Err(e) => tracing::error!(error = %e, "reqlog: roll hook failed to spawn"),
        }
    }

    /// Remove `*.parquet` shards whose mtime is older than the retention window.
    /// Best-effort: filesystem errors are ignored (logged at debug).
    fn prune(&self) {
        if self.cfg.retention_days == 0 {
            return;
        }
        let Some(cutoff) = std::time::SystemTime::now()
            .checked_sub(Duration::from_secs(self.cfg.retention_days as u64 * 86_400))
        else {
            return;
        };
        let Ok(entries) = std::fs::read_dir(&self.shards_dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("parquet") {
                continue;
            }
            if let Ok(modified) = entry.metadata().and_then(|m| m.modified()) {
                if modified < cutoff {
                    if let Err(e) = std::fs::remove_file(&path) {
                        tracing::debug!(error = %e, path = %path.display(), "reqlog: prune failed");
                    }
                }
            }
        }
    }
}

/// Truncate `body` to at most `max` bytes (`max == 0` means no limit).
fn truncate(body: &[u8], max: usize) -> &[u8] {
    if max > 0 && body.len() > max {
        &body[..max]
    } else {
        body
    }
}

/// Filesystem-safe, lexically sortable shard timestamp derived from an RFC3339
/// UTC instant (colons replaced with dashes so the name is portable).
fn shard_stamp() -> String {
    Utc::now()
        .to_rfc3339_opts(SecondsFormat::Micros, true)
        .replace(':', "-")
}

/// Map a DuckDB error onto the frozen domain `Error::Storage`.
fn map_db(e: duckdb::Error) -> Error {
    Error::Storage(format!("reqlog/duckdb: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use yb_core::now;

    /// Build a unique scratch dir under the system temp location.
    fn scratch_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("yb-reqlog-{}", yb_core::new_id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn record(i: usize) -> RequestLogRecord {
        RequestLogRecord {
            ts: now(),
            request_id: format!("req-{i}"),
            trace_id: Some(format!("trace-{i}")),
            installation_id: "inst-1".to_string(),
            surface: "anthropic".to_string(),
            requested_model: "claude-sonnet".to_string(),
            decision_model: "claude-sonnet".to_string(),
            decision_provider: "anthropic".to_string(),
            upstream_status: 200,
            is_error: false,
            request_bytes: 128,
            response_bytes: 256,
            response_truncated: false,
            request_body: format!("request-body-{i}").into_bytes(),
            response_body: format!("response-body-{i}").into_bytes(),
        }
    }

    #[test]
    fn rotate_writes_shard_and_truncates_wal() {
        let dir = scratch_dir();
        let cfg = ReqlogConfig {
            dir: dir.clone(),
            queue_size: 1024,
            shard_max_bytes: u64::MAX, // size trigger off; we rotate explicitly
            rotate_interval: Duration::from_secs(3600),
            retention_days: 30,
            max_body_bytes: 1024,
            on_roll: None,
        };

        let logger = DuckLogger::new(cfg).unwrap();

        for i in 0..50 {
            logger.log(record(i));
        }
        logger.flush().unwrap();
        assert_eq!(logger.turns_count().unwrap(), 50, "all records persisted");

        logger.force_rotate().unwrap();

        // WAL buffer is emptied by rotation.
        assert_eq!(logger.turns_count().unwrap(), 0, "turns truncated after rotate");

        // Exactly one compressed Parquet shard was written.
        let shards: Vec<_> = std::fs::read_dir(dir.join("shards"))
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("parquet"))
            .collect();
        assert_eq!(shards.len(), 1, "one parquet shard exists: {shards:?}");
        assert!(
            std::fs::metadata(&shards[0]).unwrap().len() > 0,
            "shard is non-empty"
        );

        logger.shutdown().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn roll_hook_runs_on_sealed_shard() {
        let dir = scratch_dir();
        let marker = dir.join("rolled.txt");
        // The hook writes the {shard} placeholder it was handed into a marker
        // file — proving the path is substituted into the command (no env vars).
        let cfg = ReqlogConfig {
            dir: dir.clone(),
            shard_max_bytes: u64::MAX,
            rotate_interval: Duration::from_secs(3600),
            on_roll: Some(format!("printf '%s' '{{shard}}' > {}", marker.display())),
            ..ReqlogConfig::default()
        };
        let logger = DuckLogger::new(cfg).unwrap();

        // A non-empty buffer so a shard is actually sealed.
        for i in 0..3 {
            logger.log(record(i));
        }
        logger.force_rotate().unwrap();

        let recorded = std::fs::read_to_string(&marker)
            .expect("roll hook should have written the marker file");
        assert!(recorded.ends_with(".parquet"), "hook got the shard path: {recorded}");
        assert!(std::path::Path::new(&recorded).exists(), "the shard the hook named exists");

        logger.shutdown().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_rotate_writes_no_shard() {
        let dir = scratch_dir();
        let cfg = ReqlogConfig {
            dir: dir.clone(),
            rotate_interval: Duration::from_secs(3600),
            shard_max_bytes: u64::MAX,
            ..ReqlogConfig::default()
        };
        let logger = DuckLogger::new(cfg).unwrap();

        logger.force_rotate().unwrap();
        assert_eq!(logger.turns_count().unwrap(), 0);

        let count = std::fs::read_dir(dir.join("shards")).unwrap().count();
        assert_eq!(count, 0, "no shard for an empty buffer");

        logger.shutdown().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn full_queue_drops_are_counted() {
        let dir = scratch_dir();
        // A tiny queue plus a never-draining burst: pushing far more than
        // capacity must register drops without panicking or blocking.
        let cfg = ReqlogConfig {
            dir: dir.clone(),
            queue_size: 2,
            rotate_interval: Duration::from_secs(3600),
            ..ReqlogConfig::default()
        };
        let logger = DuckLogger::new(cfg).unwrap();

        for i in 0..5000 {
            logger.log(record(i));
        }
        assert!(logger.dropped() > 0, "expected drops under a full queue");

        logger.shutdown().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
