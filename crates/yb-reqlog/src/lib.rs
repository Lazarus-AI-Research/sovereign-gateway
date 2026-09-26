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
//! [`DuckLogger::log`] applies the capture policy first: nothing is kept while
//! capture is off, and bodies are redacted (or dropped, keeping metadata only)
//! before they leave the request's thread, so unredacted text never reaches
//! the queue or the disk. It then boxes the record and pushes it onto a
//! bounded [`std::sync::mpsc::sync_channel`] with a non-blocking `try_send`. When the queue is full the record is dropped and a counter is
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
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use chrono::{NaiveDate, SecondsFormat, Utc};
use duckdb::{params, Connection};

use yb_core::{
    CaptureFilter, CapturePolicy, CapturedTurn, Error, Redaction, RequestLogRecord, RequestLogger,
    Result,
};
use yb_redact::PatternRedactor;

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
    response_body      BLOB,
    api_key_id         VARCHAR,
    user_id            VARCHAR,
    tags               VARCHAR,
    redaction          VARCHAR
)";

/// A log written before a column existed gains it, so an upgraded gateway
/// keeps its buffered turns.
const ADD_LATER_COLUMNS: &str = "\
ALTER TABLE turns ADD COLUMN IF NOT EXISTS api_key_id VARCHAR;
ALTER TABLE turns ADD COLUMN IF NOT EXISTS user_id VARCHAR;
ALTER TABLE turns ADD COLUMN IF NOT EXISTS tags VARCHAR;
ALTER TABLE turns ADD COLUMN IF NOT EXISTS redaction VARCHAR;";

/// Parameterised insert. Strings are CAST into the temporal / unsigned columns so
/// we do not need DuckDB's optional `chrono` feature enabled.
const INSERT_TURN: &str = "\
INSERT INTO turns (id, ts, log_date, request_id, trace_id, installation_id, surface,
    requested_model, decision_model, decision_provider, upstream_status, is_error,
    request_bytes, response_bytes, response_truncated, request_body, response_body,
    api_key_id, user_id, tags, redaction) VALUES (
    CAST(? AS UBIGINT), CAST(? AS TIMESTAMP), CAST(? AS DATE),
    ?, ?, ?, ?, ?, ?, ?, ?, ?,
    CAST(? AS INTEGER), CAST(? AS INTEGER), ?, ?, ?,
    ?, ?, ?, ?
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
    /// Flushed, the worker hands back a connection of its own for the
    /// export to read through, so a long export never holds up logging.
    Export(mpsc::Sender<std::result::Result<(Connection, PathBuf), String>>),
    Shutdown(Ack),
}

/// A non-blocking, DuckDB-backed [`RequestLogger`].
///
/// Cloning is intentionally not provided; share via `Arc<DuckLogger>`.
pub struct DuckLogger {
    tx: SyncSender<Msg>,
    dropped: Arc<AtomicU64>,
    worker: Mutex<Option<JoinHandle<()>>>,
    /// Off until an operator's policy says otherwise.
    policy: std::sync::RwLock<CapturePolicy>,
    /// Shared with the worker, which prunes by it.
    retention_days: Arc<AtomicU32>,
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
        let retention_days = Arc::new(AtomicU32::new(cfg.retention_days));
        let worker_retention = retention_days.clone();

        let handle = std::thread::Builder::new()
            .name("yb-reqlog".to_string())
            .spawn(move || match Worker::open(cfg, worker_retention) {
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
                policy: std::sync::RwLock::new(CapturePolicy {
                    enabled: false,
                    retention_days: retention_days.load(Ordering::Relaxed),
                    ..CapturePolicy::default()
                }),
                retention_days,
            }),
            Ok(Err(detail)) => {
                let _ = handle.join();
                Err(Error::Storage(format!("reqlog: {detail}")))
            }
            Err(_) => {
                let _ = handle.join();
                Err(Error::Internal(
                    "reqlog: worker exited during startup".into(),
                ))
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
    fn log(&self, mut record: RequestLogRecord) {
        let policy = *self.policy.read().unwrap_or_else(|e| e.into_inner());
        if !policy.enabled {
            return;
        }
        redact(&mut record, policy.redaction);
        match self.tx.try_send(Msg::Record(Box::new(record))) {
            Ok(()) => {}
            // Full queue, or worker already gone (post-shutdown). Either way we
            // drop and count — never block or panic on the request path.
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn policy(&self) -> CapturePolicy {
        *self.policy.read().unwrap_or_else(|e| e.into_inner())
    }

    fn captures(&self) -> bool {
        true
    }

    fn apply_policy(&self, policy: &CapturePolicy) {
        *self.policy.write().unwrap_or_else(|e| e.into_inner()) = *policy;
        self.retention_days
            .store(policy.retention_days, Ordering::Relaxed);
    }

    fn export(&self, filter: &CaptureFilter) -> Result<Vec<CapturedTurn>> {
        let (ack_tx, ack_rx) = mpsc::channel();
        self.tx
            .send(Msg::Export(ack_tx))
            .map_err(|_| Error::Internal("reqlog: worker is gone".into()))?;
        let (conn, shards_dir) = ack_rx
            .recv()
            .map_err(|_| Error::Internal("reqlog: worker is gone".into()))?
            .map_err(Error::Storage)?;
        // Shards pruned between listing and reading fail the first attempt;
        // the second lists them again.
        export_turns(&conn, &shards_dir, filter)
            .or_else(|_| export_turns(&conn, &shards_dir, filter))
    }
}

/// The captured turns the filter takes, from the write-ahead table and every
/// shard, oldest first. A shard written before a column existed reads it as
/// null, and a turn a rotation left in both places (the same id, time and
/// request) is taken once; turns that only share a caller's request id are
/// all kept. Tags are
/// matched here rather than in SQL: they are a small JSON object per turn.
fn export_turns(
    conn: &Connection,
    shards_dir: &Path,
    filter: &CaptureFilter,
) -> Result<Vec<CapturedTurn>> {
    let columns = "id, ts, request_id, surface, requested_model, api_key_id, user_id, tags, redaction, request_body, response_body, is_error";
    let has_shards = std::fs::read_dir(shards_dir)
        .map(|entries| {
            entries
                .flatten()
                .any(|entry| entry.path().extension().and_then(|e| e.to_str()) == Some("parquet"))
        })
        .unwrap_or(false);
    let mut source = format!("SELECT {columns} FROM turns");
    if has_shards {
        let pattern = shards_dir.join("*.parquet");
        let pattern = pattern.to_string_lossy().replace('\'', "''");
        source.push_str(&format!(
            " UNION ALL BY NAME SELECT * FROM read_parquet('{pattern}', union_by_name = true)"
        ));
    }
    let mut conditions = vec!["NOT is_error".to_string()];
    let mut values: Vec<String> = Vec::new();
    let format = |t: &yb_core::Timestamp| t.format("%Y-%m-%d %H:%M:%S%.6f").to_string();
    if let Some(from) = &filter.from {
        conditions.push("ts >= CAST(? AS TIMESTAMP)".into());
        values.push(format(from));
    }
    if let Some(to) = &filter.to {
        conditions.push("ts < CAST(? AS TIMESTAMP)".into());
        values.push(format(to));
    }
    for (column, wanted) in [
        ("requested_model", &filter.models),
        ("api_key_id", &filter.api_key_ids),
    ] {
        if !wanted.is_empty() {
            conditions.push(format!(
                "{column} IN ({})",
                vec!["?"; wanted.len()].join(", ")
            ));
            values.extend(wanted.iter().cloned());
        }
    }
    if let Some(redaction) = &filter.redaction {
        conditions.push("redaction = ?".into());
        values.push(redaction.clone());
    }
    let query = format!(
        "SELECT CAST(ts AS VARCHAR), request_id, surface, requested_model, api_key_id, user_id, tags, \
         COALESCE(redaction, 'none'), request_body, response_body FROM ({source}) WHERE {} QUALIFY row_number() OVER (PARTITION BY id, ts, request_id) = 1 ORDER BY ts",
        conditions.join(" AND ")
    );
    let mut statement = conn.prepare(&query).map_err(map_db)?;
    let rows = statement
        .query_map(duckdb::params_from_iter(values.iter()), |row| {
            Ok((
                row.get::<_, String>(0)?,
                CapturedTurn {
                    ts: yb_core::now(),
                    request_id: row.get(1)?,
                    surface: row.get(2)?,
                    requested_model: row.get(3)?,
                    api_key_id: row.get(4)?,
                    user_id: row.get(5)?,
                    tags: row.get(6)?,
                    redaction: row.get(7)?,
                    request_body: row.get::<_, Option<Vec<u8>>>(8)?.unwrap_or_default(),
                    response_body: row.get::<_, Option<Vec<u8>>>(9)?.unwrap_or_default(),
                },
            ))
        })
        .map_err(map_db)?;
    let mut turns = Vec::new();
    for row in rows {
        let (ts, mut turn) = row.map_err(map_db)?;
        if let Ok(parsed) = chrono::NaiveDateTime::parse_from_str(&ts, "%Y-%m-%d %H:%M:%S%.f") {
            turn.ts = parsed.and_utc();
        }
        if tags_match(turn.tags.as_deref(), &filter.tags) {
            turns.push(turn);
        }
    }
    Ok(turns)
}

/// The policy's redaction, applied to both bodies before a record is queued.
fn redact(record: &mut RequestLogRecord, redaction: Redaction) {
    record.redaction = redaction.as_str().to_string();
    match redaction {
        Redaction::None => {}
        Redaction::MetadataOnly => {
            record.request_body.clear();
            record.response_body.clear();
        }
        Redaction::Patterns => {
            for body in [&mut record.request_body, &mut record.response_body] {
                *body = yb_redact::redact_body(&PatternRedactor, body);
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
    retention_days: Arc<AtomicU32>,
    db_path: PathBuf,
    shards_dir: PathBuf,
    buf: Vec<RequestLogRecord>,
    next_id: u64,
    last_rotate: Instant,
    last_date: NaiveDate,
}

impl Worker {
    /// Open the WAL database and prepare the directory layout.
    fn open(cfg: ReqlogConfig, retention_days: Arc<AtomicU32>) -> Result<Self> {
        let shards_dir = cfg.dir.join("shards");
        std::fs::create_dir_all(&shards_dir)
            .map_err(|e| Error::Storage(format!("reqlog: create dir: {e}")))?;

        let db_path = cfg.dir.join("wal.duckdb");
        let conn = Connection::open(&db_path).map_err(map_db)?;
        conn.execute_batch(CREATE_TURNS).map_err(map_db)?;
        conn.execute_batch(ADD_LATER_COLUMNS).map_err(map_db)?;

        // Resume the surrogate id sequence past any rows left from a prior run.
        let max_id: i64 = conn
            .query_row("SELECT COALESCE(MAX(id), 0) FROM turns", [], |r| r.get(0))
            .map_err(map_db)?;

        Ok(Self {
            conn,
            cfg,
            retention_days,
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
                Ok(Msg::Export(ack)) => {
                    let r = self.flush().and_then(|()| {
                        let conn = self.conn.try_clone().map_err(map_db)?;
                        Ok((conn, self.shards_dir.clone()))
                    });
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

        self.conn
            .execute_batch("BEGIN TRANSACTION")
            .map_err(map_db)?;
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
                    rec.api_key_id,
                    rec.user_id,
                    rec.tags,
                    rec.redaction,
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
        std::fs::metadata(&self.db_path)
            .map(|m| m.len())
            .unwrap_or(0)
    }

    /// Flush, write a compressed Parquet shard if `turns` is non-empty, truncate
    /// the buffer, checkpoint the WAL, prune expired shards, and finally invoke
    /// the optional roll hook on the freshly-sealed shard.
    fn rotate(&mut self) -> Result<()> {
        self.flush()?;

        let mut sealed: Option<PathBuf> = None;
        if self.count()? > 0 {
            // Written under a name no export reads, then renamed into place,
            // so an export never opens a shard that is half written.
            let path = self.shards_dir.join(format!("{}.parquet", shard_stamp()));
            let partial = path.with_extension("parquet.partial");
            let partial_sql = partial.to_string_lossy().replace('\'', "''");
            self.conn
                .execute_batch(&format!(
                    "COPY (SELECT * FROM turns) TO '{partial_sql}' (FORMAT parquet, COMPRESSION zstd)"
                ))
                .map_err(map_db)?;
            std::fs::rename(&partial, &path)
                .map_err(|e| Error::Storage(format!("reqlog: seal shard: {e}")))?;
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

        match std::process::Command::new("sh")
            .arg("-c")
            .arg(&script)
            .status()
        {
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
        let retention_days = self.retention_days.load(Ordering::Relaxed);
        if retention_days == 0 {
            return;
        }
        let Some(cutoff) = std::time::SystemTime::now()
            .checked_sub(Duration::from_secs(retention_days as u64 * 86_400))
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

/// Whether a turn's tags carry every wanted `(key, value)`.
fn tags_match(tags: Option<&str>, wanted: &[(String, String)]) -> bool {
    if wanted.is_empty() {
        return true;
    }
    let Some(tags) = tags.and_then(|t| serde_json::from_str::<serde_json::Value>(t).ok()) else {
        return false;
    };
    wanted
        .iter()
        .all(|(key, value)| tags.get(key).and_then(|v| v.as_str()) == Some(value.as_str()))
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

    /// A logger with capture on and bodies kept as they came, as these tests
    /// exercise storage rather than policy.
    fn capturing(logger: DuckLogger) -> DuckLogger {
        logger.apply_policy(&CapturePolicy {
            enabled: true,
            redaction: Redaction::None,
            retention_days: 30,
        });
        logger
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
            api_key_id: Some("key-1".to_string()),
            user_id: Some("user-1".to_string()),
            tags: Some(r#"{"space":"s1"}"#.to_string()),
            redaction: "none".to_string(),
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

        let logger = capturing(DuckLogger::new(cfg).unwrap());

        for i in 0..50 {
            logger.log(record(i));
        }
        logger.flush().unwrap();
        assert_eq!(logger.turns_count().unwrap(), 50, "all records persisted");

        logger.force_rotate().unwrap();

        // WAL buffer is emptied by rotation.
        assert_eq!(
            logger.turns_count().unwrap(),
            0,
            "turns truncated after rotate"
        );

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
        let logger = capturing(DuckLogger::new(cfg).unwrap());

        // A non-empty buffer so a shard is actually sealed.
        for i in 0..3 {
            logger.log(record(i));
        }
        logger.force_rotate().unwrap();

        let recorded = std::fs::read_to_string(&marker)
            .expect("roll hook should have written the marker file");
        assert!(
            recorded.ends_with(".parquet"),
            "hook got the shard path: {recorded}"
        );
        assert!(
            std::path::Path::new(&recorded).exists(),
            "the shard the hook named exists"
        );

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
        let logger = capturing(DuckLogger::new(cfg).unwrap());

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
        let logger = capturing(DuckLogger::new(cfg).unwrap());

        for i in 0..5000 {
            logger.log(record(i));
        }
        assert!(logger.dropped() > 0, "expected drops under a full queue");

        logger.shutdown().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Nothing is kept while capture is off, which it is until a policy
    /// turns it on.
    #[test]
    fn nothing_is_captured_until_a_policy_turns_it_on() {
        let dir = scratch_dir();
        let logger = DuckLogger::new(ReqlogConfig {
            dir: dir.clone(),
            ..Default::default()
        })
        .unwrap();
        logger.log(record(1));
        assert!(logger.export(&CaptureFilter::default()).unwrap().is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Personal data is redacted before a turn is stored, and metadata-only
    /// keeps no text at all; the export says how each turn was redacted and
    /// filters by it, by model, by key and by tag, across the buffer and
    /// sealed shards.
    #[test]
    fn captured_turns_are_redacted_and_exported_by_filter() {
        let dir = scratch_dir();
        let logger = DuckLogger::new(ReqlogConfig {
            dir: dir.clone(),
            ..Default::default()
        })
        .unwrap();
        let personal = |i: usize, model: &str, key: &str, space: &str| {
            let mut r = record(i);
            r.requested_model = model.to_string();
            r.api_key_id = Some(key.to_string());
            r.tags = Some(format!(r#"{{"space":"{space}"}}"#));
            r.request_body =
                br#"{"messages":[{"role":"user","content":"mail ada@example.com"}]}"#.to_vec();
            r
        };
        logger.apply_policy(&CapturePolicy {
            enabled: true,
            redaction: Redaction::Patterns,
            retention_days: 30,
        });
        logger.log(personal(1, "assistant", "key-a", "s1"));
        logger.log(personal(2, "coder", "key-b", "s2"));
        logger.force_rotate().unwrap();
        logger.apply_policy(&CapturePolicy {
            enabled: true,
            redaction: Redaction::MetadataOnly,
            retention_days: 30,
        });
        logger.log(personal(3, "assistant", "key-a", "s1"));

        let all = logger.export(&CaptureFilter::default()).unwrap();
        assert_eq!(all.len(), 3);
        assert!(all
            .iter()
            .all(|t| !String::from_utf8_lossy(&t.request_body).contains("ada@example.com")));
        assert!(String::from_utf8_lossy(&all[0].request_body).contains("[EMAIL]"));
        assert_eq!(all[0].redaction, "patterns");
        assert!(all[2].request_body.is_empty() && all[2].redaction == "metadata_only");

        let assistant = logger
            .export(&CaptureFilter {
                models: vec!["assistant".into()],
                ..Default::default()
            })
            .unwrap();
        assert_eq!(assistant.len(), 2);
        let by_key = logger
            .export(&CaptureFilter {
                api_key_ids: vec!["key-b".into()],
                ..Default::default()
            })
            .unwrap();
        assert_eq!(by_key.len(), 1);
        let in_space = logger
            .export(&CaptureFilter {
                tags: vec![("space".into(), "s1".into())],
                redaction: Some("patterns".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(in_space.len(), 1);
        assert_eq!(in_space[0].api_key_id.as_deref(), Some("key-a"));
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A shard written before capture reads its new columns as null, so an
    /// installation that logged requests before upgrading can still export.
    #[test]
    fn a_shard_from_before_capture_is_exported_beside_new_ones() {
        let dir = scratch_dir();
        std::fs::create_dir_all(dir.join("shards")).unwrap();
        let old = duckdb::Connection::open_in_memory().unwrap();
        let shard = dir.join("shards").join("old.parquet");
        old.execute_batch(&format!(
            "CREATE TABLE turns AS SELECT TIMESTAMP '2026-01-01 00:00:00' AS ts, 'old-1' AS request_id, \
             'anthropic' AS surface, 'claude' AS requested_model, false AS is_error, \
             'hello'::BLOB AS request_body, 'hi'::BLOB AS response_body; \
             COPY turns TO '{}' (FORMAT parquet)",
            shard.display()
        ))
        .unwrap();
        let logger = DuckLogger::new(ReqlogConfig {
            dir: dir.clone(),
            ..Default::default()
        })
        .unwrap();
        let only_old = logger.export(&CaptureFilter::default()).unwrap();
        assert_eq!(only_old.len(), 1, "an old shard alone exports");
        assert_eq!(only_old[0].request_id, "old-1");
        let logger = capturing(logger);
        logger.log(record(1));
        logger.force_rotate().unwrap();
        logger.log(record(2));
        let all = logger.export(&CaptureFilter::default()).unwrap();
        assert_eq!(all.len(), 3);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Until an operator sets a policy, capture is off and the retention is
    /// the configuration's: an upgrade never shortens it.
    #[test]
    fn the_configured_retention_holds_until_a_policy_is_set() {
        let dir = scratch_dir();
        let logger = DuckLogger::new(ReqlogConfig {
            dir: dir.clone(),
            retention_days: 365,
            ..Default::default()
        })
        .unwrap();
        let policy = logger.policy();
        assert!(!policy.enabled);
        assert_eq!(policy.retention_days, 365);
        assert!(logger.captures());
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Turns a caller sent with the same request id are all exported.
    #[test]
    fn turns_sharing_a_request_id_are_all_exported() {
        let dir = scratch_dir();
        let logger = capturing(
            DuckLogger::new(ReqlogConfig {
                dir: dir.clone(),
                ..Default::default()
            })
            .unwrap(),
        );
        for i in 0..3 {
            let mut turn = record(i);
            turn.request_id = "reused".into();
            logger.log(turn);
        }
        logger.force_rotate().unwrap();
        let mut turn = record(4);
        turn.request_id = "reused".into();
        logger.log(turn);
        assert_eq!(logger.export(&CaptureFilter::default()).unwrap().len(), 4);
        let _ = std::fs::remove_dir_all(dir);
    }
}
