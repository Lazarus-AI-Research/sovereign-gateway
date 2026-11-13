//! The QE dialect: a provider whose `extra` says `dialect = "qe"` is a QE
//! server, whose Chat Completions surface is its internal request
//! representation. A request in a shape such a provider does not serve
//! natively is translated with QE's own rules ([`yb_wire::qe`]) rather than
//! through the cross-provider IR, and QE's Chat answer is written back as
//! QE's own encoder for the client's shape would have written it.
//!
//! Responses features that need state (`previous_response_id`, `store`,
//! `item_reference`, `GET` / `DELETE` / `cancel` / `input_items`,
//! `background`) are kept here, as QE keeps them: an in-memory store of each
//! response's conversation (chat messages) and object, capped by count and
//! size, oldest dropped first.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use futures::{stream, StreamExt};
use serde_json::{json, Value};

use yb_core::{Error, Extra, Result, WireFormat};
use yb_providers::ByteStream;
use yb_wire::qe::{
    anthropic_message, assistant_message, collect_chat, input_items, AnthropicStream, ChatEvents,
    Collected, Ev, ResponseItems, ResponsesCtx, ResponsesStream, SamplingDefaults,
};
use yb_wire::Usage;

use crate::service::RecordCtx;

/// Whether a provider is a QE server (`extra.dialect = "qe"`).
pub fn is_qe(extra: &Extra) -> bool {
    extra.rest.get("dialect").and_then(|d| d.as_str()) == Some("qe")
}

/// The provider's QE sampling defaults (`extra.qe_sampling = {temperature,
/// top_p}`), echoed by Responses objects for requests that do not set them.
pub fn sampling_defaults(extra: &Extra) -> SamplingDefaults {
    let mut d = SamplingDefaults::default();
    if let Some(s) = extra.rest.get("qe_sampling") {
        if let Some(t) = s.get("temperature").and_then(|v| v.as_f64()) {
            d.temperature = t as f32;
        }
        if let Some(p) = s.get("top_p").and_then(|v| v.as_f64()) {
            d.top_p = p as f32;
        }
    }
    d
}

fn hex_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()[..24].to_string()
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ---------------------------------------------------------------------------
// The response store
// ---------------------------------------------------------------------------

struct Entry {
    /// The user the response belongs to: only they can read or continue it.
    owner: Option<String>,
    history: Vec<Value>,
    response: Value,
    size: usize,
}

#[derive(Default)]
struct Inner {
    map: HashMap<String, Entry>,
    inputs: HashMap<String, Vec<Value>>,
    order: VecDeque<String>,
    bytes: usize,
    /// Background responses still running: their cancel switches.
    running: HashMap<String, tokio::sync::watch::Sender<bool>>,
}

/// Responses kept for `previous_response_id` and `GET /v1/responses/{id}`
/// (QE's `ResponseStore`): the conversation as chat messages (without
/// instructions, which do not carry over) and the response object.
pub struct ResponseStore {
    inner: Mutex<Inner>,
    pub cap: usize,
    pub max_bytes: usize,
}

impl Default for ResponseStore {
    fn default() -> Self {
        Self::new(1024, 256 << 20)
    }
}

impl ResponseStore {
    pub fn new(cap: usize, max_bytes: usize) -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            cap,
            max_bytes,
        }
    }

    pub fn put(&self, id: &str, owner: Option<&str>, history: Vec<Value>, response: Value) {
        if self.cap == 0 {
            return;
        }
        let size =
            history.iter().map(|m| m.to_string().len()).sum::<usize>() + response.to_string().len();
        let mut s = self.inner.lock().unwrap();
        s.bytes += size;
        let e = Entry {
            owner: owner.map(str::to_string),
            history,
            response,
            size,
        };
        if let Some(old) = s.map.insert(id.to_string(), e) {
            s.bytes -= old.size;
        } else {
            s.order.push_back(id.to_string());
        }
        while s.map.len() > self.cap || (self.max_bytes > 0 && s.bytes > self.max_bytes) {
            let Some(old) = s.order.pop_front() else {
                break;
            };
            if let Some(e) = s.map.remove(&old) {
                s.bytes -= e.size;
            }
            s.inputs.remove(&old);
        }
    }

    fn put_inputs(&self, id: &str, items: Vec<Value>) {
        let mut s = self.inner.lock().unwrap();
        if s.map.contains_key(id) {
            s.inputs.insert(id.to_string(), items);
        }
    }

    pub fn get(&self, id: &str, owner: Option<&str>) -> Option<Value> {
        self.inner
            .lock()
            .unwrap()
            .map
            .get(id)
            .filter(|e| e.owner.as_deref() == owner)
            .map(|e| e.response.clone())
    }

    /// The store as one user sees it.
    pub fn view<'a>(&'a self, owner: Option<&'a str>) -> View<'a> {
        View { store: self, owner }
    }

    fn set_status(&self, id: &str, status: &str) {
        if let Some(e) = self.inner.lock().unwrap().map.get_mut(id) {
            if e.response["status"] != "cancelled" {
                e.response["status"] = status.into();
            }
        }
    }

    /// `DELETE`: stops a background response and forgets it.
    pub fn delete(&self, id: &str, owner: Option<&str>) -> bool {
        let mut s = self.inner.lock().unwrap();
        if !s.map.get(id).is_some_and(|e| e.owner.as_deref() == owner) {
            return false;
        }
        if let Some(c) = s.running.remove(id) {
            let _ = c.send(true);
        }
        let Some(e) = s.map.remove(id) else {
            return false;
        };
        s.bytes -= e.size;
        s.order.retain(|x| x != id);
        s.inputs.remove(id);
        true
    }

    /// `POST .../cancel`: QE's semantics (only background responses; a
    /// running one becomes `cancelled`, a finished one is returned as is).
    pub fn cancel(&self, id: &str, owner: Option<&str>) -> Result<Value> {
        let mut s = self.inner.lock().unwrap();
        let flag = s.running.get(id).cloned();
        let Some(e) = s.map.get_mut(id).filter(|e| e.owner.as_deref() == owner) else {
            return Err(Error::NotFound(format!(
                "No response found with id '{id}'."
            )));
        };
        if e.response.get("background").and_then(|b| b.as_bool()) != Some(true) {
            return Err(Error::BadRequest(
                "Only background responses can be cancelled.".into(),
            ));
        }
        if let Some(f) = flag {
            let _ = f.send(true);
            if matches!(
                e.response["status"].as_str(),
                Some("queued" | "in_progress")
            ) {
                e.response["status"] = "cancelled".into();
            }
        }
        Ok(e.response.clone())
    }

    /// `GET .../input_items` (QE's paging: order desc by default, `after`
    /// cursor, `limit` 1-100, default 20).
    pub fn input_items(
        &self,
        id: &str,
        owner: Option<&str>,
        query: &HashMap<String, String>,
    ) -> Result<Value> {
        let s = self.inner.lock().unwrap();
        if !s.map.get(id).is_some_and(|e| e.owner.as_deref() == owner) {
            return Err(Error::NotFound(format!(
                "No response found with id '{id}'."
            )));
        }
        let mut items = s.inputs.get(id).cloned().unwrap_or_default();
        match query.get("order").map(|s| s.as_str()) {
            None | Some("desc") => items.reverse(),
            Some("asc") => {}
            Some(_) => return Err(Error::BadRequest("order: must be asc or desc".into())),
        }
        if let Some(after) = query.get("after") {
            if let Some(k) = items
                .iter()
                .position(|it| it.get("id").and_then(|x| x.as_str()) == Some(after))
            {
                items.drain(..=k);
            }
        }
        let limit = match query.get("limit").map(|l| l.parse::<usize>()) {
            None => 20,
            Some(Ok(n)) if (1..=100).contains(&n) => n,
            _ => {
                return Err(Error::BadRequest(
                    "limit: must be an integer in [1, 100]".into(),
                ))
            }
        };
        let has_more = items.len() > limit;
        items.truncate(limit);
        let first = items
            .first()
            .and_then(|i| i.get("id"))
            .cloned()
            .unwrap_or(Value::Null);
        let last = items
            .last()
            .and_then(|i| i.get("id"))
            .cloned()
            .unwrap_or(Value::Null);
        Ok(
            json!({"object": "list", "data": items, "first_id": first, "last_id": last, "has_more": has_more}),
        )
    }
}

/// The store as one user sees it: their own responses only.
pub struct View<'a> {
    store: &'a ResponseStore,
    owner: Option<&'a str>,
}

impl ResponseItems for View<'_> {
    fn history(&self, id: &str) -> Option<Vec<Value>> {
        self.store
            .inner
            .lock()
            .unwrap()
            .map
            .get(id)
            .filter(|e| e.owner.as_deref() == self.owner)
            .map(|e| e.history.clone())
    }
    fn item(&self, id: &str) -> Option<Value> {
        let s = self.store.inner.lock().unwrap();
        let mine = |k: &String| {
            s.map
                .get(k)
                .is_some_and(|e| e.owner.as_deref() == self.owner)
        };
        s.map
            .iter()
            .filter(|(k, _)| mine(k))
            .map(|(_, e)| e)
            .flat_map(|e| {
                e.response
                    .get("output")
                    .and_then(|o| o.as_array())
                    .into_iter()
                    .flatten()
            })
            .chain(
                s.inputs
                    .iter()
                    .filter(|(k, _)| mine(k))
                    .flat_map(|(_, v)| v),
            )
            .find(|it| it.get("id").and_then(|x| x.as_str()) == Some(id))
            .cloned()
    }
    fn cap(&self) -> usize {
        self.store.cap
    }
}

// ---------------------------------------------------------------------------
// Responses relayed to a provider that keeps them itself
// ---------------------------------------------------------------------------

/// Where a relayed Responses answer lives: the provider keeps it (and its
/// conversation), so `GET` / `DELETE` / `cancel` / `input_items` of its id go
/// back there, and a `previous_response_id` naming it is routed there first.
#[derive(Debug, Clone)]
pub struct Relayed {
    /// The provider's Responses endpoint (`…/v1/responses`).
    pub url: String,
    /// The credentials and edge headers the turn was sent with.
    pub headers: Vec<(String, String)>,
    pub owner: Option<String>,
    pub provider_id: String,
    pub model_id: String,
}

/// Relayed Responses ids, newest kept (bounded like the store).
pub struct RelayedResponses {
    inner: Mutex<(HashMap<String, Relayed>, VecDeque<String>)>,
    cap: usize,
}

impl Default for RelayedResponses {
    fn default() -> Self {
        Self {
            inner: Mutex::new(Default::default()),
            cap: 16384,
        }
    }
}

impl RelayedResponses {
    pub fn insert(&self, id: &str, r: Relayed) {
        let mut g = self.inner.lock().unwrap();
        if g.0.insert(id.to_string(), r).is_none() {
            g.1.push_back(id.to_string());
        }
        while g.0.len() > self.cap {
            let Some(old) = g.1.pop_front() else { break };
            g.0.remove(&old);
        }
    }

    /// The relayed response `id`, if `owner` made it.
    pub fn get(&self, id: &str, owner: Option<&str>) -> Option<Relayed> {
        self.inner
            .lock()
            .unwrap()
            .0
            .get(id)
            .filter(|r| r.owner.as_deref() == owner)
            .cloned()
    }
}

// ---------------------------------------------------------------------------
// One translated turn
// ---------------------------------------------------------------------------

/// How the client's answer is written from QE's Chat answer.
#[derive(Clone)]
pub(crate) enum Reply {
    Anthropic {
        id: String,
    },
    Responses {
        id: String,
        created: u64,
        ctx: Arc<ResponsesCtx>,
        /// This turn's conversation, stored with the reply appended.
        history: Vec<Value>,
        /// The request as sent, for its input items.
        request: Value,
        store: bool,
        background: bool,
        owner: Option<String>,
    },
}

/// A request in `surface` as QE's Chat request: the body, whether the client
/// streams, and how the answer is to be written.
pub(crate) fn translate(
    surface: WireFormat,
    body: &[u8],
    upstream_model: &str,
    extra: &Extra,
    store: &ResponseStore,
    owner: Option<&str>,
) -> Result<(Vec<u8>, bool, Reply)> {
    let v: Value = serde_json::from_slice(body)
        .map_err(|e| Error::BadRequest(format!("invalid JSON body: {e}")))?;
    let wire = |e: yb_wire::WireError| Error::BadRequest(e.to_string());
    let (mut chat, reply) = match surface {
        WireFormat::Anthropic => {
            let (chat, gaps) = yb_wire::qe::anthropic_to_chat(&v).map_err(wire)?;
            for g in &gaps.0 {
                tracing::info!(gap = %g, "qe: anthropic request carried over approximately");
            }
            (
                chat,
                Reply::Anthropic {
                    id: format!("msg_{}", hex_id()),
                },
            )
        }
        WireFormat::OpenaiResponses => {
            let t = yb_wire::qe::responses_to_chat(&v, &store.view(owner)).map_err(wire)?;
            for g in &t.gaps.0 {
                tracing::info!(gap = %g, "qe: responses request carried over approximately");
            }
            let background = v
                .get("background")
                .and_then(|b| b.as_bool())
                .unwrap_or(false);
            let keep = v.get("store").and_then(|s| s.as_bool()).unwrap_or(true) && store.cap > 0;
            if background && !keep {
                return Err(Error::BadRequest(
                    "background: background responses need the response store (store=true)".into(),
                ));
            }
            // QE echoes, and lists as input items, the request as sent (item
            // references unresolved).
            let ctx = ResponsesCtx::new(&v, sampling_defaults(extra), keep, background);
            (
                t.body,
                Reply::Responses {
                    id: format!("resp_{}", hex_id()),
                    created: now_secs(),
                    ctx: Arc::new(ctx),
                    history: t.history,
                    request: v.clone(),
                    store: keep,
                    background,
                    owner: owner.map(str::to_string),
                },
            )
        }
        other => {
            return Err(Error::Internal(format!(
                "qe translation has no {} surface",
                other.as_str()
            )))
        }
    };
    let stream = chat
        .get("stream")
        .and_then(|s| s.as_bool())
        .unwrap_or(false);
    chat["model"] = upstream_model.into();
    if stream {
        // Usage reaches the end of a Chat stream only when asked for; the
        // other shapes always report it.
        chat["stream_options"] = json!({"include_usage": true});
    }
    let bytes = serde_json::to_vec(&chat).map_err(|e| Error::Internal(e.to_string()))?;
    Ok((bytes, stream, reply))
}

fn usage_of(c: &Collected) -> Usage {
    Usage {
        input_tokens: c.prompt_tokens as u32,
        output_tokens: c.completion_tokens as u32,
        cache_read_tokens: c.cached as u32,
        cache_write_tokens: c.written as u32,
        reasoning_tokens: c.reasoning_tokens as u32,
        ..Default::default()
    }
}

impl Reply {
    /// The response object before any output (`queued` for background).
    fn initial(&self, model: &str) -> Option<Value> {
        match self {
            Reply::Responses {
                id,
                created,
                ctx,
                background,
                ..
            } => Some(ctx.object(
                id,
                model,
                *created,
                if *background { "queued" } else { "in_progress" },
                vec![],
                None,
            )),
            Reply::Anthropic { .. } => None,
        }
    }

    /// The finished client answer; a Responses one is stored (QE stores all
    /// but failed foreground responses).
    fn finish(&self, model: &str, c: &Collected, store: &ResponseStore, cancelled: bool) -> Value {
        match self {
            Reply::Anthropic { id } => anthropic_message(c, id, model),
            Reply::Responses {
                id,
                created,
                ctx,
                history,
                request,
                store: keep,
                background,
                owner,
            } => {
                let r = if cancelled {
                    ctx.object(id, model, *created, "cancelled", ctx.output(id, c), Some(c))
                } else {
                    ctx.finished(id, model, *created, c)
                };
                if *keep && (r["status"] != "failed" || *background) {
                    let mut h = history.clone();
                    h.push(assistant_message(id, c));
                    store.put(id, owner.as_deref(), h, r.clone());
                    store.put_inputs(id, input_items(request, id));
                }
                if *background {
                    store.inner.lock().unwrap().running.remove(id);
                }
                r
            }
        }
    }
}

/// A buffered QE Chat answer as the client's buffered answer.
pub(crate) async fn full(
    bytes: Vec<u8>,
    reply: Reply,
    model: &str,
    store: &ResponseStore,
    rctx: RecordCtx,
    status: u16,
) -> Result<(u16, Vec<u8>)> {
    let v: Value = serde_json::from_slice(&bytes)
        .map_err(|e| Error::Wire(format!("QE chat answer is not JSON: {e}")))?;
    let c = collect_chat(&v);
    let out = reply.finish(model, &c, store, false);
    let body = serde_json::to_vec(&out).map_err(|e| Error::Internal(e.to_string()))?;
    rctx.finish(
        usage_of(&c),
        status,
        c.error.is_some(),
        body.clone(),
        body.len() as i64,
    )
    .await;
    // A failed Responses object is a 500, as QE answers it.
    let status = if out["status"] == "failed" {
        500
    } else {
        status
    };
    Ok((status, body))
}

/// Starts a background Responses turn: the client gets the queued object
/// now; the upstream answer is read in a task that `cancel` / `DELETE` stop.
pub(crate) fn background(
    up: ByteStream,
    upstream_stream: bool,
    reply: Reply,
    model: String,
    store: Arc<ResponseStore>,
    rctx: RecordCtx,
    status: u16,
) -> Vec<u8> {
    let Reply::Responses { id, owner, .. } = &reply else {
        unreachable!("background is a Responses feature")
    };
    let id = id.clone();
    let r0 = reply.initial(&model).unwrap_or(Value::Null);
    store.put(&id, owner.as_deref(), Vec::new(), r0.clone());
    let (tx, mut rx) = tokio::sync::watch::channel(false);
    store.inner.lock().unwrap().running.insert(id.clone(), tx);
    tokio::spawn(async move {
        store.set_status(&id, "in_progress");
        let mut events = ChatEvents::default();
        let mut buf: Vec<u8> = Vec::new();
        let mut up = up;
        let mut cancelled = false;
        loop {
            tokio::select! {
                _ = rx.changed() => { cancelled = true; break; }
                item = up.next() => match item {
                    Some(Ok(chunk)) => {
                        buf.extend_from_slice(&chunk);
                        if upstream_stream {
                            while let Some(pos) = buf.iter().position(|&b| b == b'\n') {
                                let line: Vec<u8> = buf.drain(..=pos).collect();
                                let text = String::from_utf8_lossy(&line);
                                if let Some(d) = text.trim_end().strip_prefix("data:") {
                                    events.push(d);
                                }
                            }
                        }
                    }
                    Some(Err(e)) => { events.collected.error = Some(e.to_string()); break; }
                    None => break,
                }
            }
        }
        let c = if upstream_stream {
            events.finish();
            events.collected
        } else {
            serde_json::from_slice::<Value>(&buf)
                .map(|v| collect_chat(&v))
                .unwrap_or_default()
        };
        let out = reply.finish(&model, &c, &store, cancelled);
        let body = serde_json::to_vec(&out).unwrap_or_default();
        rctx.finish(
            usage_of(&c),
            status,
            c.error.is_some(),
            body.clone(),
            body.len() as i64,
        )
        .await;
    });
    serde_json::to_vec(&r0).unwrap_or_default()
}

enum Encoder {
    Anthropic(AnthropicStream),
    Responses(ResponsesStream),
}

struct StreamState {
    up: ByteStream,
    buf: Vec<u8>,
    events: ChatEvents,
    enc: Encoder,
    reply: Reply,
    model: String,
    store: Arc<ResponseStore>,
    rctx: RecordCtx,
    status: u16,
    started: bool,
    done: bool,
    recorded: bool,
    bytes: i64,
}

impl StreamState {
    fn encode(&mut self, evs: &[Ev]) -> Vec<u8> {
        let mut out = Vec::new();
        for e in evs {
            if matches!(e, Ev::Reasoning(s) | Ev::Text(s) if !s.is_empty())
                || matches!(e, Ev::ToolStart { .. } | Ev::Custom { .. })
            {
                self.rctx.first_token();
            }
            match &mut self.enc {
                Encoder::Anthropic(a) => out.extend(a.event(e)),
                Encoder::Responses(r) => out.extend(r.event(e)),
            }
        }
        out
    }

    /// The end of the client's stream, the turn recorded.
    async fn end(&mut self) -> Vec<u8> {
        let mut out = {
            let evs = self.events.finish();
            self.encode(&evs)
        };
        let c = self.events.collected.clone();
        let fin = self.reply.finish(&self.model, &c, &self.store, false);
        match &mut self.enc {
            Encoder::Anthropic(a) => out.extend(a.end(&c)),
            Encoder::Responses(r) => {
                if c.error.is_none() {
                    out.extend(r.close());
                }
                out.extend(r.end(&fin));
            }
        }
        if !self.recorded {
            self.recorded = true;
            let body = serde_json::to_vec(&fin).unwrap_or_default();
            let n = self.bytes + out.len() as i64;
            self.rctx
                .finish(usage_of(&c), self.status, c.error.is_some(), body, n)
                .await;
        }
        out
    }
}

impl Drop for StreamState {
    fn drop(&mut self) {
        if self.recorded {
            return;
        }
        let rctx = self.rctx.clone();
        let usage = usage_of(&self.events.collected);
        let bytes = self.bytes;
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                rctx.finish(usage, 499, true, Vec::new(), bytes).await;
            });
        }
    }
}

/// QE's Chat SSE stream as the client's SSE stream.
pub(crate) fn stream(
    up: ByteStream,
    reply: Reply,
    model: String,
    store: Arc<ResponseStore>,
    rctx: RecordCtx,
    status: u16,
) -> ByteStream {
    let enc = match &reply {
        Reply::Anthropic { id } => {
            Encoder::Anthropic(AnthropicStream::new(id.clone(), model.clone()))
        }
        Reply::Responses { id, ctx, .. } => {
            Encoder::Responses(ResponsesStream::new(id.clone(), ctx))
        }
    };
    let init = StreamState {
        up,
        buf: Vec::new(),
        events: ChatEvents::default(),
        enc,
        reply,
        model,
        store,
        rctx,
        status,
        started: false,
        done: false,
        recorded: false,
        bytes: 0,
    };
    let s = stream::unfold(init, |mut st| async move {
        if st.done {
            return None;
        }
        let mut out = Vec::new();
        if !st.started {
            st.started = true;
            if let (Encoder::Responses(r), Some(r0)) = (&mut st.enc, st.reply.initial(&st.model)) {
                out.extend(r.begin(&r0));
            }
        }
        loop {
            match st.up.next().await {
                Some(Ok(chunk)) => {
                    st.buf.extend_from_slice(&chunk);
                    let mut evs = Vec::new();
                    let mut ended = false;
                    while let Some(pos) = st.buf.iter().position(|&b| b == b'\n') {
                        let line: Vec<u8> = st.buf.drain(..=pos).collect();
                        let text = String::from_utf8_lossy(&line);
                        if let Some(d) = text.trim_end().strip_prefix("data:") {
                            ended |= d.trim() == "[DONE]";
                            evs.extend(st.events.push(d));
                        }
                    }
                    out.extend(st.encode(&evs));
                    if ended || st.events.collected.error.is_some() {
                        out.extend(st.end().await);
                        st.done = true;
                    }
                    if !out.is_empty() {
                        st.bytes += out.len() as i64;
                        return Some((Ok(Bytes::from(out)), st));
                    }
                }
                Some(Err(e)) => {
                    st.events.collected.error = Some(e.to_string());
                    out.extend(st.end().await);
                    st.done = true;
                    return Some((Ok(Bytes::from(out)), st));
                }
                None => {
                    out.extend(st.end().await);
                    st.done = true;
                    return Some((Ok(Bytes::from(out)), st));
                }
            }
        }
    });
    Box::pin(s)
}
