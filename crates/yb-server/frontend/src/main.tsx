// SovereignGateway admin — Preact + TSX, bundled by rolldown (build.rs) into one ES
// module the Rust server embeds. Classic JSX (pragma `h`); preact is vendored.
//
// Auth is cookie-based: POST /admin/v1/auth/login sets an HttpOnly session
// cookie; every request uses `credentials: 'include'`. The login account IS the
// user (username + Argon2 password + role). Admins manage everything; members
// read the catalog and manage their own keys + see their own spend.
//
// Navigation uses preact-router (history API, clean paths — not hash).
import { h, Fragment, render } from './vendor/preact.mjs';
import { useState, useEffect } from './vendor/hooks.mjs';
import { Router, route } from './vendor/preact-router.mjs';

async function api<T = any>(path: string, opts: { method?: string; body?: any } = {}): Promise<T> {
  const res = await fetch('/admin/v1' + path, {
    method: opts.method || 'GET',
    credentials: 'include',
    headers: { 'content-type': 'application/json' },
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  const text = await res.text();
  let data: any = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  if (!res.ok) {
    const err: any = new Error((data && data.error && data.error.message) || 'HTTP ' + res.status);
    err.status = res.status;
    throw err;
  }
  return data as T;
}

function useAsync<T>(fn: () => Promise<T>, deps: any[] = []) {
  const [state, setState] = useState<{ loading: boolean; data: T | null; error: string }>({
    loading: true, data: null, error: '',
  });
  const reload = () => {
    setState((s) => ({ ...s, loading: true }));
    fn().then((data) => setState({ loading: false, data, error: '' }))
        .catch((e) => setState({ loading: false, data: null, error: String(e.message || e) }));
  };
  useEffect(() => { reload(); }, deps);
  return [state, reload] as const;
}

const FORMATS = ['openai_chat', 'openai_responses', 'anthropic', 'gemini', 'openai_embed', 'gemini_embed', 'cohere_embed', 'voyage_embed', 'ollama_embed'];
const PERIODS = ['day', 'week', 'month', 'total'];
const SUBJECTS = ['key', 'user', 'team'];

const usd = (micros: number) => '$' + (micros / 1e6).toFixed(2);
const uuid = () => (crypto as any).randomUUID();
const nowIso = () => new Date().toISOString();
const isUnrestricted = (a: any) => !a || !(a.allowed_model_ids?.length || a.denied_model_ids?.length || a.allowed_provider_ids?.length || a.denied_provider_ids?.length);

/**
 * How a key's access reads once its team is taken into account.
 *
 * The key's own policy is only half the answer: at request time the gateway
 * merges it with the team's (deny wins, allow-lists intersect), so a key with
 * an empty policy inside a restricted team is not unrestricted at all — it
 * inherits the team's ceiling. Calling that "unrestricted", as this column
 * used to, is the one reading that is never true.
 *
 * `team` is undefined for a member, who cannot list teams; inheritance still
 * applies, so the label says the team is involved and the tooltip admits the
 * policy itself isn't visible.
 */
const accessLabel = (key: any, team: any): { text: string; title: string } => {
  const k = !isUnrestricted(key.access);
  if (!key.team_id) {
    return k
      ? { text: 'restricted', title: 'limited by this key\u2019s own policy' }
      : { text: 'unrestricted', title: 'every model and provider' };
  }
  if (!team) {
    return k
      ? { text: 'key + team', title: 'this key\u2019s policy, narrowed by its team\u2019s (not visible to you)' }
      : { text: 'team', title: 'inherited from the team (policy not visible to you)' };
  }
  const t = !isUnrestricted(team.access);
  if (k && t) return { text: 'key + team', title: 'this key\u2019s policy, narrowed by ' + team.name + '\u2019s' };
  if (k) return { text: 'restricted', title: 'limited by this key\u2019s own policy; ' + team.name + ' adds nothing' };
  if (t) return { text: 'team', title: 'inherited from ' + team.name + ' \u2014 this key adds no limits of its own' };
  return { text: 'unrestricted', title: 'every model and provider' };
};

type Me = { username: string; role: string };

function Login({ onAuth }: { onAuth: () => void }) {
  // Which login methods the server offers (GET /auth/config). Until loaded we
  // assume local so the form isn't blank on a fast connection. Only methods the
  // UI can actually service are shown (saml is a backend seam, not yet usable).
  const RENDERABLE = ['local', 'sso'];
  const [providers, setProviders] = useState<string[]>(['local']);
  const [tab, setTab] = useState<string>('local');
  const [sitekey, setSitekey] = useState<string>('');
  useEffect(() => {
    api<{ providers: string[]; turnstile_sitekey?: string }>('/auth/config')
      .then((c) => {
        const p = (c.providers || []).filter((x) => RENDERABLE.includes(x));
        const shown = p.length ? p : ['local'];
        setProviders(shown);
        setTab(shown[0]);
        if (c.turnstile_sitekey) setSitekey(c.turnstile_sitekey);
      })
      .catch(() => {});
  }, []);

  // --- local username/password ---
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [err, setErr] = useState('');
  const goLocal = async () => {
    setErr('');
    try { await api('/auth/login', { method: 'POST', body: { username, password } }); onAuth(); }
    catch (e: any) { setErr(e.message); }
  };

  // --- sso email → code ---
  const [email, setEmail] = useState('');
  const [code, setCode] = useState('');
  const [sent, setSent] = useState(false);
  const [devCode, setDevCode] = useState('');
  const [tsToken, setTsToken] = useState('');

  // Cloudflare Turnstile: load the script once and render a Managed widget on the
  // email step when a sitekey is configured. Managed mode is invisible unless
  // Cloudflare decides a challenge is warranted; the callback yields the token.
  useEffect(() => {
    if (tab !== 'sso' || !sitekey || sent) return;
    let widgetId: any;
    const w = window as any;
    const render = () => {
      const el = document.getElementById('cf-ts');
      if (el && w.turnstile && !el.hasChildNodes()) {
        widgetId = w.turnstile.render(el, {
          sitekey,
          callback: (t: string) => setTsToken(t),
          'expired-callback': () => setTsToken(''),
          'error-callback': () => setTsToken(''),
        });
      }
    };
    let poll: any;
    if (w.turnstile) {
      render();
    } else if (!document.getElementById('cf-ts-script')) {
      const s = document.createElement('script');
      s.id = 'cf-ts-script';
      s.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
      s.async = true; s.defer = true;
      s.onload = render;
      document.head.appendChild(s);
    } else {
      poll = setInterval(() => { if (w.turnstile) { clearInterval(poll); render(); } }, 200);
    }
    return () => {
      if (poll) clearInterval(poll);
      if (widgetId && w.turnstile) { try { w.turnstile.remove(widgetId); } catch (_e) {} }
    };
  }, [tab, sitekey, sent]);

  const startSso = async () => {
    setErr('');
    try {
      const body: any = { email };
      if (sitekey) body.turnstile_token = tsToken;
      const r = await api<any>('/auth/sso/start', { method: 'POST', body });
      setSent(true);
      if (r && r.dev_code) setDevCode(r.dev_code);
    } catch (e: any) { setErr(e.message); }
  };
  const verifySso = async () => {
    setErr('');
    try { await api('/auth/sso/code', { method: 'POST', body: { email, code } }); onAuth(); }
    catch (e: any) { setErr(e.message); }
  };

  const label = (p: string) => (p === 'local' ? 'Password' : p === 'sso' ? 'Email code' : p);

  return (
    <div class="login card">
      <h2>SovereignGateway admin</h2>
      {providers.length > 1 && (
        <div class="row" style="margin-bottom:12px">
          {providers.map((p) => (
            <button class={'ghost' + (tab === p ? ' active' : '')} onClick={() => { setTab(p); setErr(''); }}>{label(p)}</button>
          ))}
        </div>
      )}

      {tab === 'local' && (
        <Fragment>
          <p class="mut">Sign in with your account. First run defaults to <span class="mono">admin / admin</span>.</p>
          <div class="grid" style="margin-bottom:10px">
            <input placeholder="username" value={username} onInput={(e: any) => setUsername(e.target.value)}
              onKeyDown={(e: any) => e.key === 'Enter' && goLocal()} />
            <input type="password" placeholder="password" value={password} onInput={(e: any) => setPassword(e.target.value)}
              onKeyDown={(e: any) => e.key === 'Enter' && goLocal()} />
          </div>
          <button class="btn" onClick={goLocal}>Sign in</button>
        </Fragment>
      )}

      {tab === 'sso' && (
        <Fragment>
          {!sent ? (
            <Fragment>
              <p class="mut">Sign in with your email — we'll send you a 6-digit code.</p>
              <div class="grid" style="margin-bottom:10px">
                <input placeholder="email" value={email} onInput={(e: any) => setEmail(e.target.value)}
                  onKeyDown={(e: any) => { if (e.key === 'Enter' && !(sitekey && !tsToken)) startSso(); }} />
              </div>
              {sitekey && <div id="cf-ts" style="margin-bottom:10px"></div>}
              <button class="btn" onClick={startSso} disabled={!!sitekey && !tsToken}>Send me a code</button>
            </Fragment>
          ) : (
            <Fragment>
              <p class="mut">Enter the code sent to <span class="mono">{email}</span>, or open the emailed link.</p>
              {devCode && <p class="mut">dev code: <span class="mono">{devCode}</span></p>}
              <div class="grid" style="margin-bottom:10px">
                <input placeholder="6-digit code" value={code} autocomplete="one-time-code" inputmode="numeric"
                  onInput={(e: any) => setCode(e.target.value)} onKeyDown={(e: any) => e.key === 'Enter' && verifySso()} />
              </div>
              <div class="row">
                <button class="btn" onClick={verifySso}>Sign in</button>
                <button class="ghost" onClick={() => { setSent(false); setCode(''); setDevCode(''); }}>use a different email</button>
              </div>
            </Fragment>
          )}
        </Fragment>
      )}

      {err && <p class="err">{err}</p>}
    </div>
  );
}

/** One suggestion from `GET /complete` — `value` is stored, `label` is shown. */
type Sug = { value: string; label: string; hint: string };

/**
 * A list of values edited as removable pills, completed by the backend.
 *
 * `kind` names the vocabulary the server completes (`model`, `provider`,
 * `user`). Values are stored verbatim, so for `user` a pill holds an id and
 * `labelFor` supplies the username to display. `strict` refuses anything the
 * server did not suggest — right for ids, wrong for access policies, where
 * naming a model that isn't deployed yet is a legitimate thing to do.
 */
function TokenInput({ kind, value, onChange, placeholder, labelFor, strict }: {
  kind: string; value: string[]; onChange: (v: string[]) => void;
  placeholder?: string; labelFor?: (v: string) => string; strict?: boolean;
}) {
  const [q, setQ] = useState('');
  const [sug, setSug] = useState<Sug[]>([]);
  const [open, setOpen] = useState(false);
  const [hi, setHi] = useState(0);

  // Debounced, so a fast typist issues one request rather than one per
  // keystroke; `dead` drops a slow reply that a newer query already superseded.
  useEffect(() => {
    if (!open) { setSug([]); return; }
    let dead = false;
    const t = setTimeout(() => {
      api<Sug[]>('/complete?kind=' + kind + '&q=' + encodeURIComponent(q.trim()))
        .then((r) => { if (!dead) { setSug((r || []).filter((s) => !value.includes(s.value))); setHi(0); } })
        .catch(() => { if (!dead) setSug([]); });
    }, 120);
    return () => { dead = true; clearTimeout(t); };
  }, [kind, q, open, value.join(' ')]);

  const add = (v: string) => { if (v && !value.includes(v)) onChange([...value, v]); setQ(''); };
  const rm = (v: string) => onChange(value.filter((x) => x !== v));
  const onKey = (e: any) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      if (sug[hi]) add(sug[hi].value);
      else if (!strict) add(q.trim());
    } else if (e.key === 'ArrowDown') { e.preventDefault(); setHi((h) => Math.min(h + 1, sug.length - 1)); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setHi((h) => Math.max(h - 1, 0)); }
    else if (e.key === 'Escape') { setOpen(false); }
    // Backspace on an empty box deletes the last pill, as in every tag editor.
    else if (e.key === 'Backspace' && !q && value.length) { rm(value[value.length - 1]); }
  };

  return (
    <div class="ac-wrap">
      <div class="tok" onClick={(e: any) => { const i = e.currentTarget.querySelector('input'); if (i) i.focus(); }}>
        {value.map((v) => (
          <span key={v} class="pill">{labelFor ? labelFor(v) : v}
            <button type="button" title="remove" onClick={(e: any) => { e.stopPropagation(); rm(v); }}>&times;</button>
          </span>
        ))}
        <input value={q} placeholder={placeholder || 'type to search'}
               onInput={(e: any) => { setQ(e.target.value); setOpen(true); }}
               onFocus={() => setOpen(true)} onBlur={() => setOpen(false)} onKeyDown={onKey} />
      </div>
      {open && (sug.length > 0 || q.trim()) && (
        <div class="ac">
          {sug.map((s, i) => (
            <div key={s.value} class={'opt' + (i === hi ? ' on' : '')} onMouseEnter={() => setHi(i)}
                 onMouseDown={(e: any) => { e.preventDefault(); add(s.value); }}>
              <span>{s.label}</span>{s.hint && <span class="mut">{s.hint}</span>}
            </div>
          ))}
          {!sug.length && <div class="none">{strict ? 'no match' : 'no match — press Enter to add anyway'}</div>}
        </div>
      )}
    </div>
  );
}

/** Edit an AccessPolicy as four pill lists with backend-completed typeahead. */
function AccessEditor({ value, onSave }: { value: any; onSave: (p: any) => void }) {
  const [p, setP] = useState<any>({
    allowed_model_ids: value.allowed_model_ids || [],
    denied_model_ids: value.denied_model_ids || [],
    allowed_provider_ids: value.allowed_provider_ids || [],
    denied_provider_ids: value.denied_provider_ids || [],
  });
  // Models are stored as ids, so the pills need a name to show. A model the
  // list no longer has renders as an explicit "unknown" rather than as a
  // plausible-looking name — a dangling reference should be visible, which is
  // the whole reason policies hold ids instead of names.
  const [{ data: models }] = useAsync<any[]>(() => api('/models'));
  const [{ data: provs }] = useAsync<any[]>(() => api('/providers'));
  const nameOf = (id: string) => (models || []).find((m) => m.id === id)?.name
    || 'unknown model (' + id.slice(0, 8) + '…)';
  const provNameOf = (id: string) => (provs || []).find((p) => p.id === id)?.name
    || 'unknown provider (' + id.slice(0, 8) + '…)';
  const field = (k: string, kind: string, label: string, note: string) => (
    <div class="fld">
      <span class="lbl">{label} — {note}</span>
      <TokenInput kind={kind} value={p[k]} placeholder={'add a ' + kind}
                  strict
                  labelFor={kind === 'model' ? nameOf : provNameOf}
                  onChange={(v) => setP((s: any) => ({ ...s, [k]: v }))} />
    </div>
  );
  return (
    <div style="margin-top:6px">
      <div class="grid2">
        {field('allowed_model_ids', 'model', 'allowed models', 'empty means every model')}
        {field('denied_model_ids', 'model', 'denied models', 'always wins')}
        {field('allowed_provider_ids', 'provider', 'allowed providers', 'empty means every provider')}
        {field('denied_provider_ids', 'provider', 'denied providers', 'always wins')}
      </div>
      <button class="btn" style="margin-top:10px" onClick={() => onSave(p)}>Save access</button>
    </div>
  );
}

/** A simple modal overlay. */
function Modal({ title, onClose, children }: { title: string; onClose: () => void; children: any }) {
  return (
    <div class="modal-bg" onClick={onClose}>
      <div class="modal" onClick={(e: any) => e.stopPropagation()}>
        <button class="modal-x" onClick={onClose}>×</button>
        <h2>{title}</h2>
        {children}
      </div>
    </div>
  );
}

/** Set $ caps (per period or total) for one subject — used on user/team detail
 *  pages. The subject (type + id) is fixed by context, not typed in. */
function BudgetEditor({ subjectType, subjectId }: { subjectType: string; subjectId: string }) {
  const [{ data, error }, reload] = useAsync<any[]>(
    () => api(`/budgets?subject_type=${subjectType}&subject_id=${encodeURIComponent(subjectId)}`), [subjectId]);
  const [dollars, setDollars] = useState('');
  const [period, setPeriod] = useState('month');
  const create = async () => {
    await api('/budgets', { method: 'PUT', body: {
      id: uuid(), subject_type: subjectType, subject_id: subjectId, period,
      hard_limit_micros: Math.round(parseFloat(dollars || '0') * 1e6),
      soft_limit_micros: null, action: 'block', enabled: true,
      created_at: nowIso(), updated_at: nowIso(), deleted_at: null,
    }});
    setDollars(''); reload();
  };
  const del = async (id: string) => { await api('/budgets/' + id, { method: 'DELETE' }); reload(); };
  return (
    <Fragment>
      <h3 style="margin:14px 0 6px;font-size:14px">Budgets <span class="mut">— $ caps, per period or total (429 on breach)</span></h3>
      {error && <p class="err">{error}</p>}
      {(data && data.length) ? (
        <table><thead><tr><th>period</th><th>cap</th><th>action</th><th></th></tr></thead>
          <tbody>{data.map((b) => (
            <tr key={b.id}><td>{b.period}</td><td class="mono">{usd(b.hard_limit_micros)}</td><td>{b.action}</td>
              <td><button class="ghost del" onClick={() => del(b.id)}>delete</button></td></tr>
          ))}</tbody></table>
      ) : <p class="empty">No budget set.</p>}
      <div class="row" style="margin-top:8px">
        <input placeholder="cap in USD (e.g. 50)" value={dollars} onInput={(e: any) => setDollars(e.target.value)} />
        <select value={period} onChange={(e: any) => setPeriod(e.target.value)}>{PERIODS.map((p) => <option>{p}</option>)}</select>
        <button class="btn" onClick={create}>Set budget</button>
      </div>
    </Fragment>
  );
}

/**
 * A model's canonical name, renamed in place.
 *
 * The pencil lives on the model group header, not on a deployment row: a rename
 * is a property of the model, so N deployments of one model still offer exactly
 * one. The server leaves the old name behind as an alias, so a success reloads
 * the alias list too — the old name reappearing as a pill is the visible proof
 * that clients still sending it keep resolving.
 *
 * Enter commits, Escape cancels. Deliberately *not* commit-on-blur: clicking
 * anywhere on the page should never rename a model, and pairing commit-on-blur
 * with a visible cancel button is the classic trap where clicking cancel blurs
 * first and commits.
 */
function ModelName({ model, admin, onRenamed }: { model: any; admin: boolean; onRenamed: () => void }) {
  const [editing, setEditing] = useState(false);
  const [v, setV] = useState(model.name);
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);

  const open = () => { setV(model.name); setErr(''); setEditing(true); };
  const cancel = () => { setEditing(false); setErr(''); };
  const save = async () => {
    const name = v.trim();
    if (!name || name === model.name) { cancel(); return; }
    setBusy(true); setErr('');
    try {
      await api('/models/' + encodeURIComponent(model.id) + '/name', { method: 'PUT', body: { name } });
      setEditing(false);
      onRenamed();
    } catch (e: any) {
      // Stay open on failure so a "that name is taken" is fixable in place.
      setErr(e.message);
    } finally { setBusy(false); }
  };

  if (!editing) {
    return (
      <span class="mono">{model.name}
        {admin && <a class="pencil" title="Rename this model" onClick={open}>✎</a>}
      </span>
    );
  }
  return (
    <span class="inline-edit">
      <input class="mono" autofocus value={v} disabled={busy}
             onInput={(e: any) => setV(e.target.value)}
             onKeyDown={(e: any) => {
               if (e.key === 'Enter') { e.preventDefault(); save(); }
               else if (e.key === 'Escape') { e.preventDefault(); cancel(); }
             }} />
      <a class="ok" title="Save" onClick={save}>✓</a>
      <a class="no" title="Cancel" onClick={cancel}>✕</a>
      {err ? <span class="err hint">{err}</span>
           : <span class="mut hint">Enter to save · Esc to cancel</span>}
    </span>
  );
}

/**
 * Providers: one upstream endpoint, its credential, and the deployments served
 * through it.
 *
 * The credential is write-only by design — the API returns `has_api_key` and
 * never the key, so an edit that leaves the field blank keeps the stored one
 * rather than blanking it. The placeholder says which of those is happening.
 */
function Providers({ admin }: { admin: boolean }) {
  const [{ data, error }, reload] = useAsync<any[]>(() => api('/providers'));
  const blank = { name: '', api_base: '', api_key: '', extra: { cloudflare_access: false } };
  const [f, setF] = useState<any>(blank);
  const [editing, setEditing] = useState<string>('');
  const [msg, setMsg] = useState('');
  const [open, setOpen] = useState(false);

  const edit = (p: any) => {
    // api_key is intentionally blank: it is never sent to the browser.
    setF({ name: p.name, api_base: p.api_base || '', api_key: '', extra: p.extra || {} });
    setEditing(p.id); setMsg(''); setOpen(true);
  };
  const add = () => { setF(blank); setEditing(''); setMsg(''); setOpen(true); };
  const save = async () => {
    setMsg('');
    const body: any = { name: f.name.trim(), extra: f.extra };
    body.api_base = f.api_base.trim() || null;
    if (f.api_key.trim()) body.api_key = f.api_key.trim();
    try {
      if (editing) await api('/providers/' + encodeURIComponent(editing), { method: 'PUT', body });
      else await api('/providers', { method: 'POST', body });
      setOpen(false); reload();
    } catch (e: any) { setMsg(e.message); }
  };
  const del = async (p: any) => {
    if (!confirm('Delete provider “' + p.name + '”?')) return;
    try { await api('/providers/' + encodeURIComponent(p.id), { method: 'DELETE' }); reload(); }
    catch (e: any) { alert(e.message); }
  };

  return (
    <Fragment>
      <div class="card">
        <div class="row"><h2 style="margin:0">Providers <span class="mut">— an endpoint, its credentials, and the models it serves</span></h2>
          <span class="sp" style="flex:1"></span>
          {admin && <button class="btn" onClick={add}>+ Add provider</button>}</div>
        {error && <p class="err" style="margin-top:10px">{error}</p>}
        {!data || !data.length
          ? <p class="empty">No providers yet. {admin ? 'Add one, then give it deployments.' : 'Ask an admin.'}</p>
          : (
            <div class="tablewrap">
              <table style="margin-top:10px">
                <thead><tr><th>name</th><th>api_base</th><th>credential</th><th>edge</th><th>deployments</th>{admin && <th></th>}</tr></thead>
                <tbody>{data.map((p) => (
                  <tr key={p.id}>
                    <td class="nowrap">{p.name}</td>
                    <td class="mono mut">{p.api_base || <span class="mut">format default</span>}</td>
                    <td>{p.has_api_key
                          ? <span class="pill">key set</span>
                          : <span class="mut">none</span>}</td>
                    <td>
                      <div class="pills">
                        {p.extra?.cloudflare_access
                          && <span class="pill" title="Sends the configured Cloudflare Access service token">CF Access</span>}
                        {Object.keys(p.extra?.headers || {}).length > 0
                          && <span class="pill mono" title={Object.keys(p.extra.headers).join(', ')}>
                               +{Object.keys(p.extra.headers).length} hdr</span>}
                        {!p.extra?.cloudflare_access && !Object.keys(p.extra?.headers || {}).length
                          && <span class="mut">—</span>}
                      </div>
                    </td>
                    <td class="mut">{p.deployment_count}</td>
                    {admin && <td class="nowrap">
                      <button class="ghost" onClick={() => edit(p)}>edit</button>{' '}
                      <button class="ghost del" onClick={() => del(p)}>delete</button>
                    </td>}
                  </tr>
                ))}</tbody>
              </table>
            </div>
          )}
      </div>
      {admin && open && (
        <Modal title={editing ? 'Edit provider' : 'Add a provider'} onClose={() => setOpen(false)}>
          <div class="grid">
            <input placeholder="name (e.g. openai)" value={f.name}
                   onInput={(e: any) => setF((s: any) => ({ ...s, name: e.target.value }))} />
            <input placeholder="api_base (blank = format default)" value={f.api_base}
                   onInput={(e: any) => setF((s: any) => ({ ...s, api_base: e.target.value }))} />
            <input type="password" value={f.api_key}
                   placeholder={editing ? 'api_key (blank = keep current)' : 'api_key'}
                   onInput={(e: any) => setF((s: any) => ({ ...s, api_key: e.target.value }))} />
          </div>
          <label class="row" style="margin-top:10px;gap:8px;cursor:pointer">
            <input type="checkbox" checked={!!f.extra.cloudflare_access}
                   onChange={(e: any) => setF((s: any) => ({ ...s, extra: { ...s.extra, cloudflare_access: e.target.checked } }))} />
            <span>Behind Cloudflare Access
              <span class="mut"> — send the service token from <span class="mono">[upstream.cloudflare_access]</span></span></span>
          </label>
          <div class="row" style="margin-top:12px">
            <button class="btn" onClick={save}>{editing ? 'Save provider' : 'Add provider'}</button>
            {msg && <span class="err">{msg}</span>}
          </div>
        </Modal>
      )}
    </Fragment>
  );
}

function Models({ admin }: { admin: boolean }) {
  // Two lists: the model entities (what a rename acts on) and the deployments
  // (the upstream fan-out). The table groups the second under the first.
  const [{ loading, data, error }, reload] = useAsync<any[]>(() => api('/deployments'));
  const [{ data: modelData }, reloadModels] = useAsync<any[]>(() => api('/models'));
  // api_base / api_key / extra are the provider's now, so the deployment form
  // is just: which model, through which provider, speaking which format.
  const blank = { model_name: '', provider: '', upstream_model: '', upstream_format: 'openai_chat' };
  const [{ data: providerData }] = useAsync<any[]>(() => api('/providers'));
  const [f, setF] = useState<any>(blank);
  const [msg, setMsg] = useState('');
  const upd = (k: string, v: string) => setF((s: any) => ({ ...s, [k]: v }));
  const add = async () => {
    setMsg('');
    try {
      await api('/deployments', { method: 'POST', body: { ...f } });
      setF(blank); setShowAdd(false); reload(); reloadModels();
    } catch (e: any) { setMsg(e.message); }
  };
  const [showAdd, setShowAdd] = useState(false);
  const del = async (id: string) => { if (confirm('Delete this deployment?')) { await api('/deployments/' + id, { method: 'DELETE' }); reload(); reloadModels(); } };
  const [{ data: aliasData }, reloadAliases] = useAsync<any[]>(() => api('/aliases'));
  const aliasesFor = (modelId: string) => (aliasData || []).filter((a) => a.model_id === modelId);
  const addAlias = async (target: string) => {
    const a = prompt('New alias for ' + target + ':');
    if (!a) return;
    try { await api('/aliases', { method: 'POST', body: { alias: a.trim(), target } }); reloadAliases(); }
    catch (e: any) { alert(e.message); }
  };
  // A rename leaves the old name behind as an alias, so both lists move.
  const afterRename = () => { reloadModels(); reloadAliases(); reload(); };
  const deploymentsFor = (modelId: string) => (data || []).filter((d) => d.model_id === modelId);
  const delAlias = async (a: string) => { if (confirm('Remove alias “' + a + '”?')) { await api('/aliases/' + encodeURIComponent(a), { method: 'DELETE' }); reloadAliases(); } };
  return (
    <Fragment>
      <Providers admin={admin} />
      <div class="card">
        <div class="row"><h2 style="margin:0">Models <span class="mut">— each public name, with the deployments behind it</span></h2>
          <span class="sp" style="flex:1"></span>
          {admin && <button class="btn" onClick={() => { setMsg(''); setShowAdd(true); }}>+ Add deployment</button>}</div>
        {error && <p class="err" style="margin-top:10px">{error}</p>}
        {loading ? <p class="empty">Loading…</p> : !modelData || !modelData.length
          ? <p class="empty">No models. {admin ? 'Click “Add deployment” or run ' : 'Ask an admin, or run '}<span class="mono">gateway import</span>.</p>
          : (
            <div class="tablewrap">
              <table style="margin-top:10px">
                <thead><tr><th>provider</th><th>upstream_model</th><th>format</th><th>api_base</th>{admin && <th></th>}</tr></thead>
                {modelData.map((model) => (
                  <tbody key={model.id}>
                    <tr class="grp">
                      <td colSpan={admin ? 5 : 4}>
                        <div class="pills">
                          <ModelName model={model} admin={admin} onRenamed={afterRename} />
                          {aliasesFor(model.id).map((a) => (
                            <span key={a.alias} class="pill mono">{a.alias}{admin && <a class="x" title="Remove alias" onClick={() => delAlias(a.alias)}>×</a>}</span>
                          ))}
                          {admin && <a onClick={() => addAlias(model.name)} style="cursor:pointer" class="mut">+ alias</a>}
                        </div>
                      </td>
                    </tr>
                    {deploymentsFor(model.id).map((m) => (
                      <tr key={m.id}>
                        <td class="nowrap">{m.provider}</td>
                        <td class="mono nowrap">{m.upstream_model}</td>
                        <td><span class="pill">{m.upstream_format}</span></td>
                        <td class="mono mut">{m.api_base || <span class="mut">format default</span>}</td>
                        {admin && <td><button class="ghost del" onClick={() => del(m.id)}>delete</button></td>}
                      </tr>
                    ))}
                    {!deploymentsFor(model.id).length && (
                      <tr><td colSpan={admin ? 5 : 4} class="mut" style="padding-left:18px">
                        no deployments — this model is not routable
                      </td></tr>
                    )}
                  </tbody>
                ))}
              </table>
            </div>
          )}
      </div>
      {admin && showAdd && (
        <Modal title="Add a deployment" onClose={() => setShowAdd(false)}>
          <div class="grid">
            <input placeholder="model_name (public)" value={f.model_name} onInput={(e: any) => upd('model_name', e.target.value)} />
            <select value={f.provider} onChange={(e: any) => upd('provider', e.target.value)}>
              <option value="">— provider —</option>
              {(providerData || []).map((p) => <option value={p.name}>{p.name}</option>)}
            </select>
            <input placeholder="upstream_model" value={f.upstream_model} onInput={(e: any) => upd('upstream_model', e.target.value)} />
            <select value={f.upstream_format} onChange={(e: any) => upd('upstream_format', e.target.value)}>{FORMATS.map((k) => <option>{k}</option>)}</select>
          </div>
          <p class="mut" style="margin:10px 0 0;font-size:12px">
            The endpoint, credential and edge settings come from the provider —
            add or edit those in the Providers card above. One endpoint can serve
            several formats, which is why the format is set here.
          </p>
          <div class="row" style="margin-top:12px"><button class="btn" onClick={add}>Add deployment</button>{msg && <span class="err">{msg}</span>}</div>
        </Modal>
      )}
    </Fragment>
  );
}

function Users({ me }: { me: Me }) {
  const [{ data, error }, reload] = useAsync<any[]>(() => api('/users'));
  const [f, setF] = useState({ username: '', password: '', role: 'member' });
  const [inv, setInv] = useState({ email: '', role: 'member' });
  const [msg, setMsg] = useState('');
  // When local password login is disabled, a password account can never sign in
  // — so "add user" becomes an invite that provisions them in the IdP.
  const [localEnabled, setLocalEnabled] = useState(true);
  useEffect(() => {
    api<{ providers: string[] }>('/auth/config')
      .then((c) => setLocalEnabled((c.providers || ['local']).includes('local')))
      .catch(() => {});
  }, []);
  const add = async () => {
    setMsg('');
    try { await api('/users', { method: 'POST', body: f }); setF({ username: '', password: '', role: 'member' }); reload(); }
    catch (e: any) { setMsg(e.message); }
  };
  const invite = async () => {
    setMsg('');
    try { await api('/users/invite', { method: 'POST', body: inv }); setInv({ email: '', role: 'member' }); reload(); }
    catch (e: any) { setMsg(e.message); }
  };
  return (
    <div class="card">
      <h2>Users <span class="mut">— login accounts. Click one to set budgets.</span></h2>
      {error && <p class="err">{error}</p>}
      <table><thead><tr><th>username</th><th>role</th><th>last login</th></tr></thead>
        <tbody>{(data || []).map((u) => (
          <tr key={u.id} class="link" onClick={() => route('/users/' + u.id)}>
            <td class="mono">{u.username}{u.username === me.username && <span class="mut"> (you)</span>}</td>
            <td><span class={u.role === 'admin' ? 'pill admin' : 'pill'}>{u.role}</span></td>
            <td class="mut">{u.last_login_at ? String(u.last_login_at).slice(0, 19).replace('T', ' ') : '—'}</td>
          </tr>
        ))}</tbody></table>
      {localEnabled ? (
        <div class="row" style="margin-top:12px">
          <input placeholder="username" value={f.username} onInput={(e: any) => setF((s) => ({ ...s, username: e.target.value }))} />
          <input type="password" placeholder="password" value={f.password} onInput={(e: any) => setF((s) => ({ ...s, password: e.target.value }))} />
          <select value={f.role} onChange={(e: any) => setF((s) => ({ ...s, role: e.target.value }))}><option value="admin">admin</option><option value="member">member</option></select>
          <button class="btn" onClick={add}>Add user</button>{msg && <span class="err">{msg}</span>}
        </div>
      ) : (
        <Fragment>
          <p class="mut" style="margin-top:12px">Invite by email — they sign in via SSO; no password needed.</p>
          <div class="row">
            <input placeholder="email" value={inv.email} onInput={(e: any) => setInv((s) => ({ ...s, email: e.target.value }))}
              onKeyDown={(e: any) => e.key === 'Enter' && invite()} />
            <select value={inv.role} onChange={(e: any) => setInv((s) => ({ ...s, role: e.target.value }))}><option value="admin">admin</option><option value="member">member</option></select>
            <button class="btn" onClick={invite}>Invite user</button>{msg && <span class="err">{msg}</span>}
          </div>
        </Fragment>
      )}
    </div>
  );
}

/** `/users/:id` — a user's detail page: role, password, and their budgets. */
function UserDetail({ id, me }: { id: string; me: Me }) {
  const [{ data }, reload] = useAsync<any[]>(() => api('/users'), [id]);
  const u = (data || []).find((x) => x.id === id);
  const setRole = async (role: string) => { try { await api('/users/' + id + '/role', { method: 'PUT', body: { role } }); reload(); } catch (e: any) { alert(e.message); } };
  const reset = async () => { const p = prompt('New password:'); if (p) { await api('/users/' + id + '/password', { method: 'PUT', body: { password: p } }); alert('password reset'); } };
  const del = async () => { if (confirm('Delete this user?')) { try { await api('/users/' + id, { method: 'DELETE' }); route('/users'); } catch (e: any) { alert(e.message); } } };
  return (
    <div class="card">
      <a class="link back" onClick={() => route('/users')}>← Users</a>
      <h2>User <span class="mono">{u ? u.username : id}</span>{u && u.username === me.username && <span class="mut"> (you)</span>}</h2>
      {u && <div class="row" style="margin-bottom:10px">
        <span class="mut">role</span>
        <select value={u.role} onChange={(e: any) => setRole(e.target.value)}><option value="admin">admin</option><option value="member">member</option></select>
        <button class="ghost" onClick={reset}>reset password</button>
        <button class="ghost del" onClick={del}>delete user</button>
      </div>}
      <BudgetEditor subjectType="user" subjectId={id} />
    </div>
  );
}

function TeamMembers({ teamId, users }: { teamId: string; users: any[] }) {
  const [{ data }, reload] = useAsync<any[]>(() => api('/teams/' + teamId + '/members'), [teamId]);
  const name = (id: string) => (users.find((u) => u.id === id) || {}).username || id;
  const current = (data || []).map((m: any) => m.user_id);
  // The pill list is the desired membership; diffing it against the current
  // rows lets adding a pill and removing one both flow through a single path.
  const sync = async (next: string[]) => {
    for (const id of next.filter((x) => !current.includes(x))) {
      await api('/teams/' + teamId + '/members', { method: 'POST', body: { user_id: id } });
    }
    for (const id of current.filter((x) => !next.includes(x))) {
      await api('/teams/' + teamId + '/members/' + id, { method: 'DELETE' });
    }
    reload();
  };
  return (
    <Fragment>
      <h3 style="margin:14px 0 4px;font-size:14px">Members <span class="mut">(saved as you edit)</span></h3>
      {/* strict: a pill holds a user id, so a hand-typed name would be meaningless. */}
      <TokenInput kind="user" strict value={current} labelFor={name}
                  onChange={sync} placeholder="add a member" />
    </Fragment>
  );
}

function Teams() {
  const [{ data, error }, reload] = useAsync<any[]>(() => api('/teams'));
  const [name, setName] = useState('');
  const create = async () => { await api('/teams', { method: 'POST', body: { name } }); setName(''); reload(); };
  return (
    <div class="card">
      <h2>Teams <span class="mut">— click a team to set access, members, and budgets</span></h2>
      {error && <p class="err">{error}</p>}
      {(data && data.length) ? (
        <table><thead><tr><th>name</th><th>access</th><th>id</th></tr></thead>
          <tbody>{data.map((t) => (
            <tr key={t.id} class="link" onClick={() => route('/teams/' + t.id)}>
              <td class="mono">{t.name}</td>
              <td class="mut">{isUnrestricted(t.access) ? 'unrestricted' : 'restricted'}</td>
              <td class="mut mono">{t.id}</td>
            </tr>
          ))}</tbody></table>
      ) : <p class="empty">No teams yet.</p>}
      <div class="row" style="margin-top:12px"><input placeholder="team name" value={name} onInput={(e: any) => setName(e.target.value)} /><button class="btn" onClick={create}>Create team</button></div>
    </div>
  );
}

/** `/teams/:id` — team detail: access policy, members, and budgets. */
function TeamDetail({ id }: { id: string }) {
  const [{ data }, reload] = useAsync<any[]>(() => api('/teams'), [id]);
  const [users] = useAsync<any[]>(() => api('/users'));
  const t = (data || []).find((x) => x.id === id);
  const saveAccess = async (access: any) => { await api('/teams/' + id + '/access', { method: 'PUT', body: { access } }); alert('team access saved'); reload(); };
  const del = async () => { if (confirm('Delete team?')) { await api('/teams/' + id, { method: 'DELETE' }); route('/teams'); } };
  return (
    <div class="card">
      <a class="link back" onClick={() => route('/teams')}>← Teams</a>
      <div class="row"><h2 style="margin:0">Team <span class="mono">{t ? t.name : id}</span></h2><span class="sp" style="flex:1"></span>
        <button class="ghost del" onClick={del}>delete team</button></div>
      <h3 style="margin:14px 0 4px;font-size:14px">Model access <span class="mut">(deny wins; allow-list = ceiling)</span></h3>
      {t && <AccessEditor key={id} value={t.access || {}} onSave={saveAccess} />}
      <TeamMembers teamId={id} users={users.data || []} />
      <BudgetEditor subjectType="team" subjectId={id} />
    </div>
  );
}

function Keys({ admin }: { admin: boolean }) {
  const [{ data, error }, reload] = useAsync<any[]>(() => api('/keys'));
  const [teams] = useAsync<any[]>(() => api('/teams').catch(() => []));
  const [users] = useAsync<any[]>(() => (admin ? api('/users') : Promise.resolve([])));
  const [f, setF] = useState<any>({ name: '', team_id: '', owner_user_id: '', scopes: ['inference'] });
  const [issued, setIssued] = useState<string | null>(null);
  const [editing, setEditing] = useState<string>('');
  const teamName = (id: string) => ((teams.data || []).find((t) => t.id === id) || {}).name || 'team';
  const userName = (id: string) => ((users.data || []).find((u) => u.id === id) || {}).username || id;
  const toggleScope = (sc: string) => setF((s: any) => {
    const has = s.scopes.includes(sc);
    const scopes = has ? s.scopes.filter((x: string) => x !== sc) : [...s.scopes, sc];
    return { ...s, scopes };
  });
  const create = async () => {
    const body: any = { name: f.name };
    // Scope grant set (JSON array); omit when it's just the default.
    if (!(f.scopes.length === 1 && f.scopes[0] === 'inference')) body.scopes = f.scopes;
    if (f.team_id) body.team_id = f.team_id;
    if (admin && f.owner_user_id) body.owner_user_id = f.owner_user_id;
    const r = await api<any>('/keys', { method: 'POST', body });
    setIssued(r.token); setF({ name: '', team_id: '', owner_user_id: '', scopes: ['inference'] }); reload();
  };
  const del = async (id: string) => { if (confirm('Revoke this key?')) { await api('/keys/' + id, { method: 'DELETE' }); reload(); } };
  const saveAccess = async (id: string, access: any) => { await api('/keys/' + id + '/access', { method: 'PUT', body: { access } }); setEditing(''); reload(); };
  return (
    <div class="card">
      <h2>{admin ? 'API keys' : 'My API keys'} <span class="mut">— {admin ? 'all keys across users' : 'create and revoke your own keys'}</span></h2>
      <div class="row" style="margin:12px 0">
        <input placeholder="key name" value={f.name} onInput={(e: any) => setF((s: any) => ({ ...s, name: e.target.value }))} />
        <select value={f.team_id} onChange={(e: any) => setF((s: any) => ({ ...s, team_id: e.target.value }))}><option value="">no team</option>{(teams.data || []).map((t) => <option value={t.id}>{t.name}</option>)}</select>
        {admin && <select value={f.owner_user_id} onChange={(e: any) => setF((s: any) => ({ ...s, owner_user_id: e.target.value }))}><option value="">owner: me</option>{(users.data || []).map((u) => <option value={u.id}>{u.username}</option>)}</select>}
        {admin && <label class="mut" style="display:inline-flex;align-items:center;gap:4px"><input type="checkbox" checked={f.scopes.includes('inference')} onChange={() => toggleScope('inference')} />inference</label>}
        {admin && <label class="mut" style="display:inline-flex;align-items:center;gap:4px"><input type="checkbox" checked={f.scopes.includes('admin')} onChange={() => toggleScope('admin')} />admin (API)</label>}
        <button class="btn" onClick={create}>Issue key</button>
      </div>
      {issued && <div style="margin-bottom:12px"><div class="mut">Copy now — shown once:</div><div class="token mono">{issued}</div></div>}
      {error && <p class="err">{error}</p>}
      <table><thead><tr><th>name</th><th>prefix</th><th>team</th>{admin && <th>owner</th>}<th>access</th><th></th></tr></thead>
        <tbody>{(data || []).map((k) => (
          <Fragment key={k.id}>
            <tr>
              <td>{k.name || '—'}{(k.scopes || []).includes('admin') && <span class="pill admin" style="margin-left:6px">admin</span>}</td><td class="mono">{k.key_prefix}…{k.key_suffix}</td>
              <td class="mut">{k.team_id ? teamName(k.team_id) : '—'}</td>
              {admin && <td class="mut">{userName(k.owner_user_id)}</td>}
              <td class="mut">{(() => {
                const l = accessLabel(k, (teams.data || []).find((t) => t.id === k.team_id));
                return <span title={l.title}>{l.text}</span>;
              })()}</td>
              <td class="row"><button class="ghost" onClick={() => setEditing(editing === k.id ? '' : k.id)}>access</button><button class="ghost del" onClick={() => del(k.id)}>revoke</button></td>
            </tr>
            {editing === k.id && <tr><td colSpan={admin ? 5 : 4}><AccessEditor key={k.id} value={k.access || {}} onSave={(p) => saveAccess(k.id, p)} /></td></tr>}
          </Fragment>
        ))}</tbody>
      </table>
      {(!data || !data.length) && <p class="empty">No keys yet.</p>}
    </div>
  );
}

function Budgets() {
  // Budgets are set contextually on user/team detail pages; this standalone
  // view is intentionally removed. (Kept as a no-op redirect target if linked.)
  useEffect(() => { route('/users', true); }, []);
  return null;
}

function Spend({ admin }: { admin: boolean }) {
  const [{ data, error }] = useAsync<any[]>(() => api('/spend'));
  // Members only see spend attributed to their own keys / user.
  const [mine] = useAsync<any[]>(() => (admin ? Promise.resolve([]) : api('/keys').catch(() => [])), [admin]);
  let rows = data || [];
  if (!admin) {
    const keyIds = new Set((mine.data || []).map((k) => k.id));
    const userIds = new Set((mine.data || []).map((k) => k.owner_user_id));
    rows = rows.filter((r) => (r.subject_type === 'key' && keyIds.has(r.subject_id)) || (r.subject_type === 'user' && userIds.has(r.subject_id)));
  }
  return (
    <div class="card">
      <h2>{admin ? 'Spend' : 'My spend'} <span class="mut">— rollups by subject (key / user / team)</span></h2>
      {error && <p class="err">{error}</p>}
      <table style="margin-top:10px"><thead><tr><th>subject</th><th>id</th><th>period</th><th>spend</th><th>requests</th><th>in/out tokens</th></tr></thead>
        <tbody>{rows.map((r, i) => (
          <tr key={i}><td><span class="pill">{r.subject_type}</span></td><td class="mono mut">{r.subject_id}</td><td>{r.period}</td>
            <td class="mono">{usd(r.spend_micros)}</td><td>{r.request_count}</td><td class="mut">{r.input_tokens}/{r.output_tokens}</td></tr>
        ))}</tbody></table>
      {!rows.length && <p class="empty">No spend recorded yet.</p>}
    </div>
  );
}

/** `/account` — self-service: change your own password (current + new). */
function Account({ me }: { me: Me }) {
  const [cur, setCur] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [msg, setMsg] = useState('');
  const [ok, setOk] = useState(false);
  const submit = async () => {
    setMsg(''); setOk(false);
    if (!next) { setMsg('new password must not be empty'); return; }
    if (next !== confirm) { setMsg('new passwords do not match'); return; }
    try {
      await api('/auth/password', { method: 'PUT', body: { current_password: cur, new_password: next } });
      setOk(true); setCur(''); setNext(''); setConfirm('');
    } catch (e: any) { setMsg(e.message); }
  };
  return (
    <div class="card" style="max-width:440px">
      <h2>Account <span class="mut">— {me.username}</span></h2>
      <div class="grid" style="margin-top:10px">
        <input type="password" placeholder="current password" value={cur} onInput={(e: any) => setCur(e.target.value)} />
        <input type="password" placeholder="new password" value={next} onInput={(e: any) => setNext(e.target.value)} />
        <input type="password" placeholder="confirm new password" value={confirm} onInput={(e: any) => setConfirm(e.target.value)} />
      </div>
      <div class="row" style="margin-top:12px"><button class="btn" onClick={submit}>Change password</button>
        {ok && <span class="mut">password changed</span>}{msg && <span class="err">{msg}</span>}</div>
    </div>
  );
}

/** Imperatively redirect (used for `/` and unmatched paths). */
function Redirect({ to }: { to: string; path?: string; default?: boolean }) {
  useEffect(() => { route(to, true); }, []);
  return null;
}

function NavLink({ href, label, current, set }: { href: string; label: string; current: string; set: (p: string) => void }) {
  const go = (e: any) => { e.preventDefault(); route(href); set(href); };
  return <a href={href} class={current === href ? 'on' : ''} onClick={go}>{label}</a>;
}

function App() {
  const [me, setMe] = useState<Me | null | undefined>(undefined);
  const [path, setPath] = useState(location.pathname);
  const loadMe = () => api<Me>('/auth/me').then(setMe).catch(() => setMe(null));
  useEffect(() => { loadMe(); }, []);
  useEffect(() => {
    const f = () => setPath(location.pathname);
    addEventListener('popstate', f);
    return () => removeEventListener('popstate', f);
  }, []);

  if (me === undefined) return <p class="empty" style="text-align:center;margin-top:14vh">Loading…</p>;
  if (me === null) return <Login onAuth={loadMe} />;

  const admin = me.role === 'admin';
  const logout = async () => { try { await api('/auth/logout', { method: 'POST' }); } catch {} setMe(null); };

  // Nav available to everyone; admin-only links gated below.
  const links: [string, string, boolean][] = [
    ['/models', 'Models', false],
    ['/keys', 'Keys', false],
    ['/teams', 'Teams', true],
    ['/users', 'Users', true],
    ['/spend', 'Spend', false],
  ];

  return (
    <Fragment>
      <header>
        <span class="logo">SovereignGateway</span><span class="mut">admin</span>
        <span class="sp"></span>
        <a href="/account" class="mut mono" onClick={(e: any) => { e.preventDefault(); route('/account'); setPath('/account'); }}>{me.username}</a>
        <span class={admin ? 'pill admin' : 'pill'}>{me.role}</span>
        <button class="ghost" onClick={logout}>sign out</button>
      </header>
      <main>
        <nav>{links.filter(([, , a]) => admin || !a).map(([href, label]) => <NavLink href={href} label={label} current={path} set={setPath} />)}</nav>
        <Router onChange={(e: any) => setPath(e.url)}>
          <Redirect path="/" to="/keys" />
          <Models path="/models" admin={admin} />
          <Keys path="/keys" admin={admin} />
          {admin && <Teams path="/teams" />}
          {admin && <TeamDetail path="/teams/:id" />}
          {admin && <Users path="/users" me={me} />}
          {admin && <UserDetail path="/users/:id" me={me} />}
          <Spend path="/spend" admin={admin} />
          <Account path="/account" me={me} />
          <Redirect default to="/keys" />
        </Router>
      </main>
    </Fragment>
  );
}

render(<App />, document.getElementById('app')!);
