#!/usr/bin/env python3
"""Differential check: is a request through the gateway what QE would have
seen and answered natively?

For every case of a corpus (Anthropic Messages, OpenAI Responses and Chat
requests: single turns, agent transcripts with tool calls and reasoning, every
effort level, budgets, structured output, stops, streaming and not, Responses
previous_response_id chains) the request is sent

  native  straight to QE, in its own shape
  relay   through the gateway to a provider that serves that shape (relayed)
  chat    through the gateway to a provider that serves only Chat, with the
          QE dialect (translated by yb_wire::qe)
  ir      as chat without the dialect (the cross-provider IR), for contrast

and compared on

  (a) QE's dump of what it prepared (prompt token ids, effort, enforced
      thinking budget, max tokens, sampling, stops, grammars, tools, tool
      choice, parallel calls, cache breakpoints, extras, kwargs): identical
      except `endpoint` and `history_from` (which only says where QE stores
      the conversation)
  (b) the client-visible answer: identical except ids, timestamps and SSE
      chunk boundaries (QE coalesces tokens into deltas by timing), plus the
      exclusions listed in EXCLUDED, each with its reason
  (c) for multi-turn cases the gateway's own answer is fed back as the next
      turn, which is then compared as in (a) and (b).

Run on the QE host after start-gateway.sh. Keys are read from files, never
printed. Results go to $WORK/results.json; exit status 1 on any mismatch in a
lossless path.
"""
import json, os, re, sys, time, urllib.request, urllib.error, copy

QE = os.environ.get("QE_URL", "http://127.0.0.1:27900")
GW = os.environ.get("GW_URL", "http://127.0.0.1:27910")
WORK = os.path.expanduser(os.environ.get("WORK", "~/qe-lossless-work"))
QE_KEY = open(os.path.expanduser(os.environ.get("QE_KEY", "~/qe-stub/key"))).read().strip()
GW_KEY = open(os.path.join(WORK, "gateway.key")).read().strip()
DUMP = os.path.expanduser(os.environ.get("QE_DUMP", "~/qe-stub/prepared.jsonl"))
M = os.environ.get("QE_MODEL", "DeepSeek-V4.1-Flash")
ONLY = os.environ.get("ONLY")  # substring filter on case names
# RECORD=<dir>: also write a cassette per translated single-turn case (the
# inbound body, the QE Chat body yb_wire::qe makes of it, QE's answer to that
# body, and QE's native answer), replayed offline by
# crates/yb-wire/tests/qe_cassettes.rs. Needs QE_TRANSLATE, the qe_translate
# example binary.
RECORD = os.environ.get("RECORD")
QE_TRANSLATE = os.environ.get("QE_TRANSLATE")

PATHS = {"anthropic": "/v1/messages", "responses": "/v1/responses", "chat": "/v1/chat/completions"}

# Fields of the dump that legitimately differ between QE's endpoints.
DUMP_EXCLUDED = {"endpoint", "history_from"}


def post(base, path, body, key, method="POST"):
    h = {"Content-Type": "application/json", "Authorization": "Bearer " + key, "x-api-key": key,
         "anthropic-version": "2023-06-01"}
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base + path, data, h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def dump_len():
    try:
        with open(DUMP) as f:
            return sum(1 for _ in f)
    except FileNotFoundError:
        return 0


def dumps_since(n0):
    with open(DUMP) as f:
        lines = f.read().splitlines()
    return [json.loads(l) for l in lines[n0:]]


def send(variant, shape, body, method="POST", path=None):
    """One request in `shape` by `variant`; returns (status, text, dump lines)."""
    b = copy.deepcopy(body) if body is not None else None
    if variant == "native":
        base, key = QE, QE_KEY
        if b is not None:
            b["model"] = M
    else:
        base, key = GW, GW_KEY
        if b is not None:
            b["model"] = variant
    n0 = dump_len()
    st, txt = post(base, path or PATHS[shape], b, key, method)
    time.sleep(0.05)
    return st, txt, dumps_since(n0)


ID_RE = re.compile(r'\b(chatcmpl-|resp_|msg_|rs_|fc_|ctc_|call_|toolu_|in_)[0-9a-zA-Z_-]+')
TS_RE = re.compile(r'"(created|created_at|completed_at)":\s*\d+')


def norm_ids(txt):
    return TS_RE.sub(r'"\1":0', ID_RE.sub(r'\1X', txt))


def sse_events(txt):
    out = []
    for block in txt.split("\n\n"):
        ev, data = None, []
        for l in block.splitlines():
            if l.startswith("event:"):
                ev = l[6:].strip()
            elif l.startswith("data:"):
                data.append(l[5:].lstrip())
        if data:
            d = "\n".join(data)
            out.append((ev, d if d == "[DONE]" else json.loads(d)))
    return out


DELTA_KEYS = {
    # anthropic content_block_delta delta types and their text field
    "text_delta": "text", "thinking_delta": "thinking", "input_json_delta": "partial_json",
}
RESP_DELTAS = {"response.output_text.delta": "delta", "response.reasoning_text.delta": "delta",
               "response.function_call_arguments.delta": "delta"}


def coalesce(events):
    """Merge consecutive deltas of one block/item: chunk boundaries are timing."""
    out = []
    for ev, d in events:
        if out and isinstance(d, dict):
            pev, pd = out[-1]
            if (d.get("type") == "content_block_delta" and pd.get("type") == "content_block_delta"
                    and d["index"] == pd["index"] and d["delta"]["type"] == pd["delta"]["type"]
                    and d["delta"]["type"] in DELTA_KEYS):
                k = DELTA_KEYS[d["delta"]["type"]]
                pd["delta"][k] += d["delta"][k]
                continue
            t = d.get("type")
            if t in RESP_DELTAS and pd.get("type") == t and pd.get("item_id") == d.get("item_id"):
                pd["delta"] += d["delta"]
                if "logprobs" in d:
                    pd["logprobs"] = pd.get("logprobs", []) + d["logprobs"]
                continue
            if "choices" in d and "choices" in pd and len(d["choices"]) == 1 and len(pd["choices"]) == 1:
                a, b = pd["choices"][0], d["choices"][0]
                text = {"content", "reasoning", "reasoning_content"}
                if (a.get("finish_reason") is None and b.get("finish_reason") is None
                        and a.get("logprobs") is None and b.get("logprobs") is None
                        and a.get("delta") and set(a["delta"]) == set(b.get("delta", {})) and set(a["delta"]) <= text
                        and "role" not in a["delta"]):
                    for k in a["delta"]:
                        a["delta"][k] += b["delta"][k]
                    continue
        out.append((ev, d))
    seq = 0
    for _, d in out:
        if isinstance(d, dict) and "sequence_number" in d:
            d["sequence_number"] = seq
            seq += 1
    return out


def client_view(txt, excluded):
    """The answer as compared: ids/timestamps normalized, deltas merged, and
    the excluded JSON pointers removed."""
    t = norm_ids(txt)
    try:
        v = json.loads(t)
        evs = None
    except ValueError:
        v = None
        evs = coalesce(sse_events(t))
    def drop(obj, ptrs):
        for p in ptrs:
            parts = p.strip("/").split("/")
            cur = obj
            for k in parts[:-1]:
                if isinstance(cur, dict) and k in cur:
                    cur = cur[k]
                else:
                    cur = None
                    break
            if isinstance(cur, dict):
                cur.pop(parts[-1], None)
    if v is not None:
        drop(v, excluded.get("body", []))
        return v
    for ev, d in evs:
        if isinstance(d, dict):
            drop(d, excluded.get(d.get("type"), []))
    return evs


def diff_paths(a, b, p=""):
    if type(a) != type(b):
        return [p or "/"]
    if isinstance(a, dict):
        out = []
        for k in list(dict.fromkeys(list(a) + list(b))):
            out += diff_paths(a.get(k), b.get(k), f"{p}/{k}") if k in a and k in b else [f"{p}/{k}"]
        return out
    if isinstance(a, (list, tuple)):
        if len(a) != len(b):
            return [p + "[len]"]
        return [x for i in range(len(a)) for x in diff_paths(a[i], b[i], f"{p}[{i}]")]
    return [] if a == b else [p or "/"]


def dump_diff(a, b):
    if len(a) != 1 or len(b) != 1:
        return [f"dump lines {len(a)} vs {len(b)}"]
    x = {k: v for k, v in a[0].items() if k not in DUMP_EXCLUDED}
    y = {k: v for k, v in b[0].items() if k not in DUMP_EXCLUDED}
    return diff_paths(x, y)


# ---------------------------------------------------------------------------
# What the translated (chat) path does not reproduce, by shape, and why.
# ---------------------------------------------------------------------------
EXCLUDED = {
    "anthropic": {
        # QE sends message_start once its engine admitted the request, with the
        # prompt and cache counts; QE's Chat stream reports usage only at its
        # end, so the translated message_start says 0 (message_delta is exact).
        "message_start": ["message/usage"],
    },
    "responses": {},
}

# Dump fields a translation cannot spell identically, per case tag.
DUMP_ALLOWED = {
    # A breakpoint on one block of a multi-block message is a breakpoint on
    # the whole message in Chat: same position, different mark text.
    "marks": {"/cache/marks"},
}

# ---------------------------------------------------------------------------
# The corpus
# ---------------------------------------------------------------------------
U = "What is the weather in Paris?"
CALL = ('\n\n<｜DSML｜ calls>\n<｜DSML｜ invoke name="get_weather">\n<｜DSML｜ parameter name="city" string="true">'
        'Paris</｜DSML｜ parameter>\n</｜DSML｜ invoke>\n</｜DSML｜ calls>')
CALL2 = ('\n\n<｜DSML｜ calls>\n<｜DSML｜ invoke name="get_weather">\n<｜DSML｜ parameter name="city" string="true">'
         'Paris</｜DSML｜ parameter>\n</｜DSML｜ invoke>\n<｜DSML｜ invoke name="get_time">\n'
         '<｜DSML｜ parameter name="zone" string="true">CET</｜DSML｜ parameter>\n</｜DSML｜ invoke>\n</｜DSML｜ calls>')
SCHEMA = {"type": "object", "properties": {"zone": {"type": "string"}, "city": {"type": "string"},
          "units": {"type": "string", "enum": ["c", "f"]}}, "required": ["city", "units"]}
ANT_TOOLS = [{"name": "get_weather", "description": "Weather for a city", "input_schema": SCHEMA},
             {"name": "get_time", "description": "Time in a zone",
              "input_schema": {"type": "object", "properties": {"zone": {"type": "string"}}, "required": ["zone"]}}]
RESP_TOOLS = [{"type": "function", "name": "get_weather", "description": "Weather for a city", "parameters": SCHEMA},
              {"type": "function", "name": "get_time", "description": "Time in a zone",
               "parameters": {"type": "object", "properties": {"zone": {"type": "string"}}, "required": ["zone"]}}]
JSON_SCHEMA = {"type": "object", "properties": {"answer": {"type": "string"}, "n": {"type": "integer"}},
               "required": ["answer", "n"], "additionalProperties": False}

CASES = []


def case(name, shape, body, tags=(), turns=None):
    CASES.append({"name": name, "shape": shape, "body": body, "tags": set(tags), "turns": turns})


def ant(**kw):
    b = {"seed": 7, "max_tokens": 2048, "messages": [{"role": "user", "content": U}]}
    b.update(kw)
    return b


def resp(**kw):
    b = {"seed": 7, "max_output_tokens": 2048, "store": False, "input": U}
    b.update(kw)
    return b


for stream in (False, True):
    s = " stream" if stream else ""
    case("anthropic text" + s, "anthropic", ant(stream=stream, system="Be brief.", temperature=0.3, top_k=20, top_p=0.9))
    case("anthropic system blocks + cache marks" + s, "anthropic", ant(stream=stream,
         system=[{"type": "text", "text": "You are a weather bot."},
                 {"type": "text", "text": "Shared context.", "cache_control": {"type": "ephemeral"}}],
         messages=[{"role": "user", "content": [{"type": "text", "text": "hello"},
                                                {"type": "text", "text": U, "cache_control": {"type": "ephemeral"}}]}],
         cache_control={"type": "ephemeral"}), tags=["marks"])
    for eff in ("low", "medium", "high", "max"):
        case(f"anthropic effort {eff} + budget 3000" + s, "anthropic", ant(stream=stream, max_tokens=8192,
             thinking={"type": "enabled", "budget_tokens": 3000}, output_config={"effort": eff}))
    case("anthropic effort none" + s, "anthropic", ant(stream=stream, output_config={"effort": "none"}))
    case("anthropic integer effort 62" + s, "anthropic", ant(stream=stream, reasoning_effort=62))
    case("anthropic thinking disabled" + s, "anthropic", ant(stream=stream, thinking={"type": "disabled"}))
    case("anthropic thinking adaptive" + s, "anthropic", ant(stream=stream, thinking={"type": "adaptive"}))
    case("anthropic budget above effort cap" + s, "anthropic", ant(stream=stream, max_tokens=60000,
         thinking={"type": "enabled", "budget_tokens": 50000}, output_config={"effort": "low"}))
    case("anthropic tools auto + call" + s, "anthropic", ant(stream=stream, tools=ANT_TOOLS,
         messages=[{"role": "user", "content": CALL}]))
    case("anthropic tools any, no parallel, two calls" + s, "anthropic", ant(stream=stream, tools=ANT_TOOLS,
         tool_choice={"type": "any", "disable_parallel_tool_use": True}, messages=[{"role": "user", "content": CALL2}]))
    case("anthropic tool named + parallel calls" + s, "anthropic", ant(stream=stream, tools=ANT_TOOLS,
         tool_choice={"type": "tool", "name": "get_weather"}, messages=[{"role": "user", "content": CALL2}]))
    case("anthropic tool_choice none" + s, "anthropic", ant(stream=stream, tools=ANT_TOOLS,
         tool_choice={"type": "none"}, messages=[{"role": "user", "content": CALL}]))
    case("anthropic stop sequences" + s, "anthropic", ant(stream=stream, stop_sequences=["weather", "zzz"]),
         tags=["stop"])
    case("anthropic structured output" + s, "anthropic", ant(stream=stream,
         output_config={"format": {"type": "json_schema", "schema": JSON_SCHEMA}},
         messages=[{"role": "user", "content": '{"answer": "sunny", "n": 3}'}]))
    case("anthropic max_tokens cut" + s, "anthropic", ant(stream=stream, max_tokens=3))
    case("anthropic agent transcript" + s, "anthropic", ant(stream=stream, max_tokens=4096, tools=ANT_TOOLS,
         system="You are an agent.", thinking={"type": "enabled", "budget_tokens": 2000}, output_config={"effort": "high"},
         messages=[
             {"role": "user", "content": [{"type": "text", "text": "<system-reminder>ctx</system-reminder>"},
                                          {"type": "text", "text": "Weather and time in Paris?"}]},
             {"role": "assistant", "content": [
                 {"type": "thinking", "thinking": "I need both tools.", "signature": "qe1abc"},
                 {"type": "text", "text": "Checking."},
                 {"type": "tool_use", "id": "toolu_1", "name": "get_weather", "input": {"units": "c", "city": "Paris"}},
                 {"type": "tool_use", "id": "toolu_2", "name": "get_time", "input": "{\"zone\": \"CET\"}"}]},
             {"role": "user", "content": [
                 {"type": "tool_result", "tool_use_id": "toolu_2", "content": "14:00"},
                 {"type": "tool_result", "tool_use_id": "toolu_1", "content": [{"type": "text", "text": "18C"}],
                  "is_error": True},
                 {"type": "text", "text": "Now summarize.", "cache_control": {"type": "ephemeral"}}]},
             {"role": "assistant", "content": [{"type": "redacted_thinking", "data": "x"},
                                               {"type": "text", "text": "It is 18C at 14:00."}]},
             {"role": "user", "content": CALL}]))

    case("responses text" + s, "responses", resp(stream=stream, instructions="Be brief.", temperature=0.3, top_p=0.9))
    for eff in ("none", "minimal", "low", "medium", "high", "xhigh", "max"):
        case(f"responses effort {eff}" + s, "responses", resp(stream=stream, reasoning={"effort": eff}, max_output_tokens=40000))
    case("responses thinking_token_budget 500 + stop" + s, "responses", resp(stream=stream, reasoning={"effort": "high"},
         thinking_token_budget=500, stop=["weather"]), tags=["stop"])
    case("responses tools auto + calls" + s, "responses", resp(stream=stream, tools=RESP_TOOLS, input=CALL2))
    case("responses tools required, no parallel" + s, "responses", resp(stream=stream, tools=RESP_TOOLS,
         tool_choice="required", parallel_tool_calls=False, input=CALL))
    case("responses tool named" + s, "responses", resp(stream=stream, tools=RESP_TOOLS,
         tool_choice={"type": "function", "name": "get_weather"}, input=CALL))
    case("responses allowed_tools" + s, "responses", resp(stream=stream, tools=RESP_TOOLS,
         tool_choice={"type": "allowed_tools", "mode": "auto", "tools": [{"type": "function", "name": "get_weather"}]},
         input=CALL))
    case("responses structured output" + s, "responses", resp(stream=stream,
         text={"format": {"type": "json_schema", "name": "a", "schema": JSON_SCHEMA, "strict": True}},
         input='{"answer": "sunny", "n": 3}'))
    case("responses max_output_tokens cut" + s, "responses", resp(stream=stream, max_output_tokens=3))
    case("responses max_output_tokens cut inside calls" + s, "responses", resp(stream=stream, tools=RESP_TOOLS,
         max_output_tokens=40, input=CALL2))
    case("responses encrypted reasoning + logprobs" + s, "responses", resp(stream=stream,
         include=["reasoning.encrypted_content", "message.output_text.logprobs"], top_logprobs=2))
    case("responses agent transcript" + s, "responses", resp(stream=stream, tools=RESP_TOOLS, instructions="You are an agent.",
         reasoning={"effort": "high"}, include=["reasoning.encrypted_content"], input=[
             {"type": "message", "role": "developer", "content": [{"type": "input_text", "text": "dev note"}]},
             {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "Weather "},
                                                             {"type": "input_text", "text": "and time?"}]},
             {"type": "reasoning", "id": "rs_1", "summary": [],
              "encrypted_content": "qe1:" + __import__("base64").b64encode("I need both.".encode()).decode()},
             {"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "Checking."}]},
             {"type": "function_call", "call_id": "c1", "name": "get_weather", "arguments": "{\"units\":\"c\",\"city\":\"Paris\"}"},
             {"type": "function_call", "call_id": "c2", "name": "get_time", "arguments": "{\"zone\":\"CET\"}"},
             {"type": "function_call_output", "call_id": "c2", "output": "14:00"},
             {"type": "function_call_output", "call_id": "c1", "output": [{"type": "input_text", "text": "18C"}]},
             {"type": "message", "role": "user", "content": CALL}]))

    case("chat text" + s, "chat", {"seed": 7, "max_tokens": 256, "stream": stream,
                                    "messages": [{"role": "user", "content": U}]}, tags=["relay-only"])
    case("chat tools" + s, "chat", {"seed": 7, "max_tokens": 256, "stream": stream, "tools": [
        {"type": "function", "function": {"name": "get_weather", "parameters": SCHEMA}}],
        "messages": [{"role": "user", "content": CALL}]}, tags=["relay-only"])

# Multi-turn: the gateway's own answer to turn 1 is the history of turn 2.
case("anthropic multi-turn tool loop", "anthropic", ant(tools=ANT_TOOLS, max_tokens=4096,
     thinking={"type": "enabled", "budget_tokens": 1000}, output_config={"effort": "medium"},
     messages=[{"role": "user", "content": CALL2}]), turns=2)
case("anthropic multi-turn tool loop stream", "anthropic", ant(tools=ANT_TOOLS, stream=True,
     messages=[{"role": "user", "content": CALL}]), turns=2)
case("responses multi-turn items", "responses", resp(tools=RESP_TOOLS, include=["reasoning.encrypted_content"],
     input=CALL2), turns=2)
case("responses previous_response_id", "responses", resp(tools=RESP_TOOLS, store=True, instructions="Be an agent.",
     input=CALL), turns=2, tags=["chain"])
case("responses previous_response_id stream", "responses", resp(tools=RESP_TOOLS, store=True, stream=True,
     input=CALL), turns=2, tags=["chain"])


def next_turn(shape, body, answer_txt, chain_id=None):
    """Turn 2: turn 1's answer as history, then the tool results."""
    b = copy.deepcopy(body)
    b.pop("stream", None)
    if shape == "anthropic":
        try:
            a = json.loads(answer_txt)
        except ValueError:
            a = rebuild_anthropic(answer_txt)
        content = a["content"]
        results = [{"type": "tool_result", "tool_use_id": c["id"], "content": "18C"} for c in content
                   if c["type"] == "tool_use"]
        b["messages"] = b["messages"] + [{"role": "assistant", "content": content},
                                         {"role": "user", "content": results + [{"type": "text", "text": "thanks"}]}]
        return b
    try:
        r = json.loads(answer_txt)
    except ValueError:
        r = [d for _, d in sse_events(answer_txt) if isinstance(d, dict) and d.get("type") in
             ("response.completed", "response.incomplete")][-1]["response"]
    outs = [{"type": "function_call_output", "call_id": o["call_id"], "output": "18C"} for o in r["output"]
            if o["type"] == "function_call"]
    if chain_id:
        b["previous_response_id"] = r["id"]
        b["input"] = outs + [{"role": "user", "content": "thanks"}]
    else:
        inp = b["input"] if isinstance(b["input"], list) else [{"role": "user", "content": b["input"]}]
        b["input"] = inp + r["output"] + outs + [{"role": "user", "content": "thanks"}]
    return b


def rebuild_anthropic(txt):
    """A buffered Anthropic message from its stream."""
    blocks, msg = {}, None
    for _, d in sse_events(txt):
        t = d.get("type")
        if t == "message_start":
            msg = d["message"]
        elif t == "content_block_start":
            blocks[d["index"]] = dict(d["content_block"])
            if blocks[d["index"]]["type"] == "tool_use":
                blocks[d["index"]]["_json"] = ""
        elif t == "content_block_delta":
            b, dl = blocks[d["index"]], d["delta"]
            if dl["type"] == "text_delta":
                b["text"] += dl["text"]
            elif dl["type"] == "thinking_delta":
                b["thinking"] += dl["thinking"]
            elif dl["type"] == "signature_delta":
                b["signature"] = dl["signature"]
            elif dl["type"] == "input_json_delta":
                b["_json"] += dl["partial_json"]
    for b in blocks.values():
        if "_json" in b:
            b["input"] = json.loads(b.pop("_json") or "{}")
    msg["content"] = [blocks[i] for i in sorted(blocks)]
    return msg


def compare(c, label, native, other, shape, variant):
    """(a) dumps and (b) answers of one variant against native."""
    problems = []
    st_n, txt_n, dump_n = native
    st_o, txt_o, dump_o = other
    if st_n != st_o:
        problems.append(f"HTTP {st_n} vs {st_o}: {txt_o[:200]}")
        return problems
    if st_n != 200:
        return problems  # both refused (e.g. QE's own 400)
    allowed = set()
    if variant == "chat":
        for t in c["tags"]:
            allowed |= DUMP_ALLOWED.get(t, set())
    if "marks" in c["tags"] and variant == "chat" and len(dump_n) == 1 and len(dump_o) == 1:
        # Same breakpoints; Chat can mark a message only once, so a
        # position several Anthropic marks share appears once.
        for dl in (dump_n, dump_o):
            dl[0] = dict(dl[0], cache=dict(dl[0]["cache"], positions=sorted(set(dl[0]["cache"]["positions"]))))
    d = [p for p in dump_diff(dump_n, dump_o) if not any(p.startswith(a) for a in allowed)]
    if d:
        problems.append(f"(a) dump differs at {d}")
    excl = dict(EXCLUDED.get(shape, {})) if variant == "chat" else {}
    if "stop" in c["tags"]:
        # QE counts the tokens it decoded before the stop string was seen,
        # which depends on how the engine batched them (it differs between two
        # native runs too: see stop_nondeterminism in the results).
        excl["body"] = excl.get("body", []) + ["usage/output_tokens", "usage/total_tokens"]
        excl["message_delta"] = excl.get("message_delta", []) + ["usage/output_tokens"]
        excl["response.completed"] = excl.get("response.completed", []) + ["response/usage/output_tokens",
                                                                           "response/usage/total_tokens"]
    if variant == "chat" and "stop" in c["tags"] and shape == "anthropic":
        excl = dict(excl)
        excl["body"] = excl.get("body", []) + ["stop_reason", "stop_sequence"]
        excl["message_delta"] = excl.get("message_delta", []) + ["delta"]
    a, b = client_view(txt_n, excl), client_view(txt_o, excl)
    if variant == "chat" and "chain" in c["tags"]:
        pass
    diffs = diff_paths(a, b)
    if diffs:
        problems.append(f"(b) answer differs at {diffs[:8]}")
    return problems


def record(c, native):
    import subprocess
    if c["turns"] or "relay-only" in c["tags"] or native[0] != 200:
        return
    inbound = copy.deepcopy(c["body"])
    inbound["model"] = M
    out = subprocess.run([QE_TRANSLATE], input=json.dumps({"shape": c["shape"], "body": inbound}).encode(),
                         capture_output=True)
    if out.returncode != 0:
        return
    chat_body = json.loads(out.stdout)
    sent = dict(chat_body)
    if sent.get("stream"):
        sent["stream_options"] = {"include_usage": True}  # as the gateway asks
    n0 = dump_len()
    st, chat_answer = post(QE, PATHS["chat"], sent, QE_KEY)
    chat_dump = dumps_since(n0)
    if st != 200:
        return
    name = re.sub(r"[^a-z0-9]+", "_", c["name"].lower()).strip("_")
    cas = {"name": c["name"], "shape": c["shape"], "inbound_body": inbound, "expected_chat_body": chat_body,
           "stream": bool(inbound.get("stream")), "chat_answer": chat_answer, "native_answer": native[1],
           "tags": sorted(c["tags"]),
           "dump_equal": not dump_diff(native[2], chat_dump) or sorted(dump_diff(native[2], chat_dump))}
    os.makedirs(RECORD, exist_ok=True)
    with open(os.path.join(RECORD, name + ".json"), "w") as f:
        json.dump(cas, f, indent=1, ensure_ascii=False)


def run():
    results = []
    totals = {}
    for c in CASES:
        if ONLY and ONLY not in c["name"]:
            continue
        shape = c["shape"]
        variants = ["relay"] if "relay-only" in c["tags"] else ["relay", "chat", "ir"]
        native = send("native", shape, c["body"])
        row = {"case": c["name"], "shape": shape, "native_status": native[0], "variants": {}}
        if RECORD:
            record(c, native)
        if "stop" in c["tags"]:
            again = send("native", shape, c["body"])
            row["stop_nondeterminism"] = diff_paths(client_view(native[1], {}), client_view(again[1], {}))
            print(f"[info] native twice, {c['name']}: differs at {row['stop_nondeterminism'] or 'nothing'}")
        for v in variants:
            got = send(v, shape, c["body"])
            probs = compare(c, c["name"], native, got, shape, v)
            row["variants"][v] = {"ok": not probs, "problems": probs, "status": got[0],
                                  "native": native[1], "gateway": got[1],
                                  "dump_native": native[2], "dump_gateway": got[2]}
            # (c) the gateway's own answer fed back as the next turn
            if c["turns"] and got[0] == 200 and v != "ir":
                chain = "chain" in c["tags"]
                nb = next_turn(shape, c["body"], got[1], chain_id=chain)
                if chain:
                    # Native continues its own stored turn 1, the gateway its.
                    nb_native = next_turn(shape, c["body"], native[1], chain_id=True)
                    n2 = send("native", shape, nb_native)
                else:
                    n2 = send("native", shape, nb)
                g2 = send(v, shape, nb)
                p2 = compare(c, c["name"] + " turn 2", n2, g2, shape, v)
                if chain and v == "chat":
                    # GET of the stored turn 1 on both sides
                    rid_n = json.loads(native[1])["id"] if native[1].startswith("{") else None
                    rid_g = json.loads(got[1])["id"] if got[1].startswith("{") else None
                    if rid_n and rid_g:
                        gn = send("native", shape, None, "GET", f"/v1/responses/{rid_n}")
                        gg = send(v, shape, None, "GET", f"/v1/responses/{rid_g}")
                        da, db = client_view(gn[1], {}), client_view(gg[1], {})
                        if diff_paths(da, db):
                            p2.append(f"GET stored response differs at {diff_paths(da, db)[:8]}")
                        ia = send("native", shape, None, "GET", f"/v1/responses/{rid_n}/input_items?order=asc")
                        ib = send(v, shape, None, "GET", f"/v1/responses/{rid_g}/input_items?order=asc")
                        da, db = client_view(ia[1], {}), client_view(ib[1], {})
                        if diff_paths(da, db):
                            p2.append(f"GET input_items differs at {diff_paths(da, db)[:8]}")
                row["variants"][v]["turn2"] = {"ok": not p2, "problems": p2, "native": n2[1], "gateway": g2[1],
                                               "dump_native": n2[2], "dump_gateway": g2[2]}
                probs = probs + [f"turn 2: {p}" for p in p2]
                row["variants"][v]["ok"] = not probs
                row["variants"][v]["problems"] = probs
            ok = not probs
            key = (shape, v)
            t = totals.setdefault(key, [0, 0])
            t[0] += 1
            t[1] += ok
            mark = "ok " if ok else "DIFF"
            print(f"[{mark}] {v:5} {c['name']}" + ("" if ok else "\n        " + "\n        ".join(probs)))
            sys.stdout.flush()
        results.append(row)
    # Background responses: queued now, polled to completion, then deleted.
    if not ONLY or ONLY in "responses background":
        body = resp(store=True, background=True, input="Background question?")
        finals = {}
        for v in ("native", "relay", "chat"):
            st, txt, _ = send(v, "responses", body)
            r0 = json.loads(txt)
            rid = r0["id"]
            for _ in range(100):
                _, g, _ = send(v, "responses", None, "GET", f"/v1/responses/{rid}")
                if json.loads(g)["status"] not in ("queued", "in_progress"):
                    break
                time.sleep(0.1)
            finals[v] = (client_view(txt, {}), client_view(g, {}))
            c1 = send(v, "responses", None, "POST", f"/v1/responses/{rid}/cancel")
            d1 = send(v, "responses", None, "DELETE", f"/v1/responses/{rid}")
            g2 = send(v, "responses", None, "GET", f"/v1/responses/{rid}")
            finals[v] += (client_view(c1[1], {}), client_view(d1[1], {}), g2[0])
        for v in ("relay", "chat"):
            probs = [] if finals[v] == finals["native"] else [f"background differs: {diff_paths(list(finals['native']), list(finals[v]))[:8]}"]
            t = totals.setdefault(("responses", v), [0, 0])
            t[0] += 1
            t[1] += not probs
            print(f"[{'ok ' if not probs else 'DIFF'}] {v:5} responses background (queued, GET, cancel, DELETE)"
                  + ("" if not probs else "\n        " + probs[0]))
            results.append({"case": "responses background", "shape": "responses", "variants": {v: {"ok": not probs, "problems": probs}}})
    with open(os.path.join(WORK, "results.json"), "w") as f:
        json.dump(results, f, indent=1, ensure_ascii=False)
    print("\nsummary (cases matching / cases):")
    bad = False
    for (shape, v), (n, ok) in sorted(totals.items()):
        print(f"  {shape:9} {v:5} {ok}/{n}")
        if v in ("relay", "chat") and ok != n:
            bad = True
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(run())
