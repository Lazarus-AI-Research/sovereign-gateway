#!/usr/bin/env python3
"""Multimodal embeddings must survive the gateway.

The IR models fields exactly and has no `extra` escape hatch, so anything it
fails to model is dropped silently. That is a standing hazard for the multimodal
embeddings superset, whose parts (`image_url`, `input_audio`) exist only in the
`messages` form. Unit tests cover parse->IR->emit; this covers the whole path
through the real binary:

    a client's request
        -> the gateway (auth, routing, dispatch, IR round-trip)
            -> a stub standing in for an OpenAI-compatible runtime

The stub records what it receives and we assert the audio arrived byte-identical
and the vector came back. If a future IR change drops a part, this fails.

Run:  python3 scripts/smoke_multimodal_embed.py [path/to/gateway]
      (default: target/debug/gateway)
"""
import base64
import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import wave
from http.server import BaseHTTPRequestHandler, HTTPServer

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GATEWAY_BIN = sys.argv[1] if len(sys.argv) > 1 else os.path.join(_REPO, "target/debug/gateway")
RUNTIME_PORT, GATEWAY_PORT = 8871, 8872
received = {}


def silent_wav_b64() -> str:
    """0.5s of silence — a real WAV, so nothing can pass by being empty."""
    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(16000)
        w.writeframes(b"\x00\x00" * 8000)
    return base64.b64encode(buf.getvalue()).decode()


class StubRuntime(BaseHTTPRequestHandler):
    """Stands in for Sovereign Runtime's OpenAI-compatible /v1/embeddings."""

    def do_POST(self):
        n = int(self.headers.get("content-length", 0))
        received["body"] = json.loads(self.rfile.read(n))
        received["path"] = self.path
        out = json.dumps({
            "object": "list",
            "model": "embedding-omni-default",
            "data": [{"object": "embedding", "index": 0, "embedding": [0.1, 0.2, 0.3]}],
            "usage": {"prompt_tokens": 1, "total_tokens": 1},
        }).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):
        pass


def post(url, body, headers=None):
    req = urllib.request.Request(url, method="POST", data=json.dumps(body).encode())
    req.add_header("content-type", "application/json")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    with urllib.request.urlopen(req) as r:
        return r.status, json.loads(r.read() or b"{}"), r.headers


def main() -> int:
    if not os.path.exists(GATEWAY_BIN):
        print(f"no gateway binary at {GATEWAY_BIN} (cargo build -p yb-bin)")
        return 2
    print(f"=== multimodal embed smoke ({os.path.basename(GATEWAY_BIN)})")

    srv = HTTPServer(("127.0.0.1", RUNTIME_PORT), StubRuntime)
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    work = tempfile.mkdtemp()
    cfg, models = f"{work}/gateway.toml", f"{work}/models.toml"
    open(cfg, "w").write(f"""
[server]
bind = "127.0.0.1:{GATEWAY_PORT}"
deployment_mode = "selfhosted"
[database]
backend = "sqlite"
path = "{work}/g.db"
[upstream]
mode = "http"
[reqlog]
enabled = false
[routing]
strategy = "simple"
""")
    # An embedding deployment pointing at the stub, exactly as the appliance
    # would point at Sovereign Runtime.
    open(models, "w").write(f"""
[[model]]
model_name = "embedding-omni-default"
  [[model.deployments]]
  provider = "custom"
  upstream_model = "embedding-omni-default"
  upstream_format = "openai_embed"
  api_base = "http://127.0.0.1:{RUNTIME_PORT}/v1"
  api_key = "unused"
  weight = 1
""")

    subprocess.run([GATEWAY_BIN, "import", models, cfg], capture_output=True, check=True)
    proc = subprocess.Popen([GATEWAY_BIN, cfg], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        base = f"http://127.0.0.1:{GATEWAY_PORT}"
        for _ in range(80):
            try:
                urllib.request.urlopen(base + "/health").read()
                break
            except Exception:
                time.sleep(0.25)

        # Mint an inference key the way Control would.
        import http.cookiejar
        jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
        urllib.request.install_opener(opener)
        post(base + "/admin/v1/auth/login", {"username": "admin", "password": "admin"})
        _, issued, _ = post(base + "/admin/v1/keys", {"name": "e2e"})
        token = issued["token"]

        # The smoke suite's exact audio-embedding request.
        wav = silent_wav_b64()
        status, body, _ = post(
            base + "/v1/embeddings",
            {
                "model": "embedding-omni-default",
                "messages": [{"role": "user", "content": [
                    {"type": "input_audio", "input_audio": {"data": wav, "format": "wav"}},
                ]}],
            },
            {"authorization": f"Bearer {token}"},
        )

        fails = []
        if status != 200:
            fails.append(f"gateway returned {status}: {body}")
        if not received:
            fails.append("the runtime stub was never called — the gateway did not forward")
        else:
            sent = received["body"]
            print("  runtime received:", json.dumps(sent)[:120] + "...")
            if "messages" not in sent:
                fails.append(f"`messages` was dropped; body keys = {list(sent)}")
            else:
                content = sent["messages"][0]["content"]
                audio = [p for p in content if p.get("type") == "input_audio"]
                if not audio:
                    fails.append(f"the audio part was dropped; parts = {[p.get('type') for p in content]}")
                else:
                    a = audio[0]["input_audio"]
                    if a.get("data") != wav:
                        fails.append("audio payload was altered in transit")
                    if a.get("format") != "wav":
                        fails.append(f"format was lost: {a.get('format')!r}")
            # The gateway parses vectors into f32 and re-emits, so compare with
            # tolerance: 0.1 round-trips as 0.10000000149011612. That is the
            # same precision pgvector's float4 stores anyway.
            got = body.get("data", [{}])[0].get("embedding")
            if not got or len(got) != 3 or any(
                abs(a - b) > 1e-6 for a, b in zip(got, [0.1, 0.2, 0.3])
            ):
                fails.append(f"the vector did not come back to the client: {body}")

        if not fails:
            print("  ok   audio survived: client -> gateway -> runtime, byte-identical")
            print("  ok   the vector came back to the client")

        # Interleaved image + text in one message -> one vector. Same superset
        # path, and the shape the runtime contract gives as its example.
        received.clear()
        png = base64.b64encode(b"\x89PNG\r\n\x1a\n" + b"\x00" * 16).decode()
        status, body, _ = post(
            base + "/v1/embeddings",
            {
                "model": "embedding-omni-default",
                "messages": [{"role": "user", "content": [
                    {"type": "image_url", "image_url": {"url": f"data:image/png;base64,{png}"}},
                    {"type": "text", "text": "accompanying text"},
                ]}],
            },
            {"authorization": f"Bearer {token}"},
        )
        if status != 200:
            fails.append(f"interleaved image+text returned {status}: {body}")
        elif not received:
            fails.append("interleaved image+text never reached the runtime")
        else:
            content = received["body"].get("messages", [{}])[0].get("content", [])
            types = [p.get("type") for p in content]
            if types != ["image_url", "text"]:
                fails.append(f"interleaved parts lost or reordered: {types}")
            elif png not in content[0]["image_url"]["url"]:
                fails.append("image payload was altered in transit")
            elif content[1]["text"] != "accompanying text":
                fails.append("the accompanying text was altered")
            else:
                print("  ok   interleaved image+text survived, in order, as one vector")

        for f in fails:
            print("  FAIL", f)
        return 1 if fails else 0
    finally:
        proc.kill()
        srv.shutdown()


if __name__ == "__main__":
    sys.exit(main())
