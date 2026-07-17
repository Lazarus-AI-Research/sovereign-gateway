#!/usr/bin/env python3
"""Verify docs/openapi.yaml against a running gateway.

Three checks, because a spec can be wrong in three directions:

  1. STRUCTURE  — the document parses and every $ref resolves.
  2. COVERAGE   — every route the Rust router mounts is documented, and every
                  documented route actually exists on the server. A spec that
                  lists a route nobody serves is as broken as one that misses a
                  route people call.
  3. SHAPES     — live responses validate against their declared schemas.

Usage: check_openapi.py <base_url> <repo_root>
Exits non-zero on any failure.
"""
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator

BASE, ROOT = sys.argv[1], Path(sys.argv[2])
SPEC = yaml.safe_load((ROOT / "docs" / "openapi.yaml").read_text())
failures: list[str] = []
checks = 0


def fail(msg: str) -> None:
    failures.append(msg)
    print(f"  FAIL {msg}")


def ok(msg: str) -> None:
    global checks
    checks += 1
    print(f"  ok   {msg}")


def request(method: str, path: str, body=None, cookie=None):
    req = urllib.request.Request(BASE + path, method=method)
    if body is not None:
        req.add_header("content-type", "application/json")
        req.data = json.dumps(body).encode()
    if cookie:
        req.add_header("cookie", cookie)
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, r.read(), r.headers
    except urllib.error.HTTPError as e:
        return e.code, e.read(), e.headers
    except Exception as e:  # noqa: BLE001
        return 0, str(e).encode(), {}


# ---- 1. structure ---------------------------------------------------------
print("\n=== structure ===")
Draft202012Validator.check_schema({"$defs": SPEC.get("components", {}).get("schemas", {})})
ok("components.schemas are valid JSON Schema")

refs = re.findall(r"'\$ref':\s*'([^']+)'", str(SPEC)) + re.findall(
    r'"\$ref":\s*"([^"]+)"', json.dumps(SPEC)
)
missing = []
for ref in set(refs):
    node = SPEC
    for part in ref.lstrip("#/").split("/"):
        if not isinstance(node, dict) or part not in node:
            missing.append(ref)
            break
        node = node[part]
if missing:
    fail(f"unresolved $refs: {sorted(set(missing))}")
else:
    ok(f"all {len(set(refs))} $refs resolve")


# ---- 2. coverage ----------------------------------------------------------
print("\n=== coverage: Rust router vs spec ===")
documented: set[tuple[str, str]] = set()
for path, item in SPEC["paths"].items():
    for method in item:
        if method.lower() in {"get", "post", "put", "delete", "patch"}:
            documented.add((method.upper(), path))

# Routes the Rust router actually mounts.
admin_rs = (ROOT / "crates/yb-server/src/admin.rs").read_text()
lib_rs = (ROOT / "crates/yb-server/src/lib.rs").read_text()


def routes_from(src: str, prefix: str) -> set[tuple[str, str]]:
    """Extract (METHOD, path) from axum `.route("...", get(h).post(h))` calls.

    The handler list must be read by counting parens, not by a lazy regex: a
    lazy `.+?\\)` stops at the first close paren and silently mis-reads every
    multi-method route (`get(a).post(b)` -> just `get(a`).
    """
    found: set[tuple[str, str]] = set()
    i = 0
    needle = ".route("
    while (i := src.find(needle, i)) >= 0:
        j = i + len(needle)
        m = re.match(r'\s*"([^"]+)"\s*,', src[j:])
        if not m:
            i = j
            continue
        route = m.group(1)
        k = start = j + m.end()
        depth = 1
        while k < len(src) and depth:
            depth += (src[k] == "(") - (src[k] == ")")
            k += 1
        handlers = src[start : k - 1]
        # axum ":id" / "*path" -> OpenAPI "{id}" / "{path}"
        p = re.sub(r"\*(\w+)", r"{\1}", re.sub(r":(\w+)", r"{\1}", route))
        for meth in re.findall(r"\b(get|post|put|delete|patch)\s*\(", handlers):
            found.add((meth.upper(), (prefix + p).replace("//", "/")))
        i = k
    return found


mounted = routes_from(admin_rs, "/admin/v1") | routes_from(lib_rs, "")
# The console is an optional build feature and deliberately out of the contract.
mounted = {(m, p) for (m, p) in mounted if not (p == "/" or p.startswith("/ui"))}
# Explicit per-shape prefixes are aliases of the canonical paths.
mounted = {
    (m, p)
    for (m, p) in mounted
    if not p.startswith(("/anthropic/", "/openai/", "/gemini/", "/voyage/", "/cohere/"))
}

undocumented = sorted(mounted - documented)
phantom = sorted(documented - mounted)
if undocumented:
    fail(f"mounted but NOT documented: {undocumented}")
else:
    ok(f"all {len(mounted)} mounted routes are documented")
if phantom:
    fail(f"documented but NOT mounted: {phantom}")
else:
    ok("no phantom routes in the spec")


# ---- 3. shapes ------------------------------------------------------------
print("\n=== shapes: live responses vs declared schemas ===")


def schema_for(path: str, method: str, status: str):
    try:
        r = SPEC["paths"][path][method]["responses"][status]
    except KeyError:
        return None
    if "$ref" in r:  # a components/responses entry
        node = SPEC
        for part in r["$ref"].lstrip("#/").split("/"):
            node = node[part]
        r = node
    return r.get("content", {}).get("application/json", {}).get("schema")


def resolve(schema):
    """Inline $refs so the validator can see components/schemas."""
    return {**schema, "$defs": SPEC["components"]["schemas"]} if schema else schema


def deref(s):
    return json.loads(
        json.dumps(s).replace('"#/components/schemas/', '"#/$defs/')
    )


def check(method: str, path: str, status: int, spec_path: str = None, cookie=None, body=None):
    spec_path = spec_path or path
    code, raw, _ = request(method, path, body, cookie)
    if code != status:
        fail(f"{method} {path} -> {code}, expected {status} ({raw[:120]!r})")
        return None
    schema = schema_for(spec_path, method.lower(), str(status))
    if schema is None:
        ok(f"{method} {path} -> {code} (no json schema declared)")
        return raw
    try:
        payload = json.loads(raw)
    except Exception:
        fail(f"{method} {path} -> not JSON")
        return None
    errs = sorted(Draft202012Validator(deref(resolve(schema))).iter_errors(payload), key=str)
    if errs:
        fail(f"{method} {path} schema: {errs[0].message[:150]}")
    else:
        ok(f"{method} {path} -> {code} matches schema")
    return raw


check("GET", "/health", 200)
check("GET", "/v1/models", 200)
check("GET", "/admin/v1/auth/config", 200)

# login -> cookie
code, raw, headers = request(
    "POST", "/admin/v1/auth/login", {"username": "admin", "password": "admin"}
)
if code != 200:
    fail(f"login -> {code}")
    sys.exit(1)
cookie = headers.get("set-cookie", "").split(";")[0]
errs = sorted(
    Draft202012Validator(
        deref(resolve(schema_for("/admin/v1/auth/login", "post", "200")))
    ).iter_errors(json.loads(raw)),
    key=str,
)
ok("POST /admin/v1/auth/login -> 200 matches schema") if not errs else fail(
    f"login schema: {errs[0].message}"
)

for m, p in [
    ("GET", "/admin/v1/auth/me"),
    ("GET", "/admin/v1/models"),
    ("GET", "/admin/v1/models/health"),
    ("GET", "/admin/v1/aliases"),
    ("GET", "/admin/v1/users"),
    ("GET", "/admin/v1/keys"),
    ("GET", "/admin/v1/teams"),
    ("GET", "/admin/v1/spend"),
]:
    check(m, p, 200, cookie=cookie)

check(
    "GET",
    "/admin/v1/budgets?subject_type=user&subject_id=u1",
    200,
    spec_path="/admin/v1/budgets",
    cookie=cookie,
)

# The one-time token contract.
code, raw, _ = request("POST", "/admin/v1/keys", {"name": "spec-check"}, cookie)
if code == 200:
    errs = sorted(
        Draft202012Validator(
            deref(resolve(schema_for("/admin/v1/keys", "post", "200")))
        ).iter_errors(json.loads(raw)),
        key=str,
    )
    if errs:
        fail(f"POST /admin/v1/keys schema: {errs[0].message[:150]}")
    else:
        ok("POST /admin/v1/keys -> 200 matches IssuedKey")
    if not json.loads(raw).get("token", "").startswith("yb_"):
        fail("issued token does not carry the yb_ prefix the contract promises")
    else:
        ok("issued token carries the yb_ prefix")
else:
    fail(f"POST /admin/v1/keys -> {code}")

# The error envelope every non-2xx promises.
code, raw, _ = request("GET", "/admin/v1/definitely-not-a-route")
errs = sorted(
    Draft202012Validator(deref(resolve(SPEC["components"]["schemas"]["Error"]))).iter_errors(
        json.loads(raw)
    ),
    key=str,
)
ok("404 body matches the Error envelope") if not errs else fail(f"error envelope: {errs[0].message}")

print(f"\n=== {checks} checks passed, {len(failures)} failed ===")
sys.exit(1 if failures else 0)
