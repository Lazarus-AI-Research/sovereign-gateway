# greater-spire

SPIFFE-authenticated mTLS and HTTP connections for Rust services. One runtime
supports local PEM credentials and an embedded SPIRE agent. Services use the
same transport API with either provider.

The library authenticates machines. Each receiving application owns admission,
delegated-user permissions, tenants, producers, scopes, and resource ACLs.
Successful mTLS does **not** grant application permissions.

See the [identity and RPC contract](docs/CONTRACT.md) for startup/recovery,
revocation bounds, trust migration, typed errors, response limits, and the
distinction between local tests and live provider validation.

## Use from a service

```toml
[dependencies]
greater-spire = { path = "../lair/greater-spire" }
```

```rust,no_run
use greater_spire::{Config, IdentityRuntime};

# #[cfg(feature = "http")]
# async fn run() -> Result<(), Box<dyn std::error::Error>> {
let config = Config::load("nexis", None)?;
let mut identity = IdentityRuntime::start(config).await?;
let client = identity.http_client("vkg")?;
let response = client.get("/v1/capabilities").await?;

// Keep identity alive while the application serves requests.
// Readiness endpoints can use identity.status().await.ready.
identity.shutdown().await;
# Ok(())
# }
```

Both identity providers are included in every build. The default `http` feature
adds Hyper-based HTTP/1 and HTTP/2 transport. Disabling default features retains
the identity runtime and raw Tokio/rustls mTLS API.

## Library-owned configuration

`Config::load(service, explicit_path)` selects exactly one file, in order:

1. The explicit path, normally supplied by the application's --identity-config.
2. GREATER_SPIRE_CONFIG in that process's environment.
3. /etc/greater-spire/<service>.toml.

Relative credential paths resolve against the configuration file's directory.
Missing files fail startup; there is no working-directory search or provider
fallback. Config::from_file and Config::from_toml(text, base_directory) are
available for applications that already own configuration discovery.

Start from [files.toml.example](examples/files.toml.example):

```toml
version = 1

[identity]
spiffe_id = "spiffe://fleet.test/service/nexis"

[identity.source]
kind = "files"
directory = "/var/lib/greater-spire/nexis/current"
poll_interval_secs = 5

[transport]
handshake_timeout_secs = 10
max_connection_age_secs = 300
request_timeout_secs = 30

[peers.vkg]
url = "https://127.0.0.1:8443"
spiffe_id = "spiffe://fleet.test/service/vkg"
```

These are identity and transport settings only. The parser rejects unknown
fields, including [callers], [app], [server], and application permissions.
The application's bind address stays in application configuration. Peer URLs
are HTTPS origins without userinfo, paths, or query strings; the configured
SPIFFE ID is mandatory and is checked independently of DNS or SNI.

The files provider reads cert-chain.pem, key.pem (unencrypted PKCS#8), and
bundle.pem from a single generation. The bundle is explicitly bound to the
local identity's trust domain; cross-domain file federation is not inferred.
Certificates and keys are validated before startup or publication: identity,
key match, both TLS usages, validity, SVID profile, and chain of trust.

For credentials obtained from another secret store:

```rust,no_run
use greater_spire::{IdentitySource, SpiffeId};
# fn load(chain: &[u8], key: &[u8], bundle: &[u8]) -> greater_spire::Result<()> {
let expected: SpiffeId = "spiffe://fleet.test/service/nexis".try_into().unwrap();
let identity = IdentitySource::from_pem(&expected, chain, key, bundle)?;
# Ok(())
# }
```

The constructor derives expiration from the leaf certificate. It does not run a
renewal task. The files runtime does polling and offers reload() for an
application's SIGHUP handler. Provider and local identity changes require a new
runtime.

## Setup and renewal without a SPIRE server

The optional static-ca feature provides static_ca::StaticCa and a small
greater-spire-setup executable. Enable it in the installer, not in service
binaries. The setup process holds the CA private key; each service receives only
its own leaf key, certificate, and public trust bundle.

```sh
cargo build --features static-ca --bin greater-spire-setup
mkdir -p .fleet
target/debug/greater-spire-setup init-ca fleet.test .fleet/ca 1825
target/debug/greater-spire-setup issue .fleet/ca spiffe://fleet.test/service/nexis .fleet/nexis 90
target/debug/greater-spire-setup issue .fleet/ca spiffe://fleet.test/service/vkg .fleet/vkg 90
```

init-ca preserves an existing CA and checks its trust domain. issue creates a
fresh P-256 key and X.509-SVID with exactly one SPIFFE URI SAN and both TLS
client/server usages. It rejects a lifetime exceeding the CA's validity.

On Unix, issue writes a new generation and atomically replaces the workload's
current symlink. Files and directories are fsynced before publication. Prior
generations are retained for operator-controlled rollback and cleanup. An
installer can also use IssuedIdentity::write_generation with its own publisher.
On other platforms the CLI writes a new directory and refuses to overwrite it.

Schedule issue well before leaf expiration, for example through a systemd timer.
The library reloads credentials but does not obtain the CA key or mint its own
renewals. The installer also owns CA backup, CA rotation, filesystem ownership,
and separating service accounts. Do not recreate the CA during ordinary upgrades.

Directories are created with mode 0700 and private keys with 0600 on Unix.
The loader also accepts protected root-owned Kubernetes Secret files with group
read access for a dedicated fsGroup; it rejects world-readable keys and
group/other-writable credential files or generation directories. Set equivalent
ACLs on Windows. The installer must assign ownership/access to the intended
service. Configured trust bundles are security-sensitive even though public.

## Rotation and connection lifetime

Publish immutable generations, never modify active files individually. The
loader resolves the generation once; Kubernetes projected ..data symlinks
are supported and mismatched generation parents are rejected.

Invalid reloads preserve the previous validated snapshot and set last_error.
Readiness remains true only while that identity is valid. Expired credentials
fail closed. Unchanged reloads preserve snapshot identity, TLS configurations,
and HTTP pools.

### Observing usability and refresh health

`IdentityRuntime::watch()` returns a `tokio::sync::watch::Receiver<IdentityStatus>`
for either provider. Read its initial value, then await `changed()` for refresh
results, expiration, and shutdown. The expiry timer is independent of credential
polling and is rearmed on rotation. `status().await` remains available for probes.
The watch carries the latest state, not an event log: slow readers can coalesce
updates. Clone a borrowed snapshot before awaiting; do not hold a watch borrow
while calling runtime methods.

```rust,no_run
use greater_spire::{IdentityRuntime, RefreshStatus};
# fn observe(identity: &IdentityRuntime) -> tokio::task::JoinHandle<()> {
let mut changes = identity.watch();
tokio::spawn(async move {
    loop {
        let status = changes.borrow_and_update().clone();
        tracing::info!(usable = status.usable, valid_until = status.valid_until_unix);
        if let RefreshStatus::Error { error, since_unix, last_attempt_unix } = status.refresh {
            tracing::warn!(%error, since_unix, last_attempt_unix, "identity refresh unhealthy");
        }
        // Update application readiness and rearm its pre-expiry admission timer here.
        if changes.changed().await.is_err() {
            // The publisher is gone; the application must remain unready.
            break;
        }
    }
})
# }
```

`usable` means the current credentials are valid and the runtime has not stopped;
`ready` is retained as an identical compatibility field. A failed reload leaves
usable last-known-good credentials in place and sets `refresh` to
`RefreshStatus::Error { error, since_unix, last_attempt_unix }`. `since_unix` marks
the first failure since the last success; the error and `last_attempt_unix` reflect
the latest attempt. A successful reload, including an unchanged generation,
clears the error. All timestamps are Unix seconds. The existing `last_error` and
`last_success_unix` fields remain available.

`expires_at_unix` remains the leaf expiration. `valid_until_unix` is the earliest
expiration in the presented chain and is the appropriate admission deadline.
Applications own pre-expiry lead times: stop admission at `valid_until_unix` minus
their lead time, rearming on rotation. The library does not redefine credential
usability for an application's drain budget. Runtime shutdown/drop publishes
`usable = false`; a later refresh cannot revive a stopped runtime. Admission and
readiness are operational signals, not substitutes for transport verification.

Both inbound and outbound TLS configurations are cached. New HTTP requests use
a new pool following credential publication. Existing connections can finish
within the earlier of the presented certificate-chain expirations and
max_connection_age_secs. Trust-bundle changes reject further I/O on existing
connections; HTTP server dispatch also checks authentication for every request.
The stream's lifetime timer wakes pending I/O. Runtime shutdown invalidates its
handles; dropping the runtime also stops its background work.

The HTTP request timeout runs through response headers. Applications can add a
shorter deadline for consuming a response body; connection lifetime bounds the
underlying stream. TLS session resumption is disabled so new connections
perform fresh certificate authentication.

## Incoming requests and application authorization

identity.acceptor().accept(tcp) returns an authenticated stream and an
AuthenticatedPeer with the certificate's SPIFFE ID and expiration. It does not
require a caller allowlist or a library-specific policy document.

acceptor.serve_http_connection(tcp, service) supports Hyper services and adds
AuthenticatedPeer to **every request's extensions**. Use
hyper_util::service::TowerToHyperService for Axum/Tower services. The application
binds its listener, limits concurrent connections, and dispatches each accepted
connection to this adapter.

In the application handler, obtain the peer from request extensions, resolve its
own caller policy, then enforce the endpoint's permissions. Never obtain the
machine's identity from an HTTP header. A trusted certificate identifies a
caller; the application may still reject that caller with 403. Reevaluate
application policy on each request, including HTTP/2 and keep-alive requests.
User delegation and RPC request/response schemas remain application concerns.

Use the complete SPIFFE ID as the canonical machine subject, including its trust
domain. Do not infer identity from the final path segment or a friendly service
name. Application labels and any delegated human identity remain separate.

Outbound HttpClient is bound to one configured origin and expected SPIFFE ID.
It rejects requests to other origins, does not follow redirects, ignores proxy
environment variables, and does not automatically retry canceled requests.
The application controls retry policy for its RPC methods.

The [service client example](examples/service_client.rs) demonstrates a retained
runtime and pooled client, status observation, typed VKG capability discovery,
bounded response-body consumption, and shutdown on both success and failure:

```sh
cargo run --example service_client -- /path/to/scribe-identity.toml
```

TCP/TLS/HTTP failures preserve their underlying causes. For diagnostics, use
`error.find_cause::<PeerIdentityError>()`, `error.find_cause::<TimeoutPhase>()`, or
`error.causes()` instead of parsing strings. A timeout or interrupted response
does not prove that a mutation was uncommitted; retries remain application-owned.

### Graceful HTTP shutdown

`acceptor.serve_http_connection_with_shutdown(tcp, service, shutdown_future)`
adds a graceful-drain signal to the same adapter. The future must complete with
`()`, for example `drain.cancelled()` from a shared
`tokio_util::sync::CancellationToken`:

```rust,no_run
# #[cfg(feature = "http")]
# async fn serve_one(
#     acceptor: greater_spire::MtlsAcceptor,
#     tcp: tokio::net::TcpStream,
#     drain: tokio_util::sync::CancellationToken,
# ) -> greater_spire::Result<()> {
use bytes::Bytes;
use http_body_util::Full;
use hyper::{body::Incoming, service::service_fn, Request, Response};

let service = service_fn(|_request: Request<Incoming>| async {
    // Real handlers must authorize the AuthenticatedPeer in request extensions.
    Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::from("ok"))))
});
acceptor
    .serve_http_connection_with_shutdown(tcp, service, drain.cancelled())
    .await?;
# Ok(())
# }
```

On SIGTERM, the application first stops accepting TCP connections, then calls
`drain.cancel()` for the token shared by all connection tasks. Keep polling those
tasks: idle connections close, HTTP/1 disables keep-alive, and HTTP/2 uses its
graceful GOAWAY exchange. Accepted requests and response bodies finish, including
streams already in transit during that exchange. The signal also cancels an
unfinished TLS handshake. Use an application-owned overall drain timeout and
abort remaining tasks only if it expires. Finally call `IdentityRuntime::shutdown()`.

Do not shut down the identity runtime first: it invalidates transport handles.
Dropping a connection future aborts it; it does not drain. Certificate-chain
expiry (local or peer), maximum connection age, and trust changes remain hard
limits during draining. The existing `serve_http_connection` method is retained
for callers that do not need a shutdown signal.

## Testing application handlers

Enable `test-utils` through a dev-dependency to construct synthetic
AuthenticatedPeer values in application tests. Use the same source and version
as the normal dependency:

```toml
[dependencies]
greater-spire = { path = "../lair/greater-spire" }

[dev-dependencies]
greater-spire = { path = "../lair/greater-spire", features = ["test-utils"] }
```

With that setup, ordinary `cargo test` exposes the helper without a command-line
feature flag or `static-ca`. An upstream `cfg(test)` constructor would not work:
dependencies are not compiled with `cfg(test)` for downstream tests.

```rust
# #[cfg(feature = "test-utils")]
# {
use greater_spire::{AuthenticatedPeer, SpiffeId};

let caller: SpiffeId = "spiffe://fleet.test/service/nexis".try_into().unwrap();
let peer = AuthenticatedPeer::for_test(caller, 4_102_444_800);
// Inject into a request sent directly to your application router.
let mut request = http::Request::new(());
request.extensions_mut().insert(peer);
# }
```

The timestamp is explicit and preserved, including past times for expiry-related
application tests. The constructor performs **no certificate authentication** and
must never identify real callers. Keep `test-utils` out of production dependency
features; Cargo features are additive, so another dependency can enable it too.
Do not gate the application's ordinary HTTP/authorization suite behind a
development-identity feature. Keep real mTLS integration tests for certificate
validation, trust, rotation, and transport expiry; synthetic peers do not test
those guarantees. Tests for a certificate-generating dev command may still need
that command's separate feature.

## Embedded SPIRE and k3s

Switch only [identity.source] and deployment addresses; keep local and peer
SPIFFE IDs stable. See [spire.toml.example](examples/spire.toml.example):

```toml
[identity.source]
kind = "embedded_spire"
server_address = "spire-server.identity.svc.cluster.local:8081"
bootstrap_bundle_path = "/etc/greater-spire/bootstrap.pem"
state_dir = "/var/lib/greater-spire/nexis-agent"
join_token_file = "/run/secrets/spire/join-token"
```

This provider embeds one SPIRE agent inside each service. It talks directly to
stock **SPIRE v1.15.3**, using its private agent protocol. No Workload API socket,
sidecar, or external agent process is required. The private protocol has no
version negotiation: retain the exact server pin until integration tests pass
against a newer version. Bindings use protox; system protoc is unnecessary.

Provision a pinned bootstrap bundle, enable the server's join_token attestor,
and register the workload under the enrolled agent:

```sh
spire-server token generate -spiffeID spiffe://fleet.test/nodes/nexis-1 -ttl 600 -output json
spire-server entry create -parentID spiffe://fleet.test/nodes/nexis-1 -spiffeID spiffe://fleet.test/service/nexis -selector unix:uid:1000
```

Each replica needs its own enrollment token, agent identity, and persistent
state. Workload IDs can be shared by equivalent replicas. expected_selectors
filters authorized entries; it does not independently attest the host process
or Kubernetes service account. A Workload API provider for stock Kubernetes
attestation can be added later behind the same runtime API.

Startup waits for a valid workload identity. The agent persists its own renewed
identity before first use, refreshes workload certificates and domain-bound
bundles, and zeroizes its in-memory join token. The token file may be removed
after enrollment; persisted state supports restart. Agent state contains secrets
and retains the original restrictive state-store permissions.

Workload certificates are currently held in memory. An embedded-provider restart
requires a reachable SPIRE server, even with persisted agent state. An expired
agent identity requires fresh enrollment; the provider never falls back to files.

Moving to k3s and adopting SPIRE are independent: mounted file credentials also
work in Kubernetes. When changing issuers, preserve a common trusted root (for
example via a SPIRE upstream authority), or explicitly provision overlapping
trust on both sides before switching and retiring the old root. Matching SPIFFE
IDs alone do not establish trust. Embedded bundle refresh is authoritative from
SPIRE, so any overlap must also be represented in its managed bundle. Kubernetes
Services should pass service mTLS through to the receiving workload.

## Migration from sovereign-spire

- Package/directory: greater-spire; Rust import: greater_spire.
- Prefer Config + IdentityRuntime over initializing EmbeddedAgent directly.
- Replace identity.acceptor(policy) with identity.acceptor() and authorize
  requests in the receiving application.
- Connect/accept return AuthenticatedPeer; use peer.spiffe_id().
- Old policy helpers exist only in greater_spire::policy with the optional
  legacy-policy feature. They are not used by the runtime, TLS, or new TOML schema.
- Low-level AgentConfig and EmbeddedAgent remain available. The old
  [agent.toml.example](examples/agent.toml.example) is only for that API.

## Verification

```sh
cargo fmt --check
cargo test --all-features --all-targets
cargo test --all-features --doc
cargo test --no-default-features --features test-utils --test test_utils
cargo check --no-default-features --all-targets
cargo clippy --all-features --all-targets -- -D warnings
```

Tests cover issuer import, SVID validation, wrong peers and roots, atomic
publication, projected secrets, expiry, pool reuse, rotation, and application
authorization after authentication. Lifecycle tests cover status subscriptions,
refresh failure/recovery, expiry timers, and HTTP/1 and HTTP/2 draining of idle
connections, accepted requests, and streaming responses within authentication
limits. Live SPIRE tests are ignored by default;
they require operator-provisioned stock-server configuration. See
[tests/stock_spire.rs](tests/stock_spire.rs) for environment variables and setup.
