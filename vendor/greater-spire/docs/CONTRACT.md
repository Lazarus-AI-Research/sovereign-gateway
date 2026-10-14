# Identity and RPC contract

This describes library behavior, independently of repository layout, dependency
delivery, installer implementation, or application authorization.

## Identity providers and startup

`IdentityRuntime` owns refresh and transport lifetime. Retain one runtime per
local workload identity through its in-flight requests. Dropping or shutting it
down invalidates the associated transports. `IdentitySource::from_pem` supplies
the same transport interface without a refresh task; it does not renew anything.

The files provider validates an immutable generation containing the leaf key,
chain and trust bundle. Missing/invalid initial material fails startup. Reloads
are serialized, and candidates are checked again for validity at publication.
A failed reload cannot displace usable last-known-good material. Successful
publication after expiry restores usability without a new runtime. Issuance,
renewal scheduling and CA signing keys remain outside application processes.

The embedded provider uses join-token enrollment per replica and persists its
agent identity. It always contacts SPIRE at startup to obtain a workload SVID,
including after a restart with valid persisted agent state. Agent state is not an
offline workload-credential cache. An expired persisted agent lease requires new
enrollment; invalid state fails closed. The original consumed join token is not
needed for an ordinary restart. Do not share a node state directory between replicas.

SPIRE's reported SVID expiration must match its leaf certificate. Certificate
chains must be currently valid. Workload renewal considers the earliest chain
expiration, not just the leaf, and registration revision changes. A successful
refresh may reuse the existing certificate: it is not proof of actual renewal.

The applied workload registration revision is part of the same immutable
generation as its credentials. Expiry or shutdown rejection leaves both the old
credentials and their revision in place; the next refresh still treats the new
registration revision as unapplied. Agent recovery state is separate: a renewed
agent key must be persisted before the first RPC that presents it, even if later
workload publication fails. Workload publication must not roll back that state.

This provider speaks the private protocol pinned to stock SPIRE **1.15.3**. Its
selectors filter registration entries; they do not independently attest the
local process or Kubernetes service account. Standard Workload API support or a
different attestation model is a separate requirement if a deployment needs those
guarantees. Kubernetes alone does not require changing from file credentials.

## Failure, availability, and revocation

`usable`/`ready` report credential usability; `refresh` reports renewal health.
Neither grants application permission. A watch is a latest-state notification,
not a durable event log or a real-time scheduling guarantee. Clone watch borrows
before awaiting. A receiver closing must not leave application readiness true.
Transport checks still apply regardless of the last readiness snapshot.

| Condition | Signal | Transport consequence and recovery |
| --- | --- | --- |
| Files missing, malformed, or wrong identity on reload | Refresh error and first/latest failure times | Retain old credentials; new connections can still succeed until their validity ends. Publish a valid generation to recover. |
| SPIRE unavailable, registration removed, or refresh otherwise fails | Refresh error while the workload can remain usable | Retain the issued workload SVID until expiry. Restore connectivity/registration for renewal; removing registration does not revoke an already-issued certificate. |
| Embedded restart while SPIRE is unavailable | Startup error; no runtime handle | Restore SPIRE before restarting successfully. No fallback to file credentials occurs. |
| Persisted agent lease expired | `AgentIdentityExpired` without a new enrollment token | Obtain a new authorized enrollment token; do not reuse the consumed token or silently replace identity/trust. |
| Current credential chain expires | `usable = false`; expiry notification independently of refresh | New transport use fails; active connections are bounded by the certificates they presented. A valid renewal restores new connections. |
| Application pre-expiry lead time reached | Application-owned readiness/admission state | Stop admission against `valid_until_unix` minus the lead time; rearm on identity updates. This does not change the certificate's validity. |
| Maximum connection age reached | Connection lifetime error | Close that connection. A new connection can authenticate again with a still-valid certificate. |
| Validated trust bundle changes | Publication/refresh update | Existing connections reject subsequent I/O and request dispatch on that runtime. New handshakes use the new trust. |
| Runtime shutdown/drop | `usable = false`; stopped identity errors | Transport handles become unusable. Complete graceful draining first if desired. |

**Maximum connection age is not a revocation deadline.** It bounds a connection,
not the lifetime of a caller's certificate. Deleting the caller's files, removing
registration, or stopping its legitimate process does not invalidate copies of
the key and certificate held elsewhere.

Emergency exclusion must be enforced at receivers: application caller denial or
appropriate trust withdrawal, with an explicit propagation/reload bound. Trust
withdrawal affects all identities relying on that authority, not just one caller.
The library does not provide a per-SVID revocation list or application policy
reload. Application permissions and admission must be checked for each request,
including requests on existing connections.

Trust invalidation prevents further authenticated network use; it does not roll
back a request already accepted by the application. Certificate expiry and drain
deadlines likewise do not establish whether an in-flight mutation committed.
Keep host clocks synchronized; wall-clock certificate validation and scheduled
Tokio timers are not a distributed transaction or instantaneous revocation system.

## Trust migration

Matching SPIFFE IDs signed by unrelated authorities do not interoperate. For a
two-root migration within the same trust domain:

1. Distribute and validate the overlapping old/new bundles at **both receivers**
   while their existing leaf credentials still work. Bundle publication can end
   existing connections, so clients must be prepared to establish new ones.
2. Renew one side under the new authority while retaining overlap. Verify actual
   authenticated requests with the other side, then rotate that side too.
3. After all relevant peers use the new issuer, remove the old authority from
   every relevant bundle. Verify new-issued peers still work and old-issued peers
   cannot reconnect.

Do not remove a root still needed to validate a runtime's own active certificate:
that generation is rejected and the previous bundle remains in effect. This
fail-safe behavior is why publication success and fleet convergence must be
observed, not assumed. During provider migration, a common upstream authority can
avoid a root change. Embedded bundle refresh is authoritative from SPIRE; managed
overlap must also be represented there. File bundles are bound to the local trust
domain, not inferred cross-domain federation.

## HTTP requests, errors, and response bounds

`HttpClient` binds one HTTPS origin to one exact expected SPIFFE ID. It does not
follow redirects, use environment proxies, or retry canceled requests. HTTP error
status codes remain responses for the application to handle; they are not TLS
authentication errors. A successful TLS handshake or HTTP status alone is not a
successful application operation or a valid receipt.

Connection/handshake and response-header timeouts have explicit `TimeoutPhase`
values. The HTTP request timeout covers the operation through response headers;
it does **not** bound the complete response body. Connection authentication/age
limits continue to bound underlying I/O, but applications must impose shorter
body time and size limits appropriate to each operation. Count bytes as frames
arrive; checking after an unbounded collect is too late. Do not trust
Content-Length as a limit. If adding decompression, bound the decoded size too.

Network, handshake, SPIRE connection, HTTP request and HTTP connection errors
retain their sources. `Error::find_cause::<T>()` finds a typed cause and
`Error::causes()` walks all causes, including I/O payloads and rustls custom
certificate errors that standard `source()` alone can omit. These helpers never
interpret diagnostic strings. Legacy `Transport(String)`/`Tls(String)` variants
remain, but live connection errors now use the sourced variants.

Useful classifications include `PeerIdentityError::Mismatch`, other
`PeerIdentityError` variants, `rustls::Error::InvalidCertificate`, `TimeoutPhase`,
and `std::io::Error`. An identity in a mismatch diagnostic is an unverified
certificate claim, not an authenticated caller. `Stopped`/`IdentityExpired` can
occur directly or under another error; use the complete cause iterator if several
layers share the `Error` type. Do not disable peer verification to recover from
an authentication error.

Handler errors remain local. In HTTP/2, an application failure can reset one
stream without failing the connection future. Applications should record their
own per-request errors or map them to their response schema; a connection result
is not a request-level error log.

Timeouts, connection failures after dispatch, interrupted bodies, and malformed
receipts can leave a mutation's outcome **unknown**. This API deliberately offers
no generic `is_retryable()` or automatic mutation retry. The application owns
idempotency keys, exact-payload replay and reconciliation. Never infer an
uncommitted write from a missing response or a response-body error.

The runnable [service client example](../examples/service_client.rs) retains a
runtime and pooled HTTP client, observes status, reads VKG's capabilities into an
application-owned typed view, and bounds response bytes/time before decoding.
It performs only a read and shuts down on success or error. It is an example,
not a VKG SDK or a complete VKG
schema. Production clients must use their selected API contract and check required
capabilities; capability flags describe support, not authorization.

Retain and clone the client for repeated operations. Calling `http_client("vkg")`
again creates an independent pool, not another handle to the existing pool.

## Validation boundaries

Maintained local tests cover real mTLS, wrong peer/issuer errors, response/drain
bounds, reload failure and recovery, removed files, expiration, two-peer root
overlap and retirement, offline embedded startup with persisted state, expired
agent lease handling, renewal decisions, and revision consistency across rejected
and successful workload publications. These tests do not constitute a
live SPIRE deployment qualification or exercise Scribe/VKG application workflows.

The operator-provisioned `stock_spire` test covers live enrollment, refresh,
interoperation and token-free restart when explicitly configured. It is ignored
otherwise. Refresh success alone must not be reported as certificate renewal.
Before selecting the embedded provider for production, verify actual **agent and
workload** renewal against the pinned server (changed certificate/key material),
plus server outage/recovery, expired-state reenrollment, removed/recreated
registration, and managed trust-bundle rotation. Record the exact version and
results; local decision/state tests are not substitutes for these live checks.
