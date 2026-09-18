# A3S Gateway threat model

Status: **authored for Production Candidate**. Independent security review and
remediation evidence are still required for Enterprise GA (see
[`ROADMAP.md`](../ROADMAP.md)).

## Scope

In scope: the Gateway binary and local data plane — listeners, routing,
middleware, health/balancing, ACL and managed-snapshot activation, Node API,
durable usage spool, standalone providers (file/Docker/Kubernetes), and local
OpenAI-compatible policy surfaces.

Out of scope (Cloud / joint EXIT): Cloud control-plane auth UX, long-term usage
ledger, Power `PW0` observation delivery, Box MicroVM, Cloud object authority
(`WEB0.1`), multi-replica Cloud rolling orchestration.

## Assets

| Asset | Sensitivity |
| --- | --- |
| Live traffic (HTTP/SSE/WS/gRPC/TCP/UDP/TLS) | Confidentiality, integrity, availability |
| ACL / managed snapshot desired state | Integrity, authenticity |
| Node API (health, metrics, version, managed apply) | Integrity, availability; may expose ops metadata |
| API keys / grants in managed inference policy | Secret material |
| Usage spool records | Integrity, bounded confidentiality (prompt-free by design) |
| TLS private keys / ACME material | Secret material |
| Provider credentials (kubeconfig, Docker host) | Secret material |

## Trust boundaries

1. **Untrusted clients** → Gateway listeners.
2. **Gateway** → upstream services (may be untrusted or partially trusted).
3. **Operators / Cloud** → Node API and snapshot apply (must authenticate).
4. **Host filesystem** → spool, ACME storage, static digests (OS isolation assumed).

## Threats and controls

| ID | Threat | Control (current) | Residual risk |
| --- | --- | --- | --- |
| T1 | Soft-open on invalid desired state | Fail-closed validate/activate; prior runtime retained | Misconfigured ACL still serves last good state |
| T2 | Upstream body returned despite response middleware failure | Response-phase fail-closed on HTTP/SSE/gRPC/OpenAI surfaces | Custom middleware bugs outside registry |
| T3 | Auth bypass when forward-auth down | Listener `502` without upstream contact | Operators may remove middleware under pressure |
| T4 | Rate-limit bypass when Redis down | Default fail-closed `503`; explicit `redis_fail_open` opt-in | Opt-in fail-open is intentional risk |
| T5 | Snapshot / journal tampering | Digest/CAS/expiry checks; corrupt journal fail-closed | Host root can still rewrite disks |
| T6 | Usage spool integrity loss | Private permissions; untracked files fail activation | Disk-full / capacity exhaustion under load |
| T7 | Node API exposure | Bind/auth configuration; mTLS client CA fail-closed | Default misbind to public interface |
| T8 | Provider label injection soft-defaults | Declared strategy/priority/timeout/port fail-closed | Unknown future label keys need the same bar |
| T9 | Credential replay after revocation | Managed snapshot succession fail-closed on request path | Clock skew on expiry |
| T10 | SSRF via upstream URLs | Server URL validation; health probe scheme checks | Operator-supplied URLs remain powerful |

## Non-goals

- Traditional WAF / L7 exploit kits (optional `wire` is LLM/MCP inspection only).
- Inventing workers or Cloud ledger semantics inside Gateway.
- Claiming Enterprise GA from this document alone.

## External review checklist

- [ ] Threat model reviewed by an independent party
- [ ] Findings tracked with remediation evidence per release
- [ ] Node API and managed-apply paths included in review scope
- [ ] Residual risks accepted or mitigated in operator runbooks

Reporting process: see [`SECURITY.md`](../SECURITY.md).
