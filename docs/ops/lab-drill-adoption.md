# Lab drill (not a production adoption)

This document records an **operator lab drill** using Gateway fault-injection
and soak harnesses. It does **not** satisfy the Enterprise GA “representative
production adoption” gate — see
[`production-adoption-template.md`](production-adoption-template.md).

## Drill identity

| Field | Value |
| --- | --- |
| Kind | Lab drill |
| Gateway mode | `standalone` |
| Evidence | Fault-injection suite + soak harness |
| Production customer | None (intentionally) |

## Topology (lab)

- Single Gateway process on a developer or CI host
- Local upstream spun by `scripts/soak-gateway.py`
- No Redis / Docker / Kubernetes required for soak profiles
- Fault-injection suite uses in-process live-listener tests
  (`--features kube,redis,wire`)
- Managed Runtime real OS-process evidence:
  `scripts/run-managed-runtime-evidence.*`
- CI `enterprise-ga-smoke` covers Linux and Windows runners

## Workload (lab)

- Profiles: `http-json`, `sse-finite`, `openai-json`, `openai-sse`
- Smoke: `scripts/run-soak-gateway-smoke.*`
- Extended lab: `scripts/run-soak-gateway-extended.*` (default 120s)

## Recovery drill map

| Failure class | Runbook | Automated proof |
| --- | --- | --- |
| Listener | [`runbooks/listener-failure.md`](runbooks/listener-failure.md) | Fault-injection suite listener cases |
| Upstream | [`runbooks/upstream-failure.md`](runbooks/upstream-failure.md) | Passive / circuit / failover cases |
| Controller | [`runbooks/controller-failure.md`](runbooks/controller-failure.md) | `validate_activation` provider cases |
| Disk | [`runbooks/disk-failure.md`](runbooks/disk-failure.md) | Spool / journal cases |
| Network | [`runbooks/network-failure.md`](runbooks/network-failure.md) | Redis / forward-auth cases |

## Sign-off

- [x] Explicitly **not** a production adoption case study
- [ ] Production adoption filled from a real deployment (separate document)
