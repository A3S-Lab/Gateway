# Production adoption case study template

<!-- enterprise-ga: adoption_status=template -->

Enterprise GA requires **at least one representative production adoption** with
topology, workload, operating bounds, and recovery outcomes.

This file is a **template**, not a completed case study. Fill it only with a
real deployment you are authorized to document. Do not invent customers or
metrics.

When a real case study exists, copy this structure to
[`production-adoption.md`](production-adoption.md), set
`<!-- enterprise-ga: adoption_status=complete -->`, and mark the checklist gate
**Landed** only after `scripts/check-enterprise-ga-status.py` passes.

## Identity

| Field | Value |
| --- | --- |
| Organization / product | |
| Contact (optional) | |
| Gateway version | |
| Mode (`standalone` / `cloud-managed`) | |
| Date range in production | |

## Topology

- Regions / AZs:
- Replica count and placement:
- Entrypoints (protocols, TLS):
- Upstream types (HTTP, SSE, OpenAI-compatible, …):
- Dependencies (Redis, forward-auth, Docker/K8s providers):

## Workload

- Peak RPS / concurrent streams:
- Payload / stream characteristics:
- SLO targets (availability, P99 latency, error budget):

## Operating bounds

- Capacity envelope reference (`benchmarks/soak/results/…` or internal):
- Rollback path:
- Node API / metrics / paging:

## Recovery evidence

| Incident or drill | Date | Failure class | Outcome |
| --- | --- | --- | --- |
| | | listener / upstream / controller / disk / network | |

Link runbooks exercised: `docs/ops/runbooks/`.

## Sign-off

- [ ] Operator confirms numbers are from production or authorized drills
- [ ] No unpublished customer secrets in this document
- [ ] Linked soak/fault-injection evidence matches the running version
