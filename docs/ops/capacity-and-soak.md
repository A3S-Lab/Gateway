# Capacity envelopes and soak evidence

Enterprise GA gate: publish **dedicated-hardware** capacity envelopes and
**long-duration** soak results for HTTP, streaming, and model workloads.

This document defines the contract and the local harness. Short smoke runs
prove the harness works; they are **not** published capacity envelopes.

## Relationship to existing matrices

| Artifact | Role | Not a substitute for |
| --- | --- | --- |
| Same-host protocol matrix (`benchmarks/`) | Regression / comparison | Dedicated-hardware envelopes |
| AI token-aware comparison | Feature-on streaming evidence | Multi-hour soak / capacity claims |
| `scripts/soak-wire.sh` | Optional `wire` feature soak | Core data-plane soak |
| `scripts/soak-gateway.py` (this gate) | Core HTTP + SSE soak harness | Published envelopes until hardware-pinned |

## Profiles

| Profile id | Traffic | Default smoke | Envelope candidate durations |
| --- | --- | ---: | --- |
| `http-json` | GET keep-alive JSON via Gateway → local upstream | 30s | 2h, 24h |
| `sse-finite` | Finite SSE stream relay | 30s | 2h, 24h |
| `openai-json` | POST `/v1/chat/completions` JSON (standalone PathPrefix proxy) | 30s | 2h, 24h |
| `openai-sse` | POST `/v1/chat/completions` SSE with `[DONE]` | 30s | 2h, 24h |

OpenAI-shaped profiles exercise transport through Gateway to a deterministic
local upstream. They do **not** invent cloud-managed inference policy.

Lab-extended runs use `--envelope-status lab-extended` via
`scripts/run-soak-gateway-extended.{sh,ps1}` (default 120s). Draft table:
[`capacity-envelope-draft.md`](capacity-envelope-draft.md).

Until results come from a dedicated runner, mark JSON
`"envelope_status": "smoke-only"` or `"lab-extended"` — never `"published"`.
Committed `smoke-*.json` must stay `smoke-only` and
`hardware.dedicated_runner: false` (omitting the flag is a soft-open).
Committed lab and smoke JSON must keep schema `a3s.gateway.soak-result.v1`,
`pass: true`, `requests.err=0`, and `requests.ok_per_sec` equal to
`round(ok/duration_secs, 2)`.
Smoke wrappers pin `--envelope-status smoke-only`; lab-extended wrappers pin
`lab-extended`; published wrappers pin `published` plus dedicated-runner env and
a 7200s floor that `A3S_GATEWAY_PUBLISH_MIN_DURATION` cannot lower.
Every wrapper must keep all four profiles
(`http-json`, `sse-finite`, `openai-json`, `openai-sse`).
`check-enterprise-ga-status.py` refuses wrapper soft-opens that drop those pins
or profiles, and refuses `dedicated-hardware-envelopes.md` soft-opens that drop
publish honesty Non-goals.

## Pass / fail (harness)

A soak **fails** if any of:

1. Gateway process exits during the run
2. Successful requests are zero
3. Error rate exceeds 1% of successful requests (smoke) or the envelope table’s stated budget
4. On platforms that sample RSS: steady-state RSS growth exceeds 1.5× after warm-up (possible leak)

A soak **passes** only when the process stays up and budgets hold. Passing a
30s smoke does **not** authorize capacity marketing numbers.

## Hardware pin fields (required for published envelopes)

Record in every published JSON under `benchmarks/soak/results/`:

- `hardware.host`, `cpu_model`, `cpu_cores`, `memory_gb`, `os`, `kernel`
- `gateway.version` (from `a3s-gateway --version`) and `git_sha`. The sha is the
  commit embedded in that version string, not `git rev-parse HEAD` and not
  `GITHUB_SHA`. A dirty build (`-dirty`) or a binary with no embedded sha is
  `publish-refused`, not `published`. `features` is recorded as well.
- `profile`, `duration_secs`, `concurrency`
- `requests.ok`, `requests.err`, `rss` samples (when available)
- `pass` boolean and `fail_reasons[]`

Until those fields come from a dedicated runner with multi-hour evidence, mark
results `"smoke-only"` or `"lab-extended"` — never `"published"`.

## How to run smoke

From the Gateway crate root:

```bash
cargo build --bin a3s-gateway
python3 scripts/soak-gateway.py --bin ./target/debug/a3s-gateway --duration 30 --concurrency 16
# Windows
python scripts/soak-gateway.py --bin .\\target\\debug\\a3s-gateway.exe --duration 30 --concurrency 16
```

Wrappers: `scripts/run-soak-gateway-smoke.sh`, `scripts/run-soak-gateway-smoke.ps1`.

## Still open for Enterprise GA

- Multi-hour runs on pinned dedicated hardware
- Published envelope tables (req/s, P99, RSS ceiling) per profile
- Independent sign-off that envelopes match operator runbooks
