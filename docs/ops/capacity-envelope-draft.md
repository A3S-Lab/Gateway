# Capacity envelope draft (lab evidence)

**Status: not published.** Dedicated-hardware Enterprise GA envelopes remain
**Open**. This draft records lab-extended and smoke harness outputs so operators
can see the table shape without mistaking developer-machine numbers for
capacity promises.

## Envelope status legend

| `envelope_status` | Meaning |
| --- | --- |
| `smoke-only` | Short CI/local harness proof |
| `lab-extended` | Longer lab run; `dedicated_runner: false` |
| `published` | Dedicated-hardware, multi-hour, signed into ROADMAP (none yet) |

## How to regenerate lab-extended rows

```bash
cargo build --bin a3s-gateway
# default 120s × 4 profiles
./scripts/run-soak-gateway-extended.sh
# Windows: ./scripts/run-soak-gateway-extended.ps1
```

Results land in `benchmarks/soak/results/lab-*.json`. The draft table below is
checked against those files by `scripts/check-enterprise-ga-status.py` (profile,
duration, concurrency, ok/s, RSS growth, host, pass). Do not hand-edit a row
without the matching JSON.

## Draft table (latest lab-extended on this workspace)

Captured 2026-09-18 from `run-soak-gateway-extended.ps1` with
`A3S_GATEWAY_SOAK_DURATION=20`, concurrency 4, host `DESKTOP-BM5D1UH`
(`dedicated_runner: false`). **Not** a capacity promise.

| Profile | Duration | Concurrency | ok/s | RSS growth | Host | Pass | Result file |
| --- | ---: | ---: | ---: | ---: | --- | --- | --- |
| `http-json` | 20s | 4 | 612.6 | 1.03× | DESKTOP-BM5D1UH | yes | `lab-http-json.json` |
| `sse-finite` | 20s | 4 | 610.4 | 1.03× | DESKTOP-BM5D1UH | yes | `lab-sse-finite.json` |
| `openai-json` | 20s | 4 | 551.3 | 1.03× | DESKTOP-BM5D1UH | yes | `lab-openai-json.json` |
| `openai-sse` | 20s | 4 | 550.5 | 1.05× | DESKTOP-BM5D1UH | yes | `lab-openai-sse.json` |

## Still required for `published`

- Pinned dedicated runner (CPU model, cores, RAM, OS image)
- Multi-hour durations (2h / 24h) per profile
- Explicit PASS budgets signed in ROADMAP Product maturity
- No use of developer workstation rows as marketing capacity
