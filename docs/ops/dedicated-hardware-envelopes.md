# Dedicated-hardware published envelopes

Enterprise GA requires **published** capacity envelopes from a dedicated
runner. Lab and smoke results must never be relabeled as published.

## Fail-closed publish gate

`scripts/soak-gateway.py --envelope-status published` refuses unless:

| Requirement | Env / arg |
| --- | --- |
| Dedicated runner flag | `A3S_GATEWAY_DEDICATED_RUNNER=1` |
| Host name | `A3S_GATEWAY_HW_HOST` |
| CPU model | `A3S_GATEWAY_HW_CPU_MODEL` |
| Memory GiB | `A3S_GATEWAY_HW_MEMORY_GB` |
| Minimum duration | hard floor **7200s**. `A3S_GATEWAY_PUBLISH_MIN_DURATION` may only raise it |

Wrappers: `scripts/run-soak-gateway-published.{sh,ps1}` (locked release binary,
default 2h × 4 profiles).

Unit proof that the gate refuses soft-opens:
`python3 scripts/test_soak_envelope_status.py`.

## Example (dedicated machine only)

```bash
export A3S_GATEWAY_DEDICATED_RUNNER=1
export A3S_GATEWAY_HW_HOST=gw-bench-01
export A3S_GATEWAY_HW_CPU_MODEL='AMD EPYC 9454 48-Core Processor'
export A3S_GATEWAY_HW_MEMORY_GB=256
export A3S_GATEWAY_SOAK_DURATION=7200
export A3S_GATEWAY_SOAK_CONCURRENCY=32
./scripts/run-soak-gateway-published.sh
```

Then:

1. Commit `benchmarks/soak/results/published-*.json` only from runs that passed
   and recorded `gateway.version` plus the 40-character lowercase commit
   embedded in `a3s-gateway --version`. A working-tree sha does not count.
   A failed run, a dirty build, or a passing run without that embedded
   identity is `publish-refused-*.json` and cannot land the gate.
   `--out` cannot rename that result to `published-*.json`.
2. Fill [`capacity-envelope-draft.md`](capacity-envelope-draft.md) published section
3. Update [`enterprise-ga-checklist.md`](enterprise-ga-checklist.md) and ROADMAP

## Non-goals

- Publishing from GitHub-hosted runners or developer laptops
- Lowering the default 2h floor to make CI green
- Inventing production adoption metrics from these envelopes
