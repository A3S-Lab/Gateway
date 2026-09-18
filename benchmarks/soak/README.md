# Soak result schema

JSON files under `results/` follow this shape. Smoke artifacts use
`envelope_status: "smoke-only"`. Published dedicated-hardware envelopes must
set `envelope_status: "published"` and fill every hardware pin field.

```json
{
  "schema": "a3s.gateway.soak-result.v1",
  "envelope_status": "smoke-only",
  "profile": "http-json",
  "duration_secs": 30,
  "concurrency": 16,
  "hardware": {
    "host": null,
    "cpu_model": null,
    "cpu_cores": null,
    "memory_gb": null,
    "os": "windows",
    "kernel": null
  },
  "gateway": {
    "version": null,
    "git_sha": null,
    "features": [],
    "bin": "target/debug/a3s-gateway"
  },
  "requests": { "ok": 0, "err": 0 },
  "rss_kb": { "min": null, "max": null, "growth": null, "samples": 0 },
  "pass": true,
  "fail_reasons": []
}
```

Do not treat smoke-only JSON as a capacity promise in README or marketing.
