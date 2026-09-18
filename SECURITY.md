# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 1.1.x | Yes |
| 1.0.x | Best-effort (security fixes may require upgrade to 1.1.x) |
| &lt; 1.0 | No |

## Reporting a vulnerability

Please report security issues privately to the A3S Lab maintainers via GitHub
Security Advisories for [A3S-Lab/Gateway](https://github.com/A3S-Lab/Gateway)
when available, or by contacting the maintainers through the organization
security channel. Do not open a public issue for undisclosed vulnerabilities.

Include: affected version, reproduction steps, impact, and any proof-of-concept
that stays within legal test environments you own or are authorized to test.

## Scope notes

Gateway is a local data plane. Cloud control-plane, Power observation delivery,
and Box/MicroVM substrates have their own boundaries — see
[`docs/threat-model.md`](docs/threat-model.md) and [`ROADMAP.md`](ROADMAP.md).
