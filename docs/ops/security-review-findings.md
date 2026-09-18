# Security review findings

<!-- enterprise-ga: review_status=unsigned -->

**Status: unsigned.** Independent security review has not signed off.

This file is the fail-closed landing place for review findings. Do **not** set
`review_status=signed` or mark the checklist security-review gate **Landed**
until an independent reviewer has delivered written findings and remediation
evidence is linked below.

Package for reviewers: [`security-review-package.md`](security-review-package.md).
Continuous dependency evidence (`cargo audit`) is **not** a review sign-off.

## When signing (dedicated process only)

Replace the HTML comment above with:

```text
<!-- enterprise-ga: review_status=signed -->
```

And fill:

| Field | Value |
| --- | --- |
| Reviewer / firm | |
| Review date | |
| Scope revision (git SHA / version) | |
| Report link (private OK) | |
| Residual risks accepted | |
| Remediation PRs / CHANGELOG entries | |

Then update [`enterprise-ga-checklist.md`](enterprise-ga-checklist.md) and
ROADMAP Product maturity only after `scripts/check-enterprise-ga-status.py`
passes with this gate Landed.
