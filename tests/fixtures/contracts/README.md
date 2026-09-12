# Frozen cross-product contract snippets

These files are **Gateway-owned lock fixtures** for I0.2b / I0.2c / I0.3 schema
ids. Standalone Gateway CI cannot `include_str!` into sibling monorepo crates
(`apps/cloud`, `crates/power`), so the published constant lines live here.

They are not a substitute for provisioned Cloud/Power EXIT. When updating a
schema id in Cloud or Power, update the matching fixture and Gateway constant
in the same change set.
