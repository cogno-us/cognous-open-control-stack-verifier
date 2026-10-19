# Build phases

Historical record, moved here from the README. All phases are done; the repository is pre-release and on hold.

Each phase lands as its own small pull request.

| Phase | Content | State |
|---|---|---|
| 0 | Bootstrap: licence, this README, `.gitignore` | done |
| 1 | Strict JSON parser and canonical form (pinned profile, no migration) | done |
| 2 | Tier V1 (wire and structure) and tier V2 (consistency of the record) | done |
| 3 | Tier V2 identity recomputation from a proposal export; tier V4 ledger comparison | done |
| 4 | Command line (`cognous-verify`), report output | done |
| 5 | CI, claim-boundary check, release-state hold | done |
| 6 | Tier V3: witness re-derivation and holder inventory shape (`--witness`, `--holder-inventory`) | done |
| 7 | Profile sidecar checks (`v2.profile.*`: operation identity, rule revision, freshness) and reason registry labels 0.1 and 0.2 | done |
