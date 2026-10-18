# Cognous Open Control Stack verifier

This repository holds the independent verifier for the Open Control Stack. It reads the records a run leaves behind and checks them without using any of the stack's own code: its own JSON parser, its own canonical form, standard library only. It reports whether the record is internally consistent, which parts it could not check, and how well it catches deliberately damaged records, with the counts shown for each category. It is a verification report, not an attestation or certification. It cannot show that a decision was right, that a destination really did or did not act, or who produced the record. Pre-release; nothing here is published.

Status: pre-release, on hold (see `release-state.json`); nothing is published and there are no tags. The design this repository implements is `docs/engineering/INDEPENDENT-VERIFIER-DESIGN.md` in `cogno-us/open-decision-evidence-standard` (stages S2 to S4 are built here, and tier V3 witness re-derivation, which the design deferred; the report contract, the mutation corpus and the mutation report are owned by other repositories).

## Phases

Each phase lands as its own small pull request.

| Phase | Content | State |
|---|---|---|
| 0 | Bootstrap: licence, this README, `.gitignore` | done |
| 1 | Strict JSON parser and canonical form (pinned profile, no migration) | done |
| 2 | Tier V1 (wire and structure) and tier V2 (consistency of the record) | done |
| 3 | Tier V2 identity recomputation from a proposal export; tier V4 ledger comparison | done |
| 4 | Command line (`cognous-verify`), report output | done |
| 5 | CI, claim-boundary check, release-state hold | done |
| 6 | Tier V3: witness re-derivation and holder inventory shape (`--witness`, `--holder-inventory`) | this change |

## Not built here

The mutation corpus, its operators and the mutation report belong to the qualification repository; `tests/damage.py` here is a smoke check written alongside the verifier and is not a detection measurement. See `docs/tiers.md` for what each tier checks.

## What it will not do

- It imports nothing from the stack and has no third-party dependency.
- It reports three-valued results per check (confirmed, could not check, refuted) with explicit denominators. It never computes a composite score.
- It does not attest, certify, sign, authorize or deny anything. A report is never an input to a grant or a decision.
- It does not claim that a decision was correct, that a policy was adequate, that a ledger is complete or unforged, that an effect occurred in the world, or that a record was not omitted before export. A record whose commitments were all recomputed consistently after tampering is accepted (the forgery bound).

## Licence

Apache-2.0. See `LICENSE`.
