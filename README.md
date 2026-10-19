# Cognous Open Control Stack verifier

Independent checker for the run records an Open Control Stack workflow leaves behind. Status: pre-release and on hold; not in the hub component lock (label: **merged**; contracts stay `0.1.0-draft`). It is for people who want a second reading of a run record that does not rely on the stack's own code: reviewers, qualification authors and operators of the synthetic reference workflow.

This repository holds the independent verifier for the Open Control Stack. It reads the records a run leaves behind and checks them without using any of the stack's own code: its own JSON parser, its own canonical form, standard library only. It reports whether the record is internally consistent and which parts it could not check; detection rates are measured by the qualification repository and are not reported here (the report's `mutation_report` member is always null). It is a verification report, not an attestation or certification. It cannot show that a decision was right, that a destination really did or did not act, or who produced the record. Pre-release; nothing here is published.

Status: pre-release, on hold (see `release-state.json`); nothing is published and there are no tags. The design this repository implements is `docs/engineering/INDEPENDENT-VERIFIER-DESIGN.md` in `cogno-us/open-decision-evidence-standard` (stages S2 to S4 are built here, and tier V3 witness re-derivation, which the design deferred; the report contract, the mutation corpus and the mutation report are owned by other repositories).

## At a glance

| | |
|---|---|
| What it is | A command line tool (`cognous-verify`) and a Python package (`cognous_verify`) that parse a run record and report, per check, `confirmed`, `could_not_check` or `refuted`. |
| Who it is for | Reviewers and engineers who hold a run record and want an independent consistency reading of it. |
| What it never does | Decide, grant, sign or attest. See [What it will not do](#what-it-will-not-do). |
| Dependencies | None at run time (standard library only). Python 3.11 or later. |
| Where it sits | Tooling and qualification side group of the stack; the mutation corpus that measures detection lives in the qualification repository. |

## Where it fits

<!-- stack-map-block:start -->
The Open Control Stack has five hub groups plus a cross-cutting exchange component and two side groups. This is the same map as the hub [stack map](https://github.com/cogno-us/cognous-open-control-stack/blob/main/docs/stack-map.md); names are defined in [naming](https://github.com/cogno-us/cognous-open-control-stack/blob/main/docs/naming.md), and commands and profiles per repository are in [profiles and tools](https://github.com/cogno-us/cognous-open-control-stack/blob/main/docs/profiles-and-tools.md). The map is for navigation; it is not an execution sequence and it selects nothing. Selected revisions come only from the hub `component-lock.json`.

| Group | Members |
|---|---|
| 01 Knowledge & Provenance | [Evidence Registry (The Index)](https://github.com/cogno-us/cognous-evidence-registry), [Evidence Attestation (BitRep)](https://github.com/cogno-us/cognous-evidence-attestation) |
| 02 Institutional Governance | [Institutional Governance (Alvorada)](https://github.com/cogno-us/cognous-institutional-governance) |
| 03 Declaration & Policy Control | [Action Manifest](https://github.com/cogno-us/cognous-action-manifest), [Control Plane](https://github.com/cogno-us/cognous-control-plane) |
| 04 Constrained Execution | [Execution Runtime](https://github.com/cogno-us/cognous-execution-runtime) |
| 05 Replay & Evidence | [Replay Bundle](https://github.com/cogno-us/cognous-replay-bundle), [Governance Evidence Pack](https://github.com/cogno-us/cognous-governance-evidence-pack), [ODES](https://github.com/cogno-us/open-decision-evidence-standard) |
| Cross-cutting exchange | [Governed Exchange (GAX/IMX)](https://github.com/cogno-us/cognous-governed-exchange) |
| Optional reasoning protocols (side group) | [PRP](https://github.com/cogno-us/portable-reasoning-protocol), [Research Intelligence Protocol](https://github.com/cogno-us/research-intelligence-protocol), [TFA Protocol](https://github.com/cogno-us/truth-freedom-agency-protocol) |
| Tooling and qualification (side group) | [Ergonomics (`cognous-ocs`)](https://github.com/cogno-us/cognous-open-control-stack-ergonomics), [Verifier](https://github.com/cogno-us/cognous-open-control-stack-verifier), [Orchestrator](https://github.com/cogno-us/cognous-stack-orchestrator), [Qualification](https://github.com/cogno-us/cognous-stack-qualification) |

Status labels used in this repository's tables: **merged** (reviewed and merged in the owning repository; not by itself selected), **selected** (pinned in the hub component lock), **known limit** (a limitation that existing documentation already states), **proposed** (draft or planned work, not a supported interface). Last checked against `component-lock.json` at hub commit `dcc9bd7533ef`; refresh at the pin round.
<!-- stack-map-block:end -->

This repository is in the **Tooling and qualification** side group. It reads records produced by the control plane (and the orchestrator's overlay runs) and does not import any stack code. The hub does not select it; it is documented here and in the hub [stack map](https://github.com/cogno-us/cognous-open-control-stack/blob/main/docs/stack-map.md).

## Install and quick start

The package is not published (nothing is published and there are no tags), so install from a checkout. This was run from a clean checkout in a scratch virtual environment (Python 3.13); the run takes well under a second.

```bash
git clone https://github.com/cogno-us/cognous-open-control-stack-verifier
cd cognous-open-control-stack-verifier
python -m venv .venv && . .venv/bin/activate
pip install .
cognous-verify --version
```

Expected: `cognous-verify 0.1.0`, exit 0. `--help` and `--version` exit 0 without verifying anything; that 0 is not an accept.

Verify one bundled synthetic run (a record, its proposal export, its manifest and its destination ledger snapshot):

```bash
cd tests/data/real-runs/default-applied
cognous-verify bounded-run-record.json --proposal proposal.json --manifest manifest.json --ledger destination.json
echo "exit=$?"
```

Expected output (the last line is yours to read, not part of the tool output):

```text
overall: accept (derived from the checks that ran; not a score, not an attestation)
checks: 32; confirmed 32, could not check 0, refuted 0
tier V3 (witness re-derivation) not run: no witness or holder inventory supplied
not applicable to this record: 3 checks
note: ledger completeness is not established: the ledger has no sequence number, chain or signature, so a dropped tail, a consistent rewrite, or a decision that never reached the ledger cannot be seen
does not prove: see does_not_prove in the report
exit=0
```

Two more runs show the other outcomes. With only the run record, the checks that need the outside inputs report `could_not_check`, the overall outcome is `abstain` and the exit code is 3 (the first lines read `overall: abstain` and `checks: 29; confirmed 15, could not check 14, refuted 0`). A record that disagrees with its proposal export is `reject` with exit code 1, for example `REFUTED v2.identity.run-id` with finding `run_id_mismatch` when the `run_id` of the record is edited in a copy.

What this does not show: an accepted report says the supplied records agree with each other under the checks in [what each tier checks](docs/tiers.md). It does not say the decision was right, that the destination acted, or who produced the record.

Add `--out FILE` to write the JSON report, `--json` to print it, and `--witness FILE` or `--holder-inventory FILE` to run tier V3.

## Command and exit codes

Options beyond the inputs: `--out FILE` (write the JSON report), `--json` (print it), `--controller-revision REV`, `--source-revision REV`, `--generated-at TIME` and `--version`.

| Exit code | Meaning |
|---|---|
| 0 | accept: every check that ran is confirmed |
| 1 | refuted: at least one check is refuted |
| 2 | usage or input error; nothing was verified |
| 3 | abstain: nothing refuted, but some checks could not be made |
| 4 | crash; no report is written |

`cognous-verify RUN_RECORD [--proposal F] [--manifest F] [--ledger F] [--witness F] [--holder-inventory F]`. Exit codes: 0 accept, 1 refuted, 2 usage or input error (including the same input file named twice), 3 abstain, 4 crash. `--help` and `--version` also exit 0 without verifying anything or writing a report; that 0 is not an accept. Each decision and refusal row is resolved against the reason registry its own `reason_vocabulary_version` names (`runtime-authority-reasons/0.1` or `/0.2`, both vendored; absent means 0.1). `docs/tiers.md` has the per-tier checks, the profile sidecar checks (which cover only the members their rules read, not host configuration) and the known limits, including that the destination ledger snapshot is not covered by the witness. Everything is `0.1.0-draft`.

## What it checks

| Tier | Needs | Checks | Label |
|---|---|---|---|
| V1 wire and structure | the run record | strict JSON parse; closed member sets, enumerations and patterns from the vendored contract schema | merged |
| V2 internal consistency | the run record (identity checks also need a proposal export; the manifest is optional) | journal, decision, refusal, attempt and profile rules; identity recomputation; per-row reason registry resolution | merged |
| V3 witness re-derivation | `--witness` and/or `--holder-inventory` | the witness digests match the supplied records; holder inventory shape | merged |
| V4 receipts | `--ledger` | the destination ledger snapshot agrees with the record's decisions and attempts | merged |
| Profile sidecar (`v2.profile.*`) | the run record | operation identity, rule revision and freshness members, only where the record carries them | merged |

The full list of checks, codes and known limits is in [docs/tiers.md](docs/tiers.md). Inputs are the run record (JSON), optional proposal exports, run manifest, destination ledger snapshot, witness records (one JSON object per line) and holder inventory. The report follows the ODES `verification-report` contract `0.1.0-draft`; a consumer that decides on a report reads the decision-facing members described in [docs/tiers.md](docs/tiers.md#decision-facing-output), not the diagnostic text.

## What ships

| Item | What it is | Label |
|---|---|---|
| `src/cognous_verify/` | The package: own strict parser (`wire`), own canonical form (`canon`), tier rules, report writer, command line. Standard library only. | merged |
| `cognous-verify` | The command line (see above). | merged |
| `src/cognous_verify/data/` | Vendored contract schemas (`control-plane-journal`, `execution-attempt-lifecycle`), the two reason registries (`runtime-authority-reasons` 0.1 and 0.2) and the post-journal gate code set, with source revisions and digests in `PROVENANCE.json`. Copied, never imported. Re-read at the pin round. | merged |
| `tests/` and `tests/data/` | The test suite, vendored ODES contract oracles with fixtures, and captured synthetic runs (`real-runs`, `orchestrator-runs`, `witnessed-runs`). | merged |
| `scripts/check_claim_boundaries.py` | Refuses forbidden claim wording while `release-state.json` is on hold. | merged |
| `tools/` | Development tools, not shipped: `capture_real_runs.py`, `capture_witnessed_runs.py` and `capture_cp_differential.py` (run the stack to produce inputs; need a control plane checkout), `damage_selfcheck.py` and `deletion_corpus.py` (probes of the verifier's own checks), `make_canon_vectors.py`, `vendor_oracle.py`. | merged |
| `release-state.json` | The hold record: publication and production are not authorized. | known limit |

Status labels are defined in the stack map block above.

## Known limits

These are stated in detail in [docs/tiers.md](docs/tiers.md#not-checked-by-these-tiers); the short form:

- **known limit** A record whose affected commitments were all recomputed consistently after tampering is accepted (the forgery bound).
- **known limit** Journal integrity (counts, order and bindings agreeing) does not show that any row was durably stored or retained.
- **known limit** Ledger completeness cannot be seen: a dropped tail, a consistent rewrite, or a decision that never reached the ledger. The ledger snapshot is not covered by the witness.
- **known limit** Single-row deletions that nothing else in the record corroborates are accepted; the list is in [docs/tiers.md](docs/tiers.md#single-row-deletions-known-limit).
- **known limit** Completion reasons are a floor: a completed check must carry the reasons its own recorded input events imply, but the required-input list is not recorded, so `required_input_not_read` is not required.
- **known limit** The runtime sqlite export is not read; only the control plane local destination snapshot is.

## Not built here

The mutation corpus, its operators and the mutation report belong to the qualification repository; `tests/damage.py` here is a smoke check written alongside the verifier and is not a detection measurement. See `docs/tiers.md` for what each tier checks.

## What it will not do

- It imports nothing from the stack and has no third-party dependency. The package and its tests do not import stack code; the tests load the vendored ODES reference validators by path as outside oracles.
- It reports three-valued results per check (confirmed, could not check, refuted) with a tally of `n` items of a stated unit per check (a check over zero items is reported as one `could_not_check` item). It never computes a composite score.
- It does not attest, certify, sign, authorize or deny anything. A report is never an input to a grant or a decision.
- It does not claim that a decision was correct, that a policy was adequate, that a ledger is complete or unforged, that an effect occurred in the world, or that a record was not omitted before export. A record whose commitments were all recomputed consistently after tampering is accepted (the forgery bound).

## Tests and checks

```bash
pip install -e ".[dev]"
make check      # lint, strict types, tests with sockets off (80% coverage floor), claim-boundary check
```

## Documentation

- [docs/README.md](docs/README.md): documentation index and reading paths.
- [docs/tiers.md](docs/tiers.md): what each tier checks and what it does not.
- [docs/history.md](docs/history.md): the build phases.
- The design this repository implements is `docs/engineering/INDEPENDENT-VERIFIER-DESIGN.md` in `cogno-us/open-decision-evidence-standard` (stages S2 to S4 are built here, and tier V3 witness re-derivation, which the design deferred; the report contract, the mutation corpus and the mutation report are owned by other repositories).

## Licence

Apache-2.0. See `LICENSE`.
