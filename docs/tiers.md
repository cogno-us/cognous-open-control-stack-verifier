# What each tier checks, and what it does not

Verdicts are three-valued per check: `confirmed`, `could_not_check`, `refuted`. Every check
carries a denominator (`checked` of `total` items of a stated unit). There is no composite
score. A check with nothing to examine in the record is never a vacuous `confirmed`: it is
listed under `x-not-applicable` in the report (reasons `no_items_in_record`,
`no_journal_in_record`) instead of among the results, so a clean trace is not forced to
abstain. A check that lacks an input is `could_not_check` (`input_absent`,
`tier_unavailable`). A crash inside a check produces no report at all (exit code 4) and is
never counted as detection.

The command is `cognous-verify RUN_RECORD [--proposal F] [--manifest F] [--ledger F]`. Exit
codes: 0 accept, 1 refuted, 2 usage or input error, 3 abstain, 4 crash. The overall outcome is
derived from the checks (reject if any is refuted, abstain if any could not be made, accept if
all confirmed); it is not a score and not an attestation. The report follows the ODES
`verification-report` contract 0.1.0-draft.

## Tier V1: wire and structure

- `wire.*` (per input file): strict parse. Refusal codes: `wire_too_large`, `wire_not_utf8`,
  `wire_bom`, `wire_syntax`, `wire_duplicate_member`, `wire_nonfinite_constant`,
  `wire_lone_surrogate`, `wire_number_out_of_range`, `wire_depth`, `wire_trailing_data`.
- `v1.structure`: closed member sets, enumerations, `x-` extension names, constants and
  patterns, from the vendored contract schema (`control-plane-journal` for a run record,
  `execution-attempt-lifecycle` for a lifecycle document). Codes `schema_violation`,
  `unknown_enum_value`, `undeclared_member`, `invalid_extension_key`,
  `unsupported_contract_version`.

A raw producer record carries no `contract` or `contract_version`; the structure check
supplies them for its own use and says so in the check notes. The record is not altered.

## Tier V2: internal consistency

Rule groups written from the contract text, each its own check:

| Check | Examines |
|---|---|
| `v2.journal.decisions` | unique ids; `result` iff reasons empty and binding present; `effect_id` is the commitment of the binding's proposal, grant id and grant revision; horizon names the binding's proposal; tenant fields together |
| `v2.journal.references` | attempts, refusals, journal events, observations and reconciliations name an existing decision or effect, and the decision is authorized where required |
| `v2.journal.attempts` | acknowledgement and error shapes per status; at most one lifecycle starting `attempted` per effect |
| `v2.journal.reconciliations` | held when rejected; accepted observations carry policy, aware times, age within bound; result matches state; `observations` equals the accepted ones |
| `v2.journal.closeouts` | lineage to an attempt row and an accepted observation; no missing closeout |
| `v2.journal.refusals` | unique ids, reasons, horizon equality, changed inputs attributed |
| `v2.journal.inputs_and_times` | missing inputs claim no commitment; every stated time has a UTC offset |
| `v2.journal.journal_mode` | vocabulary version and runtime authority required with a journal, forbidden without |
| `v2.journal.vocabulary`, `v2.journal.check_ids` | vocabulary transitions; unique check ids |
| `v2.lifecycle.control_plane_attempts` | start record, reconciled-existing marker, fixed `started_at`, no repeated row |
| `v2.lifecycle.journal_protocol` | open, inputs, completed or interrupted with unchanged binding; each completion binds to its own resolution check by content; non-overlapping checks listed in order |
| `v2.lifecycle.executor_rows` | runtime executor rows and result (lifecycle documents only) |

The delegated lifecycle groups run only when no earlier group refuted; otherwise they are
`could_not_check` with reason `earlier_rules_refuted`.

### Verifier-side binding rules (`v2.journal.check_bindings`)

The contract text does not state these; its valid fixtures hold them ("resolution inputs read
consistently across decisions, checks and journal") and so does every clean real run in the
test corpus. They tie the places a resolution is recorded to each other. The group runs last
and only when every contract group found nothing, so a contract refusal code is never
accompanied by one of these.

| Code | Rule |
|---|---|
| `resolution_check_mismatch` | a decision's `resolution_inputs` and `reasons` equal those of one decision-stage resolution check (each check used once); an effect-time refusal's `resolution_inputs` equal those of one effect-stage check |
| `resolution_check_without_completion` | with a journal, there are no more resolution check rows than `completed` journal checks. An evaluation that opened and never completed (opened only, or `interrupted`) is valid evidence and has no row; a row, and a decision resting on it, with an unfinished journal check is refused |
| `effect_check_before_decision_check` | no effect-stage check is listed before the first decision-stage check (an effect check happens on a persisted decision, whose decision check came first) |

What they do not claim: that the inputs were read correctly, that the check was complete, or
that checks are in true time order (without a journal, nothing says whether two checks
overlapped, so the order of two checks of the same stage is not examined).

### Identity (needs a proposal export; the manifest is optional)

The proposal export is the full runtime proposal model dump (nulls included). A decision pairs
with the proposal whose commitment equals the horizon's `proposal_commitment`.

| Check | Examines |
|---|---|
| `v2.identity.proposal-commitment` | each decision's horizon commits to a supplied proposal |
| `v2.identity.effect-id` | `effect_id` equals the commitment of the proposal commitment, grant id and revision (nulls for a held decision) |
| `v2.identity.binding-fields` | each member of an authorized binding (manifest identity, actor, target, amount, unit, payload commitment, ...) equals the proposal's |
| `v2.identity.horizon-times` | the horizon's `not_before` and `expires_at` equal the proposal's |
| `v2.identity.payload-commitment` | the proposal's payload commitment is the commitment of its payload |
| `v2.identity.run-id`, `v2.identity.manifest-digest` | the proposal names this run; with a manifest, its digest and identity match and the manifest input's `record_commitment` matches |
| `v2.decisions.reason-registry` | every reason is in the vendored `runtime-authority-reasons/0.1` registry |
| `v2.decisions.authorized-inputs-agree` | an authorized decision's resolution inputs agree with their expectations |
| `v2.decisions.recomputable-reasons` | the one reason the record lets us recompute (`grant_revoked`, runtime-authority profile only) |

## Tier V4: receipts (needs a destination ledger)

The ledger is the control-plane local destination snapshot (`effects`, `grant_effect_counts`). It has
no sequence number, chain or signature.

| Check | Examines |
|---|---|
| `v4.ledger.keys` | each row is keyed by its own `effect_id` |
| `v4.ledger.effects-have-authorized-decisions` | every row has an authorized decision (else an unauthorized effect) |
| `v4.ledger.row-matches-binding` | row target, amount, unit and payload match the decision's binding |
| `v4.ledger.counts` | `grant_effect_counts` equals the rows per grant |
| `v4.ledger.acknowledged-attempts-have-rows` | an acknowledged or partial attempt has a row, and its acknowledgement agrees with it |
| `v4.ledger.observations-agree` | an accepted applied or partial observation has a row and agrees with it |

The report also carries recomputed `unauthorized_effects` and `excess_duplicate_effects`
(`x-recomputed-counters`).

## Not checked by these tiers

- That a decision was right, that a policy was adequate, or that a grant was lawfully issued.
- That `result` or `reasons` are what the controller would compute: the retained record does
  not hold the inputs the rules read (tier V3, deferred).
- Commitments over bodies the record does not retain (`record_commitment`, manifest body)
  unless the outside input is supplied (see the identity and ledger tiers).
- Self-consistent forgery: a record whose affected commitments were all recomputed after
  tampering is accepted.
- Ledger completeness: a dropped tail, a consistent rewrite, or a decision that never reached
  the ledger cannot be seen (stated in every report that includes a ledger).
- Any ledger format other than the control-plane local destination snapshot (the runtime
  sqlite export is not read).
- Tier V3 (witness re-derivation): not implemented.
- A changed resolution check id. The ids of resolution checks and of journal checks are
  separate producer ids (the contract says so), and a completed journal check binds to a
  resolution check by stage, inputs and reasons, not by id; a record whose only change is one
  resolution check id is still consistent by content, and the verifier does not invent a link
  between the two id sets.
