# What each tier checks, and what it does not

Verdicts are three-valued per check: `confirmed`, `could_not_check`, `refuted`. Every check
carries a denominator (`checked` of `total` items of a stated unit). There is no composite
score. A check with nothing to examine in the record is `could_not_check` with reason
`no_items_in_record`, not a vacuous `confirmed`. A crash inside a check is reported as
`could_not_check` with `error: true` and is never counted as detection.

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

## Not checked by these tiers

- That a decision was right, that a policy was adequate, or that a grant was lawfully issued.
- That `result` or `reasons` are what the controller would compute: the retained record does
  not hold the inputs the rules read (tier V3, deferred).
- Commitments over bodies the record does not retain (`record_commitment`, manifest body)
  unless the outside input is supplied (see the identity and ledger tiers).
- Self-consistent forgery: a record whose affected commitments were all recomputed after
  tampering is accepted.
