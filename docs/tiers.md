# What each tier checks, and what it does not

Verdicts are three-valued per check: `confirmed`, `could_not_check`, `refuted`. Every check
carries a tally (`confirmed`, `could_not_check`, `refuted` and `n` items of a stated unit; a check over zero items is reported as one `could_not_check` item, contract default 3). There is no composite
score. A check with nothing to examine in the record is never a vacuous `confirmed`: it is
listed under `x-not-applicable` in the report (reasons `no_items_in_record`,
`no_journal_in_record`) instead of among the results, so a clean trace is not forced to
abstain. A check that lacks an input is `could_not_check` (`input_absent`,
`tier_unavailable`). A crash inside a check produces no report at all (exit code 4) and is
never counted as detection.

The command is `cognous-verify RUN_RECORD [--proposal F] [--manifest F] [--ledger F] [--witness F] [--holder-inventory F]`. Exit
codes: 0 accept, 1 refuted, 2 usage or input error, 3 abstain, 4 crash. The overall outcome is
derived from the checks (reject if any is refuted, abstain if any could not be made, accept if
all confirmed); it is not a score and not an attestation. The report follows the ODES
`verification-report` contract 0.1.0-draft (revision of 2026-10-18).

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
| `v2.journal.journal_mode` | vocabulary version and runtime authority required with a journal, forbidden without; a row labelled `runtime-authority-reasons/0.1` holding a code only 0.2 registers is `reason_label_mismatch` (draft revision 3; the converse is not checked) |
| `v2.journal.vocabulary`, `v2.journal.check_ids` | vocabulary transitions; unique check ids |
| `v2.lifecycle.control_plane_attempts` | start record, reconciled-existing marker, fixed `started_at`, no repeated row |
| `v2.lifecycle.journal_protocol` | open, inputs, completed or interrupted with unchanged binding; each completion binds to its own resolution check by content; non-overlapping checks listed in order |
| `v2.lifecycle.executor_rows` | runtime executor rows and result (lifecycle documents only) |

The delegated lifecycle groups run only when no earlier group refuted; otherwise they are
`could_not_check` with reason `earlier_rules_refuted`.

### Records written with an opt-in profile

The control plane's opt-in profiles (`operation-identity`, `rule-revision`, `freshness`) add optional
members, two check phases (`overdue`, `expired`) and one read state (`nonce_mismatch`) to the run
record. The vendored journal schema (ODES 0663d5a2, draft revision 3 plus the terminal-revocation fixtures) declares them as optional, so
`v1.structure` accepts them; before that every profile-on record was refused there (orchestrator
finding F-3). The ODES fixtures from real profile-on runs (38 valid, 21 invalid, `profile-*`; the profile-on records re-captured at control plane 3755c71a)
are in `tests/data/odes-fixtures/journal/`. Four journal rules are read differently when, and only
when, the profile member is present on the row they concern (`profile.py`, the member table pinned
to the schema by a test); each has negative tests (the same defect without the member, and a
profile-on record with the defect, is still refused):

| Rule | Relaxed when | Still refused |
|---|---|---|
| `second_attempt_for_effect` | an attempt's latest row is `failed` with `check_expired_before_dispatch` and a refusal of the same effect carries that reason and the freshness `deadline`; one refusal excuses one attempt | no `deadline` on the refusal, another failure reason, more such attempts than refusals |
| `observation_time_future` | the effect has a decision, attempt or refusal row carrying a freshness member: "future" is judged against the later of `evaluation_time` and `reconciled_at` | an observation later than both (plus tolerance); a freshness member only on another effect. Staleness stays relative to the evaluation. (The ODES validator relaxes this for the whole record when any freshness member is present; this is narrower and every valid fixture still passes) |
| `journal_missing` | the decision is a hold whose only reason is `check_lease_unavailable` and carries the freshness `evaluated_at`: refused before a check is journalled | a second reason, or no `evaluated_at` |
| lifecycle projection | `overdue` and `expired` events are not the lifecycle contract's protocol and are left out of `v2.lifecycle.journal_protocol` | they are checked by `v2.journal.profile` instead |

`v2.journal.profile` exists only for a record with a profile phase or a `nonce_mismatch` read: such a
phase needs the freshness `deadline` and a `nonce_mismatch` input needs `age_basis`
(`profile_value_without_member`), and a profile phase follows the `opened` event of its check
(`journal_protocol`). Freshness times (`evaluated_at`, `recorded_at`, `deadline`) need a UTC offset
(`timestamp_invalid`, in `v2.journal.inputs_and_times`). A record with no profile member gets no new
check and its report is unchanged; a record that carries an empty profile list gets one, which is `could_not_check` (`no_items_in_record`), never `confirmed`; every verdict of the 156 default fixtures and clean runs is pinned
(`tests/data/default-path-verdicts.json`, produced at adb8927).

Profile-on records are still subject to every other rule: a tampered `effect_id` or decision result
is refused as before.

### Profile semantics (`v2.profile.*`)

The profile members are the sidecar contracts' to define (`operation-identity`, `rule-revision`,
`freshness-clocks`, ODES 0663d5a2, schemas, validators and fixtures vendored unchanged in `tests/data/`
with digests in SOURCE.json; the package never imports them, and the tests load them as reference oracles). Until this tier a record tampered only in such a
member was accepted. `sidecar.py` re-derives, from the supplied record alone, the rules a raw record
can answer; one check per profile, present only when a member of that profile is in the record (a
record without profile members has none of them, so a default report is unchanged), each carrying its
`does_not_prove` statement in its notes and in the report's `extensions["x-profile-checks"]`. A report that ran any `v2.profile.*` check also lists the report
contract's optional non-claim `profile_sidecar_semantics_only` in `does_not_prove` (ODES decision 29,
statement text from the contract: profile-on sidecar checks cover only the members the rules read;
host-configuration rules such as signer set, extension limit and resolver capability are not
checked). A report with no profile check does not carry it.

| Check | Re-derives | Codes (the sidecar contract's own) |
|---|---|---|
| `v2.profile.operation-identity` | the operation ledger replayed in append order (renewal outcome, writer, new revision, context), unique ids, joins naming an admitted operation of the same grant at a licensed revision, one join per attempt and per check, `merged_into`; decisions carrying the issuer's operation id, issuer, principal, grant and a licensed revision; each join against its attempt, decision, journal check (opened, completed, same effect and decision) and resolution check; every attempt has a join; refusals name their check; one committed effect per operation; a rejection needs a committed peer | `duplicate_*_id`, `renewal_*`, `join_*`, `merged_into_*`, `decision_operation_*`, `operation_issuer_mismatch`, `first_revision_mismatch`, `attempt_without_join`, `refusal_check_*`, `operation_committed_twice`, `rejection_without_committed_peer`, `timestamp_invalid`, `schema_violation` |
| `v2.profile.rule-revision` | revision rows (unique ids, no accepted self-signed row, supersession target, `from_digest` is the digest adopted at the time, arity only on registry rows), refusal rows, and for every decision and refusal carrying `rule_identity`: the state, `verified_through` and findings recomputed from the revision rows recorded at or before the row's time (a revision written later never adopts earlier), `unknown` list, a policy the row read has an entry, an unadopted policy holds with `policy_status_unknown` | `duplicate_revision_id`, `self_signed_row_accepted`, `supersedes_unknown`, `from_digest_mismatch`, `rule_identity_recomputed_mismatch`, `rule_identity_findings_mismatch`, `rule_identity_unknown_mismatch`, `verified_through_state_mismatch`, `finding_level_mismatch`, `observed_digest_finding_mismatch`, `policy_input_without_rule_identity`, `unadopted_policy_not_held`, ... |
| `v2.profile.freshness` | `deadline` is the opening's `recorded_at` plus `age_bound_seconds` (instants, not text), both or neither; later events of a check carry the opening's clock members; `overdue` and `expired` written strictly after the deadline with their reason; one opening, nothing after a terminal event, no time regression; the extension an opening names exists, matches its bound and window and was recorded before use; accepted and refused extensions, recovery runs; `decided_at` and `started_at` equal `evaluated_at`; an expired check has a refusal with the same deadline and a failed attempt, and licensed no dispatch; nonce reuse; lease holds | `deadline_mismatch`, `deadline_members_incomplete`, `check_event_clock_drift`, `expired_not_past_deadline`, `overdue_before_deadline`, `expired_refusal_*`, `expired_*`, `extension_*`, `recovery_*`, `recorded_before_evaluated`, `evaluation_alias_mismatch`, `nonce_reused_across_checks`, `nonce_reason_mismatch`, `lease_unavailable_*`, ... |

Verdicts: `confirmed`, or `refuted` with the codes above. `could_not_check` (`input_absent:configured_signer_set`)
only for a rule-revision identity row that names `signer_not_configured`: the configured signer set is
host configuration in no record, so that row is not recomputed. Where a rule needs host configuration
(the configured signer set, the declared extension limit, the resolver's capability) it is not made:
`accepted_extension_exceeds_limit`, `accepted_extension_authority_unconfigured`,
`extension_reason_unexplained`, `nonce_bound_without_capability`, `signer_not_configured`. Not derived
because a raw record does not carry the sidecar's projections: clock rows, input reads, the freshness,
trend, arity and recomputability reports, and the closed member sets of the profile rows (the journal
contract leaves their shape to the sidecars; the rows are checked for the members the rules read, a
member of the wrong kind or missing is `schema_violation`).

Measured over the ODES sidecar fixtures (record rebuilt from each fixture: `tests/test_sidecar.py`,
every code the checks do not derive is listed there with its reason, and a test fails if a listed
code becomes found): valid 12 + 15 + 20, all accepted by the ODES validator and by these checks; invalid
fixtures refused with their own code: operation-identity 51 of 66 (the 15 not found are the sidecar's
structural codes), rule-revision 32 of 81, freshness-clocks 54 of 97. The control plane's own
functions are the differential reference: `tests/data/sidecar/cp-differential.json` (control plane
0eed74e, `tools/capture_cp_differential.py`) holds 720 `operation_status`, 36 `licensed_revisions`, 600
`resolve_rule` and 36 deadline cases, and the verifier's functions agree on every one.

One real record is refused: the ODES journal fixture `profile-op-grant-mismatch-held` (listed under `invalid`, marked `refused_by: operation-identity`) is accepted by the
journal rules and refused here (`decision_operation_binding_mismatch`), as the ODES sidecar fixture
`decision-operation-binding-mismatch` (the same record) is by the operation-identity validator: the
capture rebound the operation's ledger row to another grant after the first authorized decision, so
the ledger and that decision disagree. `tests/test_odes_differential.py` pins both. Every valid
profile record (38 of 38) and every default record is accepted unchanged.

What this does not show: that the destination committed one effect per operation, that an issuer or
a signer is who a row says, that the clocks were true (the writer of the record writes both sides of
every comparison), or that rows are complete (rows dropped together with everything that names them
agree). A self-consistent forgery is accepted, as for every tier.

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
| `v2.decisions.reason-registry` | every reason is in the vendored registry its row's `reason_vocabulary_version` names (`runtime-authority-reasons/0.1` or `/0.2`; an absent label is read as 0.1; any other label is `reason_vocabulary_unknown` and its codes are not judged) |
| `v2.decisions.authorized-inputs-agree` | an authorized decision's resolution inputs agree with their expectations |
| `v2.decisions.recomputable-reasons` | the one reason the record lets us recompute (`grant_revoked`, runtime-authority profile only) |
| `v2.inputs.read-by-document-kind` | emitted only when a proposal, manifest or ledger input is supplied with a document kind that reads none of them (an execution-attempt-lifecycle or unsupported document): `could_not_check` (`tier_unavailable`), so the run abstains instead of accepting with that evidence unexamined |
| `v2.coverage.items-examined` | emitted only when no check beyond the parse and the document shape examined an item (and none is refuted): `could_not_check` (`tier_unavailable`), so a record with nothing in it abstains instead of accepting |

## Tier V3: witness re-derivation (needs a witness file)

Input: the `witness-digest/0.1` records a witness holds, one JSON object per line (the control
plane's `acp witness publish` writes this file; `LocalFileWitness`). The verifier recomputes
every value in them from the run record with its own canonical form, from the profile's text:
a ledger is every list-valued top-level member of the record document; the chain head after
`i` rows is `commitment({"prev": head[i-1], "row": commitment(row[i])})` from `sha256:` plus 64
zeros; a witness record's `digest` is the commitment of the record without `digest`; `sequence`
is the index; `previous_digest` is the recorded digest of the record before; one run; per-ledger
counts never decrease. Each line goes through the strict parser; nothing is repaired.

| Check | Examines | Codes |
|---|---|---|
| `v3.witness.records` | every line parses; closed member set (`version`, `run_id`, `sequence`, `previous_digest`, `ledgers`, `digest`, and the optional `extensions`); each ledger entry has `count` (an integer, 0 or more) and `head`, and optionally `extensions`; `extensions` is an object with `x-` names (`invalid_extension_key`) and is covered by `digest` like any member | `wire_*`, `witness_record_shape`, `witness_version_unsupported`, `invalid_extension_key` |
| `v3.witness.digest-recompute` | each record's `digest` recomputes | `witness_chain_invalid` |
| `v3.witness.chain` | contiguous sequence, `previous_digest` linkage, one run, counts not decreasing | `witness_chain_invalid` |
| `v3.witness.run-id` | each record names the run of the record supplied | `witness_run_mismatch` |
| `v3.witness.ledger-heads` | for every (witness record, ledger) the record holds at least `count` rows and the head over the first `count` rows equals the held head. Denominator: witness records (the note gives the number of ledger heads re-derived) | `witness_ledger_shrunk` (a covered row was dropped, or the ledger emptied or removed), `witness_ledger_head_mismatch` (a covered row rewritten, reordered, or dropped and replaced) |
| `v3.witness.coverage` | per non-empty ledger of the record: does the latest witness record cover every row? Rows appended after it are reported `could_not_check` (`input_absent`, note names the ledger and the number of rows): unwitnessed, not intact | none (never a refusal) |

The codes are the control plane's own for the same conditions (its `witness_ledger_shrunk`,
`witness_ledger_head_mismatch`, `witness_chain_invalid`, `witness_run_mismatch`), so a result
can be compared with its `verify_against_witness`; the shape and version codes are the
verifier's. `tests/data/witnesses/cp-differential.json` holds that function's verdicts over 898
cases (25 witnessed records, record and witness damage, `tests/witness_mutations.py`), and a
test requires the same accept/refuse split, the same code set and the same unwitnessed rows in
every case. A chain defect, a run mismatch or a shape error stops the later checks (`earlier_rules_refuted`),
as the control plane's verifier does.

An empty witness file is `could_not_check` (`witness_holds_no_digest`), not a refusal, and so
is a record that is not a control-plane record store document (`unsupported_document`). With
neither `--witness` nor `--holder-inventory` the tier is not run: there is no V3 check, no V3
input, no `V3` in `scope.tiers_run`, and the report says so in `x-notes` (an earlier build
listed a `v3.witness.present` could-not-check item; the contract revision of 2026-10-18 says
a tier that did not run has no items). With an inventory and no witness, V3 runs the inventory
checks only and says nothing about the witness nobody supplied.

**Holder inventory** (`holder-inventory/0.1`). The run record does not carry one: it is a member
of the runtime-authority profile, which the record does not retain (a profile commitment is not
the profile). It can be supplied with `--holder-inventory`:

| Check | Examines |
|---|---|
| `v3.holder-inventory.document` | strict parse; closed members; version; non-empty strings within the length bounds; `recorded_at` a time with a UTC offset, read with the same rule as the record's own times (`timestamp_invalid`); `version` another string is `unsupported_contract_version`; holder `kind` in `routed`, `self_credentialed`, `other` (`unknown_enum_value`); `credential_ref` null, a string or absent; optional `extensions` on the inventory and on a holder, `x-` names only (`invalid_extension_key`) (`holder_inventory_shape`, `undeclared_member`). An inventory enumerating no holder claims nothing and is `could_not_check` |
| `v3.holder-inventory.record-reference` | rows in the record carrying `holder_inventory_missing`. The record does not say which profile was in force, so they cannot be tied to a supplied inventory: always `could_not_check` (`input_absent` when none is supplied). No such rows: not applicable |

Duplicate holder ids and the inventory being complete are not checked: the profile does not
define them (the inventory is the control; a holder nobody listed stays invisible).

**Where it is reported.** Since the ODES `verification-report` revision of 2026-10-18 (decision 27,
ODES main fe705e87) tier V3 is a tier like the others. When a witness or an inventory was
supplied: the V3 checks are in `checks` (after V1, V2 and V4) and counted in `summary`; `V3` is in
`scope.tiers_run`; the files are in `subject.inputs` with roles `witness` and `holder_inventory`, so
`inputs_digest` covers them; the report carries the non-claim `witness_is_not_publication`; the
V3 results feed the overall outcome and the exit code as they always did. `extensions["x-v3-notes"]`
keeps what a check cannot carry (`witness_supplied`, `holder_inventory_supplied`, `not_applicable`,
`limits`). When neither was supplied none of this is present. `x-tier-v3` is gone; a reader of
`checks` alone now sees a V3 refusal. The V3 check ids are free strings in the contract.

**What a confirmed V3 result shows, and what it does not.**

- It shows the witness file matches the records it was given: the covered rows are the rows
  the digest was computed over. It does not show the witness was published, that it was
  published in time, or that a party independent of the record keeper held it. A witness file
  supplied by whoever supplied the records vouches for nothing that party could rewrite: a
  record and a witness rewritten together to agree are accepted (a test pins this).
- Rows appended after the latest digest are not covered, and only list-valued ledgers are:
  top-level scalars and dictionaries (`run_id`, `input_time_floors`) are not.
- A record with no witness has no V3 result at all (the tier did not run); it is never a refusal and never a pass of V3.
- The signer remains an asserted name. The `witness-digest/0.1` record has no signer or proof
  member, so there is nothing to check about who published it; a record with an extra member is
  refused as a shape error and is not read as a signature (an `x-` extension is accepted and is
  never one either). If a profile later adds a keyed
  proof, only what its contract defines would be checked.
- Two ODES drafts now exist for the witness and the inventory (`witness-digest`,
  `holder-inventory`). Their schemas, validators and fixtures are vendored unchanged
  (`tests/data/`, digests in SOURCE.json) and `tests/test_witness_contracts.py` runs every
  fixture through both the ODES validator and these checks (see "Divergences from the ODES
  drafts"). The control plane's own verifier remains a differential reference for the witness
  checks (898 cases).

### Divergences from the ODES drafts

Measured by `tests/test_witness_contracts.py` over the vendored fixtures at ODES 0663d5a2:
`witness-digest` 7 valid and 33 invalid, `holder-inventory` 6 valid and 22 invalid. On every
fixture not listed here the verifier and the ODES validator agree on accept or refuse and on
the refusal (ODES `undeclared_member` and `schema_violation` are the verifier's
`witness_record_shape`; `holder_inventory_shape` for the inventory, which keeps
`undeclared_member`). Rule used for each case: the verifier does not become stricter than
what a supplied file can show, does not turn an abstention into a refusal, does not
depart from the control plane's own verdict codes that the 898-case differential pins, and
does not count something that derives nothing as a check made.

Changed in the verifier (it was wrong or looser than the profile, in the direction of ODES):

| Case | Before | Now | Why |
|---|---|---|---|
| `extensions` on a witness record, ledger entry, inventory or holder | refused as an undeclared member | accepted when an object with `x-` names; a name without `x-` is `invalid_extension_key` | the ODES convention, the ledger contract is read the same way, and on a witness record the extension is covered by `digest` so it cannot be altered unseen. It is never read as a signer or proof: a `signer` or `proof` member stays a shape error and an `x-proof` value proves nothing |
| inventory `recorded_at` without a UTC offset, or not a time | accepted (any non-empty string) | `timestamp_invalid` | a time without an offset is not evidence, the rule the verifier already applies to the record's own times. The verifier reads an instant as ODES time semantics section 1 defines it: upper-case `T` and `Z` only, no space separator, ASCII digits, seconds mandatory, at most six fraction digits, offset minutes 00 to 59, no leap second, no naive time. Every place the verifier parses a time (`timeutil.aware`) uses the same rule, so it accepts and refuses the same forms as the ODES validators |
| inventory `version` another string | `holder_inventory_shape` | `unsupported_contract_version` | same condition, the ODES code name (a non-string stays a shape error) |
| witness `version` not a string | `witness_version_unsupported` | `witness_record_shape` | a wrong type, not an unsupported version |

Kept (a deliberate difference, each pinned by a test that fails if the two stop differing):

| Case | ODES | Verifier | Why it is kept |
|---|---|---|---|
| ledger entry with `count` 0 (`ledger-count-zero`) | refused (an entry covers at least 1 row; the producer omits empty ledgers) | accepted when the head is the genesis head, else `witness_ledger_head_mismatch`; the entry is left out of the number of heads re-derived, and rows of that ledger are reported uncovered | the entry says "no row covered", which is what omitting the ledger says (a missing ledger counts as empty), so it hides nothing and cannot be told from an omission; the control plane accepts it and the 898-case differential pins the same codes. The ODES fixture is refused here too, but for its digest (the count was edited without re-signing), not for the count |
| empty witness file (`empty-witness-file`) | refused, `witness_holds_no_digest` | `could_not_check`, same reason code | an empty file is the absence of an input, not evidence about the record. Abstain stays abstain; it is never accepted and the exit code is 3 |
| run record with no `run_id` (`record-without-run-id`) | refused, `witness_run_mismatch` | `could_not_check` (`record_has_no_run_id`); the heads and coverage checks are `could_not_check` too | the record offers no run to compare with, so a mismatch is not shown |
| witness file that is one bare object (`witness-file-is-an-object`) | refused: the document is an array | accepted as one record | on the wire the file is JSON lines, and one record on one line is that object; the verifier cannot tell the two files apart. The array rule is a rule of the document model |
| inventory enumerating no holder (`enumerates-no-holder`) | valid | `could_not_check` | it claims nothing, so a confirmation would be vacuous |
| inventory holder missing `credential_ref` (`credential-ref-member-missing`) | refused (required) | accepted | the control plane's own model defaults the member to null and accepts the file; the verifier does not refuse an inventory the producer honours. The producer always writes the member. Recorded for ODES: either make the member optional or keep the stricter document rule |

ODES classifies two of these (`witness_holds_no_digest`, `witness_run_mismatch`) as refusals
because they are the control plane's verdict codes for the same conditions. The verifier
reports them as abstentions: the difference is classification, not outcome (neither accepts).

## Tier V4: receipts (needs a destination ledger)

The ledger is the control-plane local destination snapshot (`effects`, `grant_effect_counts`, optional
`operations`). It has no sequence number, chain or signature.

Shape (`v1.structure.ledger`, code `ledger_shape`), the ODES `destination-ledger` 0.1.0-draft
contract read from its own text: a row is closed, seven required members (`effect_id`, `grant_id`,
`target`, `amount`, `unit`, `payload`, `state`) plus two optional ones, `operation_digest` (the
string `sha256:` and 64 lowercase hex digits, nothing else) and `extensions` (an object with `x-`
names). `extensions` is also allowed at document level. An optional member that is present is
type-checked like a required one; `null` is not an absent member. The contract's fixtures
(13 valid, 48 invalid) are run through the verifier and the copied ODES validator in
`tests/test_ledger_contract.py`; the two agree on every one.

| Check | Examines |
|---|---|
| `v4.ledger.keys` | each row is keyed by its own `effect_id` |
| `v4.ledger.effects-have-authorized-decisions` | every row has an authorized decision (else an unauthorized effect) |
| `v4.ledger.row-matches-binding` | row target, amount, unit and payload match the decision's binding |
| `v4.ledger.counts` | `grant_effect_counts` equals the rows per grant |
| `v4.ledger.rows-agree-with-attempts` | every row's effect has an attempt row in the record (`ledger_row_without_attempt`: the control plane writes an attempt before it dispatches, so a row for, say, an effect the effect-time check refused is not producible; a record of the atomic claim route, which holds a `claim`-stage check and no attempt, observation, reconciliation, effect-stage check or refusal at all, is the one exception: the destination owns the attempts there, so a row is reported could-not-check, `attempt_rows_not_in_record`, never confirmed), and not only attempts that ended `failed` (`ledger_row_after_definitive_failure`: `failed` is the adapter's assertion that the destination did not accept; an attempt left `attempted`, `unknown`, `acknowledged` or `partial` allows a row) |
| `v4.ledger.acknowledged-attempts-have-rows` | an acknowledged or partial attempt has a row, and its acknowledgement agrees with it. The receipt is read in three shapes: the native `effect` (compared by commitment), the adapter `observation` of state applied or partial (its `effect_id` must be the attempt's and its `destination_state` is compared member by member; an abstention for members outside the row is left to `v4.ledger.observations-agree`), and the marker `{"reconciled_existing": true}`, comparable only when the record holds an accepted applied or partial observation of that effect. An acknowledgement with none of these has nothing to compare: could-not-check, `no_comparable_receipt`, never confirmed. A fresh execution is `duplicate: false` or `newly_executed: true`; two fresh claims for one effect are refuted (`fresh_acknowledgement_repeated`), and `duplicate` and `newly_executed` claiming the same thing is refuted (`acknowledgement_flags_contradict`) |
| `v4.ledger.observations-agree` | an accepted applied or partial observation has a row and its `destination_state` agrees with it, member by member. The seven required row members must be present and equal (a missing or differing one is refuted, `observation_differs_from_ledger_row`). `operation_digest`: if the row and the state both carry it they must be equal, else refuted with `operation_digest_mismatch`; this is judged before, and regardless of, any other member the state carries, so the optional member cannot hide a mismatch. A digest only the state carries (the row has none), or any other member the row has no place for, is reported could-not-check, `destination_state_has_members_outside_ledger_row`; a digest only the row carries is not compared, could-not-check, `operation_digest_not_in_destination_state`. A row carrying the digest the state agrees with is no longer "outside the row" and is confirmed. `extensions` on a row are ignored by logic and not compared; `extensions` on the state that are not equal to the row's count as outside members |

The report also carries recomputed `unauthorized_effects` and `excess_duplicate_effects`
(`x-recomputed-counters`).

## Evidence check hardening (checks that must not confirm over input they cannot support)

- Attempt lifecycle (`v2.lifecycle.*`). An attempt's identity (`effect_id`, `decision_id`) is fixed
  by its first row (`attempt_identity_changed`). Control-plane rows: `attempted` only opens an
  attempt; `acknowledged`, `partial` and `failed` close it (no row after them); `unknown` may be
  followed only by one of those (`attempt_transition_invalid`). Executor events: `attempted` ->
  `executed`, `partial`, `failed`, `unknown`, `denied`, `reconciled` (the runtime writes
  `attempted` -> `reconciled` when the destination already holds the effect); `executed` and `partial` -> `unknown` or
  `reconciled`; `unknown` -> `reconciled`, `executed`, `partial`, `failed`; `reconciled`, `failed` and
  `denied` close. An observation in an execution result must name the effect and decision of the
  attempt row the result names (`result_binding_mismatch`). The ODES validator implements the same
  table except `executed` -> `unknown` and `partial` -> `unknown`, which it refuses and this verifier
  accepts (the control plane adapter appends `unknown` after `executed` or `partial` when the
  follow-up observation is not accepted); the difference is pinned in `tests/test_result_rules.py`.
  The code name here is `attempt_transition_invalid`; the ODES validator names it `attempt_transition`.
- Identity: a `tenant_id` carried by only one of the binding and the proposal is a difference
  (`binding_proposal_mismatch`), never a pass.
- Operation profile: a record that declares the profile with no operation, renewal or join row and
  no operation-bearing decision is could-not-check (`operation_profile_without_operation_rows`).
- Expiry: the attempt that carries `check_expired` is the one the join names for that check, and a
  dispatch after an expired check is excused only by an attempt that failed with `check_expired`
  (an unrelated failed attempt for the same effect is not enough). Refusal rows are checked against
  their evaluation pass time like the other rows.
- Recovery runs: a non-string check id in `interrupted` or `overdue` is a typed shape refusal.
- Bounds. A check lists at most 100 findings (`omitted_findings` in the result, `x-omitted-findings`
  in the report; the tally still counts the refuted items); the structural pass stops after 1000
  findings; the journal matcher is iterative and a record with more than 5000 completed journal
  checks is could-not-check (`tier_unavailable`, `input_exceeds_limit`); the witness derives chain
  heads only over the rows a record asks for; a check never reports more refuted items than it
  examined. A repeated control-plane row is found with a set of canonical commitments, not a
  pairwise scan.
- Known limit kept: the reasons of a recovery run are not required to be non-empty or enumerated
  here (the contract does not enumerate them).

## Fix round 2 rules (journal and lifecycle records)

Each rule runs after the contract rule groups and only when they found nothing, so a contract
refusal code is never accompanied by one of these.

- Dispatch licence (`dispatch_without_license`, `effect_check_refusal_missing`). The control plane
  writes one effect-stage check per `execute`, then either a refusal (the check carries reasons) or
  at most one attempt lifecycle. A record holds no more attempt lifecycles than passing effect-stage
  checks that no refusal used (lifecycles excused by an expiry refusal are not counted); with a journal
  the check is tied to its decision through the journal events, and every effect-stage check that
  carries reasons has a refusal for that decision.
- Completion reasons (`completion_reasons_minimum`, `journal_unbound_completion`). A completed check carries at least
  the reasons its own recorded input events imply (the ODES `reasons_minimum` table, applied as a floor): an input read
  `unreadable` that no later read of the same input rescued as `cached_positive` implies `status_unreadable`; a read
  `nonce_mismatch` implies `status_nonce_mismatch`; an authority context or purpose whose last read is missing with no
  read state implies `authority_context_missing` or `purpose_unreadable`; any input whose last read is missing and not
  rescued requires at least one reason. The table is a floor, not a derivation: the list of required inputs is not
  recorded, so `required_input_not_read` is not required. A completion binds to a check whose
  reasons are the completion's reasons plus, at most, codes of the closed set vendored in
  `data/post-journal-gate-codes.json` (source and digest in `data/PROVENANCE.json`).
- Result identity and status matrix (`result_attempt_unresolved`, `result_binding_mismatch`,
  `result_state_matrix`). The matrix is the runtime producer's: which status may carry which flags and
  observed state. A validated observation (`state`) and a route-B recovery report (`status`) are told apart.
- Binding members (`binding_member_mismatch`, `binding_proposal_mismatch`). `policy_versions`,
  `role_mapping_digest`, `authority_context_status` and `requirement_id` agree with the inputs the decision itself
  read, when it kept them (`requirement_id` with the id of each successful `conflict` read, which the control plane
  keys by the requirement; a decision with no successful conflict read is not compared, never refused for that);
  `requirement_id` also agrees with the proposal export when one is supplied; `effective_max_effects` is a
  non-negative integer within the supplied manifest's `effect_limits.max_effects`. `effective_max_effects` is not
  compared with the captured inputs: the control plane derives it from the requirement's and the grant's permission
  limits and the manifest action limit, none of which a captured input states, so a record verified without a
  manifest and ledger gives that member no document to be checked against. A pass of these checks shows the members
  agree with each other and with what was captured; it does not show the decision was correct (V1 and V2 do not
  re-derive decisions).
- Ledger ceiling (`ledger_count_above_ceiling`, `ledger_ceiling_invalid`). A grant's effect count may not
  exceed the largest `effective_max_effects` among its authorized decisions; every contributing ceiling is
  validated before the maximum is taken.
- Causal order (`attempt_before_decision`, `closeout_before_attempt`, `reconciliation_before_attempt`), each
  inside one clock domain: evaluation-clock stamps only between rows with the same `time_source`, service-clock
  `recorded_at` only between rows that carry it.
- Freshness activation: a nested `read_state` of `nonce_mismatch` switches the freshness checks on.
- Equality: listed observations and journal input keys are compared by canonical bytes (`1` is not `true`,
  `50` is not `50.0`).
- Inputs: a role that takes one input (manifest, destination ledger, witness, holder inventory) given twice is a
  usage error (`--manifest` and the others repeated: exit 2).
- Zero items: a profile check over zero items is `could_not_check` with `no_items_in_record` over a total of zero
  (the tally reports it as one `could_not_check` item), never confirmed. An acknowledgement whose observation has members outside the ledger row is
  `could_not_check` (`no_comparable_receipt`), not agreeing.

## Decision-facing output

A consumer that decides on a report reads, per check, `verdict`, `tally` and `could_not_check_reason`, and the
`summary` counts, and the overall outcome (`x-overall`). Finding `detail`, the `x-notes` and `x-reason` extension text and
the `does_not_prove` wording are diagnostic and may be reworded; a finding's `code` and `locator` identify the defect and are
not read to reach a decision either.
`report.decision_facing` is that projection; `tests/test_decision_facing.py` shows that rewording the diagnostic
text leaves it unchanged and that it agrees with the vendored ODES fixtures' expectations where they overlap.

## Single-row deletions (known limit)

`tools/deletion_corpus.py` deletes one row of one list member of each valid journal fixture and real run
(1772 deletions over 67 records) and runs the verifier. The verifier accepted 74 of them before the dispatch
licence and accepts 62 now. The 12 newly refused are a refusal deleted while its attempt stays (9) and an
effect-stage check deleted while its attempt stays (3).

The 62 still accepted are of two kinds, each pinned by an example in `tests/test_deletion_limits.py`:

- Residual (61): the row has no counterpart in the rest of the record, so the record without it is one the control
  plane could have produced. Hold decisions (20), authorized decisions never dispatched in the record (11), the
  trailing row of an attempt lifecycle (5), vocabulary changes (2), and rows of the opt-in profiles (operation
  renewals 5, age extension refusals 6, recovery runs 4, rule revision refusals 5, rule revisions 1), one
  rejected-observation reconciliation and one input event of an interrupted check.
- By design (1): the tail of the check events. A journal that stops early is an interrupted check, which the
  contract keeps as unfinished evidence.

The ODES reference validator accepts 222 of the same deletions. No completeness member is proposed here: it would
change the contract and is a decision for the contract's owner. This is a probe of the verifier's own checks, not
a detection rate.

Further limits of the corpus and of the rules behind it:

- It deletes one row at a time. Deleting several rows, or deleting rows and recomputing the commitments that cover
  them, is not probed (the consistent-rewrite limit above applies).
- A refusal deleted from a record is detected only when the record carries a journal; on the atomic route, or for a
  record without a journal, the dispatch-licence count has nothing to compare with and does not see the deletion.
- Binding-member comparisons (`policy_versions`, `role_mapping_digest`, `authority_context_status`) read only the
  inputs the decision itself kept. A record whose decision inputs were trimmed gives no comparison and these rules are
  silent on it.
- Result identity (`effect_id`, `decision_id`) is compared when the result carries it; the lifecycle schema keeps both
  optional, so a result that omits them is not refused for that.
- The completion-reasons rule is a floor: it applies the implication table to the input events the record holds and does not require `required_input_not_read`, which nothing in the record implies (a stricter version is a decision for the contract's owner).

## Not checked by these tiers

- That a decision was right, that a policy was adequate, or that a grant was lawfully issued.
- That `result` or `reasons` are what the controller would compute: the retained record does
  not hold the inputs the rules read. Tier V3 as built re-derives the witness digests, not the
  decisions.
- Commitments over bodies the record does not retain (`record_commitment`, manifest body)
  unless the outside input is supplied (see the identity and ledger tiers).
- Self-consistent forgery: a record whose affected commitments were all recomputed after
  tampering is accepted.
- Durable inclusion: journal integrity (counts, order and bindings agreeing) does not show that
  any row was durably stored or retained. The report says so in the statement of the
  `self_consistent_forgery_not_detected` non-claim; the verification-report contract has no
  separate non-claim id for it (the id set is closed).
- Ledger completeness: a dropped tail, a consistent rewrite, or a decision that never reached
  the ledger cannot be seen (stated in every report that includes a ledger).
- Any ledger format other than the control-plane local destination snapshot (the runtime
  sqlite export is not read).
- The destination ledger snapshot (the V4 input) is not covered by the witness. The witness digests only list-valued top-level members of the run record; the snapshot is a separate document with no sequence, chain or signature, so a witnessed run says nothing about it.
- Tier V3 shows the witness matches the supplied records, not that it was published, timely or independently held (see above; the report carries the non-claim `witness_is_not_publication` whenever V3 ran).
- Number-form drift that the pinned profile writes alike. `50.0`, `50.00`, `5e1` and `50.0e0`
  are one float under the pinned profile (Python semantics: the canonical text is `repr`), so
  no commitment changes and the verifier accepts them; an integer written where a float was
  (`50` for `50.0`) does change the canonical bytes and is refused. A stricter reading of
  lexical forms would be a different profile, not a check.
- A dropped ledger row that nothing in the record corroborates. When the record holds an
  accepted applied or partial observation of the effect, a missing row is refused
  (`observation_without_ledger_row`, a real mismatch between the record and the snapshot);
  when it holds only an unknown attempt and no accepted observation, the record does not say
  the row exists and the ledger has no sequence or chain, so the drop cannot be seen.
- A ledger "from another run" whose content is the run's own (identical synthetic proposals
  share an effect id and produce the same row): the same document in other bytes.
- A changed resolution check id. The ids of resolution checks and of journal checks are
  separate producer ids (the contract says so), and a completed journal check binds to a
  resolution check by stage, inputs and reasons, not by id; a record whose only change is one
  resolution check id is still consistent by content, and the verifier does not invent a link
  between the two id sets.
