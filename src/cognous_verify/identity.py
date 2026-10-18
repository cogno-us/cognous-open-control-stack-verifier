"""Tier V2 identity: recompute the commitments a run record declares, from supplied inputs.

Needs the run record plus a proposal export; the manifest is optional. Everything is
recomputed with this package's canonical form. Nothing here calls the controller.

Proposal export, as the verifier reads it: the control plane's ``RuntimeProposal`` written as
a full dump, every member present and nulls kept (the proposal commitment is taken over that
dump, so a proposal missing a defaulted member cannot be recomputed against). The
tenant-aware variant adds ``tenant_id``. The members and their JSON types are
``PROPOSAL_MEMBERS`` below.

Pairing: a decision pairs with the supplied proposal whose commitment equals the proposal
commitment its operation horizon states. When as many proposals were supplied as there are
decisions, a decision that pairs with none is refuted; with fewer or more, it could not be
checked.
"""

from __future__ import annotations

from typing import Any

from . import data
from .canon import commitment
from .results import CheckResult, Finding, could_not_check, make_result

V1 = "V1"
V2 = "V2"

STR = "string"
OPT_STR = "string_or_null"
OBJ = "object"
STR_LIST = "string_list"
NUM = "number"
INT = "integer"

PROPOSAL_MEMBERS: dict[str, str] = {
    "manifest_id": STR,
    "manifest_version": STR,
    "manifest_digest": STR,
    "actor": STR,
    "principal": STR,
    "action_id": STR,
    "adapter_id": STR,
    "target": STR,
    "payload": OBJ,
    "payload_commitment": STR,
    "requested_permissions": STR_LIST,
    "amount": NUM,
    "unit": STR,
    "effects": INT,
    "authority_context_ref": OPT_STR,
    "requirement_id": OPT_STR,
    "risk_metadata": OBJ,
    "not_before": OPT_STR,
    "expires_at": OPT_STR,
    "correlation_id": OPT_STR,
    "run_id": OPT_STR,
    "expected_side_effects": STR_LIST,
    "evidence_refs": STR_LIST,
}
TENANT_MEMBER = ("tenant_id", STR)

# binding member -> proposal member, compared type-strictly through the canonical form
BINDING_FIELDS = (
    "manifest_id",
    "manifest_version",
    "manifest_digest",
    "actor",
    "principal",
    "action_id",
    "adapter_id",
    "target",
    "payload_commitment",
    "requested_permissions",
    "amount",
    "unit",
    "effects",
)


def _type_ok(value: Any, kind: str) -> bool:
    if kind == STR:
        return type(value) is str
    if kind == OPT_STR:
        return value is None or type(value) is str
    if kind == OBJ:
        return type(value) is dict
    if kind == STR_LIST:
        return type(value) is list and all(type(v) is str for v in value)
    if kind == NUM:
        return type(value) in (int, float)
    return type(value) is int


def proposal_shape(doc: Any) -> list[Finding]:
    """Findings when ``doc`` is not a full proposal export (see module docstring)."""
    if type(doc) is not dict:
        return [Finding("proposal_export_shape", "$", "a proposal export is a JSON object")]
    expected = dict(PROPOSAL_MEMBERS)
    if "tenant_id" in doc:
        expected[TENANT_MEMBER[0]] = TENANT_MEMBER[1]
    out: list[Finding] = []
    for name, kind in expected.items():
        if name not in doc:
            out.append(
                Finding(
                    "proposal_export_shape",
                    f"$.{name}",
                    "member missing: the export must be the full model dump, nulls included",
                )
            )
        elif not _type_ok(doc[name], kind):
            out.append(Finding("proposal_export_shape", f"$.{name}", f"expected {kind}"))
    for name in doc:
        if name not in expected:
            out.append(Finding("proposal_export_shape", f"$.{name}", "undeclared member"))
    return out


def _same(a: Any, b: Any) -> bool:
    """Equality through the canonical form: ``50`` and ``50.0`` differ."""
    return commitment(a) == commitment(b)


def _decision_key(d: dict[str, Any]) -> str | None:
    horizon = d.get("operation_horizon")
    if horizon is not None:
        key = horizon.get("proposal_commitment")
        return key if type(key) is str else None
    binding = d.get("binding")
    return binding["proposal_commitment"] if binding else None


class Pairing:
    """Which supplied proposal belongs to which decision."""

    def __init__(self, record: dict[str, Any], proposals: list[dict[str, Any]]) -> None:
        self.record = record
        self.proposals = proposals
        self.by_commitment = {commitment(p): p for p in proposals}
        self.decisions: list[dict[str, Any]] = record["decisions"]
        self.paired: dict[int, dict[str, Any]] = {}
        self.unpaired: list[int] = []
        for i, d in enumerate(self.decisions):
            key = _decision_key(d)
            if key is not None and key in self.by_commitment:
                self.paired[i] = self.by_commitment[key]
            else:
                self.unpaired.append(i)
        self.one_to_one = len(proposals) == len(self.decisions)


def _absent(check_id: str, tier: str, unit: str, what: str) -> CheckResult:
    return could_not_check(check_id, tier, unit, 0, f"input_absent:{what}")


def proposal_structure(proposals: list[tuple[str, Any]]) -> CheckResult:
    """Tier V1: each supplied proposal export is a full dump with the declared members."""
    findings: list[Finding] = []
    for i, (_name, doc) in enumerate(proposals):
        for f in proposal_shape(doc):
            findings.append(Finding(f.code, f"$.proposals[{i}]{f.path[1:]}", f.message))
    return make_result(
        "v1.structure.proposal-export", V1, "proposal exports", len(proposals), findings
    )


def run(
    record: dict[str, Any],
    proposals: list[dict[str, Any]] | None,
    manifest: Any | None,
) -> list[CheckResult]:
    """The V2 identity checks. ``proposals`` None means none were supplied."""
    unit = "decisions"
    ids = (
        ("v2.identity.proposal-commitment", unit),
        ("v2.identity.effect-id", unit),
        ("v2.identity.binding-fields", "authorized decisions"),
        ("v2.identity.horizon-times", unit),
        ("v2.identity.payload-commitment", "proposal exports"),
        ("v2.identity.run-id", "proposal exports"),
        ("v2.identity.manifest-digest", "proposal exports"),
    )
    if not proposals:
        return [_absent(cid, V2, u, "proposal_export") for cid, u in ids]
    pairing = Pairing(record, proposals)
    out: list[CheckResult] = [
        _proposal_commitment(pairing),
        _effect_id(pairing),
        _binding_fields(pairing, manifest),
        _horizon_times(pairing),
        _payload_commitment(proposals),
        _run_id(record, proposals),
    ]
    out.append(_manifest(record, proposals, manifest))
    return out


def _unpaired(pairing: Pairing, findings: list[Finding]) -> int:
    """Record unpaired decisions: refuted when proposals and decisions are one to one."""
    skipped = 0
    for i in pairing.unpaired:
        if pairing.one_to_one:
            findings.append(
                Finding(
                    "proposal_commitment_mismatch",
                    f"$.decisions[{i}].operation_horizon.proposal_commitment",
                    "no supplied proposal export has the commitment the decision states",
                )
            )
        else:
            skipped += 1
    return skipped


def _proposal_commitment(pairing: Pairing) -> CheckResult:
    findings: list[Finding] = []
    skipped = _unpaired(pairing, findings)
    for i in pairing.paired:
        binding = pairing.decisions[i]["binding"]
        if binding is not None and binding["proposal_commitment"] != _decision_key(
            pairing.decisions[i]
        ):
            findings.append(
                Finding(
                    "binding_proposal_mismatch",
                    f"$.decisions[{i}].binding.proposal_commitment",
                    "the binding commits to another proposal than the horizon",
                )
            )
    notes = [] if pairing.one_to_one else ["proposal count differs from decision count"]
    return make_result(
        "v2.identity.proposal-commitment",
        V2,
        "decisions",
        len(pairing.decisions),
        findings,
        skipped=skipped,
        reason="decision_has_no_supplied_proposal" if skipped else None,
        notes=notes,
    )


def _effect_id(pairing: Pairing) -> CheckResult:
    findings: list[Finding] = []
    skipped = len(pairing.unpaired)
    for i, proposal in pairing.paired.items():
        d = pairing.decisions[i]
        b = d["binding"]
        expected = commitment(
            {
                "proposal": commitment(proposal),
                "grant_id": b["grant_id"] if b else None,
                "grant_revision": b["grant_revision"] if b else None,
            }
        )
        if d["effect_id"] != expected:
            findings.append(
                Finding(
                    "invalid_effect_identity",
                    f"$.decisions[{i}].effect_id",
                    "effect_id is not the commitment of {proposal, grant_id, grant_revision} "
                    "recomputed from the proposal export",
                )
            )
    return make_result(
        "v2.identity.effect-id",
        V2,
        "decisions",
        len(pairing.decisions),
        findings,
        skipped=skipped,
        reason="decision_has_no_supplied_proposal" if skipped else None,
    )


def _manifest_ceiling(manifest: Any | None, action_id: Any) -> Any:
    """``effect_limits.max_effects`` the supplied manifest declares for the action, else None."""
    if type(manifest) is not dict or type(manifest.get("actions")) is not list:
        return None
    for action in manifest["actions"]:
        if type(action) is dict and action.get("action_id") == action_id:
            limits = action.get("effect_limits")
            return limits.get("max_effects") if type(limits) is dict else None
    return None


def _binding_fields(pairing: Pairing, manifest: Any | None = None) -> CheckResult:
    findings: list[Finding] = []
    total = 0
    skipped = 0
    for i, d in enumerate(pairing.decisions):
        b = d["binding"]
        if b is None:
            continue
        total += 1
        proposal = pairing.paired.get(i)
        if proposal is None:
            skipped += 1
            continue
        # requirement_id: an absent or null one on either side is the empty string
        if not _same(b.get("requirement_id") or "", proposal.get("requirement_id") or ""):
            findings.append(
                Finding(
                    "binding_proposal_mismatch",
                    f"$.decisions[{i}].binding.requirement_id",
                    "binding requirement_id differs from the proposal export",
                )
            )
        if "effective_max_effects" in b:
            ceiling = b["effective_max_effects"]
            limit = _manifest_ceiling(manifest, b.get("action_id"))
            if type(ceiling) is not int or ceiling < 0:
                findings.append(
                    Finding(
                        "binding_member_mismatch",
                        f"$.decisions[{i}].binding.effective_max_effects",
                        "effective_max_effects is a non-negative integer",
                    )
                )
            elif type(limit) is int and not isinstance(limit, bool) and ceiling > limit:
                findings.append(
                    Finding(
                        "binding_member_mismatch",
                        f"$.decisions[{i}].binding.effective_max_effects",
                        "effective_max_effects exceeds the effect_limits.max_effects of the "
                        "supplied manifest",
                    )
                )
        for name in BINDING_FIELDS:
            if not _same(b.get(name), proposal.get(name)):
                findings.append(
                    Finding(
                        "binding_proposal_mismatch",
                        f"$.decisions[{i}].binding.{name}",
                        f"binding {name} differs from the proposal export",
                    )
                )
        # symmetric: a tenant on only one side (either side) is a difference, never a pass
        if not _same(b.get("tenant_id"), proposal.get("tenant_id")):
            findings.append(
                Finding(
                    "binding_proposal_mismatch",
                    f"$.decisions[{i}].binding.tenant_id",
                    "binding tenant_id differs from the proposal export "
                    "(a tenant carried by only one side counts as a difference)",
                )
            )
    return make_result(
        "v2.identity.binding-fields",
        V2,
        "authorized decisions",
        total,
        findings,
        skipped=skipped,
        reason="decision_has_no_supplied_proposal" if skipped else None,
    )


def _horizon_times(pairing: Pairing) -> CheckResult:
    findings: list[Finding] = []
    skipped = len(pairing.unpaired)
    for i, proposal in pairing.paired.items():
        h = pairing.decisions[i]["operation_horizon"]
        if h is None:
            continue
        for name in ("not_before", "expires_at"):
            if not _same(h.get(name), proposal.get(name)):
                findings.append(
                    Finding(
                        "horizon_times_mismatch",
                        f"$.decisions[{i}].operation_horizon.{name}",
                        f"horizon {name} differs from the proposal export",
                    )
                )
    return make_result(
        "v2.identity.horizon-times",
        V2,
        "decisions",
        len(pairing.decisions),
        findings,
        skipped=skipped,
        reason="decision_has_no_supplied_proposal" if skipped else None,
    )


def _payload_commitment(proposals: list[dict[str, Any]]) -> CheckResult:
    findings: list[Finding] = []
    for i, p in enumerate(proposals):
        if commitment(p["payload"]) != p["payload_commitment"]:
            findings.append(
                Finding(
                    "payload_commitment_mismatch",
                    f"$.proposals[{i}].payload_commitment",
                    "payload_commitment is not the commitment of the payload",
                )
            )
    return make_result(
        "v2.identity.payload-commitment", V2, "proposal exports", len(proposals), findings
    )


def _run_id(record: dict[str, Any], proposals: list[dict[str, Any]]) -> CheckResult:
    findings: list[Finding] = []
    skipped = 0
    for i, p in enumerate(proposals):
        if p["run_id"] is None:
            skipped += 1
        elif p["run_id"] != record["run_id"]:
            findings.append(
                Finding(
                    "run_id_mismatch",
                    f"$.proposals[{i}].run_id",
                    "the proposal export names another run than the record",
                )
            )
    return make_result(
        "v2.identity.run-id",
        V2,
        "proposal exports",
        len(proposals),
        findings,
        skipped=skipped,
        reason="proposal_names_no_run" if skipped else None,
    )


def _manifest(
    record: dict[str, Any], proposals: list[dict[str, Any]], manifest: Any | None
) -> CheckResult:
    if manifest is None:
        return _absent("v2.identity.manifest-digest", V2, "proposal exports", "manifest")
    findings: list[Finding] = []
    digest = commitment(manifest)
    for i, p in enumerate(proposals):
        if p["manifest_digest"] != digest:
            findings.append(
                Finding(
                    "manifest_digest_mismatch",
                    f"$.proposals[{i}].manifest_digest",
                    "manifest_digest is not the commitment of the supplied manifest",
                )
            )
        if type(manifest) is dict:
            for name in ("manifest_id", "manifest_version"):
                if name in manifest and manifest[name] != p[name]:
                    findings.append(
                        Finding(
                            "manifest_identity_mismatch",
                            f"$.proposals[{i}].{name}",
                            f"{name} differs from the supplied manifest",
                        )
                    )
    for i, d in enumerate(record["decisions"]):
        for j, x in enumerate(d["resolution_inputs"]):
            if x["input_type"] == "manifest" and x["record_commitment"] not in (None, digest):
                findings.append(
                    Finding(
                        "manifest_input_commitment_mismatch",
                        f"$.decisions[{i}].resolution_inputs[{j}].record_commitment",
                        "the manifest input commits to another manifest than the one supplied",
                    )
                )
    return make_result(
        "v2.identity.manifest-digest", V2, "proposal exports", len(proposals), findings
    )


# --------------------------------------------------------------------------- decisions without outside input


def decision_checks(record: dict[str, Any]) -> list[CheckResult]:
    """Checks over the decisions that need no proposal: registry, expectations, recomputable codes."""
    return [_reason_registry(record), _authorized_inputs(record), _recomputable(record)]


def _reason_rows(record: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    rows = [(f"$.decisions[{i}]", d) for i, d in enumerate(record["decisions"])]
    rows += [(f"$.refusals[{i}]", r) for i, r in enumerate(record["refusals"])]
    return rows


def _reason_registry(record: dict[str, Any]) -> CheckResult:
    """Each row is resolved against the registry its own label names (absent label: 0.1).

    A code is registered for a row only in that registry: a code that exists only in 0.2 under
    a 0.1 label is refused. A label outside the vendored registries is flagged
    (``reason_vocabulary_unknown``) and its codes are not judged, since no registry names them.
    """
    findings: list[Finding] = []
    rows = _reason_rows(record)
    labels = data.registry_labels()
    for path, row in rows:
        declared = row.get("reason_vocabulary_version")
        label = data.DEFAULT_REGISTRY if declared is None else declared
        if label not in labels:
            findings.append(
                Finding(
                    "reason_vocabulary_unknown",
                    path + ".reason_vocabulary_version",
                    f"vocabulary {declared!r} is not one of the vendored {', '.join(labels)}",
                )
            )
            continue
        known = data.registry_codes(label)
        for code in row["reasons"]:
            if code not in known:
                findings.append(
                    Finding(
                        "reason_code_unregistered",
                        path + ".reasons",
                        f"reason {code!r} is not in the registry {label} the row names",
                    )
                )
    return make_result(
        "v2.decisions.reason-registry",
        V2,
        "decisions and refusals",
        len(rows),
        findings,
        notes=[f"registry {lab} sha256 {dig}" for lab, dig in data.registry_digests().items()],
    )


def _authorized_inputs(record: dict[str, Any]) -> CheckResult:
    findings: list[Finding] = []
    authorized = [(i, d) for i, d in enumerate(record["decisions"]) if d["result"] == "authorized"]
    for i, d in authorized:
        for j, x in enumerate(d["resolution_inputs"]):
            expected, observed = x["expected"], x["observed"]
            if not expected:
                continue
            where = f"$.decisions[{i}].resolution_inputs[{j}]"
            if x["missing"]:
                findings.append(
                    Finding(
                        "authorized_input_contradicts_expected",
                        where,
                        "an input with expectations is missing under an authorized decision",
                    )
                )
                continue
            for key, want in expected.items():
                if key not in observed or not _same(observed[key], want):
                    findings.append(
                        Finding(
                            "authorized_input_contradicts_expected",
                            f"{where}.observed.{key}",
                            f"observed {key} differs from the expectation under an authorized decision",
                        )
                    )
    return make_result(
        "v2.decisions.authorized-inputs-agree",
        V2,
        "authorized decisions",
        len(authorized),
        findings,
    )


def _operand_matches(row: dict[str, Any], operands: dict[str, Any]) -> bool:
    wanted_type = operands["input_type"]
    for x in row["resolution_inputs"]:
        if x["input_type"] != wanted_type:
            continue
        ok = True
        for key, value in operands.items():
            if key == "input_type":
                continue
            _, _, member = key.partition(".")
            if x["observed"].get(member) != value:
                ok = False
        if ok:
            return True
    return False


def _recomputable(record: dict[str, Any]) -> CheckResult:
    """Reason codes the registry marks recomputable are re-derived from the retained operands."""
    registry = data.registry_all()
    recomputable = {
        code: spec["operands"]
        for code, spec in registry.items()
        if spec["reason_kind"] == "recomputable"
    }
    findings: list[Finding] = []
    rows = _reason_rows(record)
    for path, row in rows:
        for code, operands in recomputable.items():
            matches = _operand_matches(row, operands)
            stated = code in row["reasons"]
            authorized = row.get("result") == "authorized"
            if matches and authorized:
                findings.append(
                    Finding(
                        "recomputable_reason_ignored",
                        path,
                        f"the retained operands assert {code!r} but the decision is authorized",
                    )
                )
            elif stated and not matches:
                findings.append(
                    Finding(
                        "recomputable_reason_unsupported",
                        path + ".reasons",
                        f"{code!r} is stated but the retained operands do not show it",
                    )
                )
    return make_result(
        "v2.decisions.recomputable-reasons",
        V2,
        "decisions and refusals",
        len(rows),
        findings,
        notes=[
            "re-derived: " + ", ".join(sorted(recomputable)),
            "every other registry code is typed-only: the retained record does not hold the "
            "inputs to recompute it (tier V3, deferred)",
        ],
    )
