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

## 2026-10-22: review scan 4 fixes

Binding version members are compared with the kept inputs, the effective-grant members of `runtime_authority`
are checked for shape, and the claim-boundary check reads release-state.json strictly and normalises more
disguised wording (see `docs/tiers.md` and `scripts/check_claim_boundaries.py`). The check stays a wording gate
on HOLD: it authorizes nothing and shows no clearance, and nothing here is for production use.

## 2026-10-22: review scan 5 fixes

The claim-boundary check now reads every tracked or untracked-unignored file that is not binary (suffix compared
case-insensitively; extensionless and unlisted suffixes are read; NUL bytes or invalid UTF-8 in a file with no
known text suffix mean binary and skip it; known binary suffixes are not read), so a new suffix cannot hide
wording. The Apache-2.0 `LICENSE` text, now read, is an excluded path in the allow-list; the excused-match count
is unchanged. The lookalike table gains the Latin small capitals and more Cyrillic, Greek, Armenian and IPA
letters, and the rule list also covers the short `prod` and the `deploy`, `deployment` variants of the existing wording. The refusal-reason binding
is documented, not changed (see `docs/tiers.md`). The check stays a wording gate on HOLD: it authorizes nothing and
shows no clearance, and nothing here is for production use.

## 2026-10-22: reason registry 0.2 re-vendored at Control Plane 0a41faa9

The vendored `runtime-authority-reasons-0.2.json` is re-copied byte-exact from Control Plane 0a41faa9 (164 codes;
the one new code is `invalid_manifest`). Before this, a real Control Plane refusal carrying `invalid_manifest`
under the 0.2 label was refuted as `reason_code_unregistered`. The vendored 0.1 file is unchanged (byte-identical
at 0a41faa9). `PROVENANCE.json` carries the new revision and digest for the 0.2 entry only. This is a data
re-copy: no rule changed, the check stays a wording gate on HOLD, it authorizes nothing, and nothing here is for
production use.
