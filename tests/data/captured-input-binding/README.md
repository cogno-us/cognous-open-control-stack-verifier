Negative fixtures for the binding check against captured inputs. Each file is a real run record
(`tests/data/real-runs/<name>/bounded-run-record.json`) with one change: `binding.requirement_id` of
the authorized decision names another requirement, while the decision's own conflict read still
names the original. Expected: refused with `binding_member_mismatch` at
`$.decisions[i].binding.requirement_id`, with no other document supplied.
