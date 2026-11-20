# tests

Fast, offline unit tests for listdap's correctness-critical parsers. No Domain
Controller and no network: each test assembles the exact binary bytes the parser
consumes (`tests/sd_helpers.py`) and asserts on the decoded result.

## Run

```bash
python3 tests/run.py          # zero dependencies (stdlib only)
python3 -m pytest tests/ -q   # same tests under pytest, if installed
```

Both exit non-zero on failure (CI-friendly).

## Coverage

| File | What it locks in |
|------|------------------|
| `test_acls_dacl.py` | DACL parser + effective-access engine (`modules/acls.py`): DENY ACEs (v2.23.0), `INHERIT_ONLY` and conditional/callback ACEs (v2.25.0), the ALLOW-only default contract that protects gpo/adidns/adcs/gmsa, and granting-SID attribution. |
| `test_domain_fsmo.py` | FSMO role identification (`modules/domain.py`): PDC / RID / Infrastructure matched distinctly, DNS-partition Infrastructure objects excluded. |
| `test_sids.py` | SID privilege classification (`utils/sids.py`): `is_privileged_sid` (current-domain scope) vs `privileged_rid_of` (domain-agnostic — flags a foreign privileged RID such as another domain's -512/-519 in sIDHistory). |

These guard the false-positive / false-negative fixes — the kind of regression
that is invisible in a smoke test because the tool still runs, it just reports
the wrong thing. Add a case here when you touch a parser or a finding rule.

`sd_helpers.py` builds Security Descriptors / ACEs (incl. object and callback
forms); extend it rather than re-deriving byte layouts in each test.
