# pass-fix report
- privacy.py `_label_class`: label exactly `pass` (bare lowercase, not a flag; flags carry leading dashes) returns None. DB_PASS, db-pass, PASS, --pass stay password class.
- tests/test_privacy.py: N32-N34 fixtures; new test for DB_PASS/db-pass/PASS/--pass still redacted with label kept.
- RED: 3 failures in test_must_not_flag (e.g. `[Fix pass: [REDACTED:context] helpers]`). GREEN: 49 tests OK.
- Gate: full suite OK, schema check OK, diff --check clean, coverage 94%, erased.
- Spec amended (password bullet exception + N32-N34 rows). CHANGELOG unchanged (existing bullet needs no word).
