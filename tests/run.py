#!/usr/bin/env python3
"""Zero-dependency test runner — no pytest required.

    python3 tests/run.py            # stdlib only
    python3 -m pytest tests/ -q     # same tests under pytest (if installed)

Discovers every `test_*` function in the listed modules, runs it, and reports.
Exit code is non-zero if any test fails (CI-friendly).
"""
import importlib
import os
import sys
import traceback

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

TEST_MODULES = [
    "tests.test_acls_dacl",
    "tests.test_domain_fsmo",
]


def main() -> int:
    passed, failed, fails = 0, 0, []
    for modname in TEST_MODULES:
        mod = importlib.import_module(modname)
        for name in sorted(vars(mod)):
            fn = getattr(mod, name)
            if not (name.startswith("test_") and callable(fn)):
                continue
            try:
                fn()
                passed += 1
                print(f"  [PASS] {modname}.{name}")
            except Exception as e:  # noqa: BLE001 — a test runner wants them all
                failed += 1
                fails.append(f"{modname}.{name}")
                print(f"  [FAIL] {modname}.{name}: {e}")
                traceback.print_exc()
    print(f"\n{passed} passed, {failed} failed")
    if fails:
        print("FAILURES: " + ", ".join(fails))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
