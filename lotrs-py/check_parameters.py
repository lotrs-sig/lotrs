#!/usr/bin/env python3
"""Check the release manifest and Python profiles without paper sources or Sage.

Rust checks the same manifest in tests/parameters.rs. Sage additionally
checks exact prime selection and the estimator's derived bounds.
"""
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lotrs-py"))
from params import PRODUCTION_PARAMS, BENCH_PARAMS, BENCH_4OF32


def main():
    p = json.loads((ROOT / "parameters.json").read_text())
    for field, value in p.items():
        assert getattr(PRODUCTION_PARAMS, field) == value, field
    for profile in (PRODUCTION_PARAMS, BENCH_PARAMS, BENCH_4OF32):
        for field, value in p.items():
            if field not in ("name", "beta", "T", "phi"):
                assert getattr(profile, field) == value, (profile.name, field)
        assert profile.phi == max(22 * profile.T, 1100)
        profile.check_security()
    assert p["q"] == 2**43 - 67
    assert p["q_hat"] == 2**35 - 451
    print("Artifact manifest and Python profiles agree; parameter conditions pass.")


if __name__ == "__main__":
    main()
