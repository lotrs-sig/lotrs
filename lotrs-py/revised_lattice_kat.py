#!/usr/bin/env python3
"""Cross-language KAT at the production lattice, with N=4/T=2 for fast testing.

Keeps all production lattice dimensions, moduli and samplers; only the
ring size and threshold are reduced; phi retains the regularity floor. This is a
conformance fixture, not a production benchmark or security estimate.
Run from any directory, using the Python reference's dependencies.
"""
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lotrs-py"))
from params import PRODUCTION_PARAMS
from vectors import generate


def generate_kat():
    overrides = dict(beta=4, T=2)
    par = replace(PRODUCTION_PARAMS, **overrides)
    par.check_security()
    vector = generate(par)
    assert vector["verification"], "generated signature failed verification"

    def digest(encoded):
        return hashlib.sha3_256(bytes.fromhex(encoded)).hexdigest()

    return {
        "schema_version": vector["schema_version"],
        "base_parameters": json.loads((ROOT / "parameters.json").read_text()),
        "overrides": overrides,
        "pp_seed": vector["pp_seed"],
        "signing_seed": vector["signing_seed"],
        "ell": vector["ell"],
        "message": vector["message"],
        "pp_sha3_256": digest(vector["pp_bytes"]),
        "keygen": [dict(col=key["col"], row=key["row"], seed=key["seed"],
                        pk_sha3_256=digest(key["pk_bytes"]))
                   for key in vector["keygen"]],
        "signature_byte_length": vector["signature"]["byte_length"],
        "signature_sha3_256": digest(vector["signature"]["bytes"]),
    }


def main():
    assert sys.argv[1:] in ([], ["--write"]), "usage: revised_lattice_kat.py [--write]"
    actual = generate_kat()
    path = ROOT / "lotrs-py/revised_lattice_kat.json"
    if sys.argv[1:] == ["--write"]:
        path.write_text(json.dumps(actual, indent=2) + "\n")
        print("Wrote production-lattice KAT; run Rust tests to cross-check it.")
    else:
        expected = json.loads(path.read_text())
        assert actual == expected, "production-lattice KAT mismatch"
        print("Production-lattice KAT matches; signature verifies in Python.")


if __name__ == "__main__":
    main()
