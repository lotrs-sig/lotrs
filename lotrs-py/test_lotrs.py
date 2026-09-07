"""
test_lotrs.py -- Unit and end-to-end tests for LoTRS.
"""

from params import TEST_PARAMS
from lotrs import LoTRS
from ring import Ring

# A single shared scheme instance (CDT building is expensive).
_scheme = None


def _get_scheme():
    global _scheme
    if _scheme is None:
        _scheme = LoTRS(TEST_PARAMS)
    return _scheme


def _make_ring(par):
    """Generate a full PK table + secret keys for testing."""
    scheme = _get_scheme()
    pp = scheme.setup(b"\x00" * 32)
    pk_table = []
    all_sks = []
    for col in range(par.N):
        cpks, csks = [], []
        for row in range(par.T):
            seed = bytes([col, row]) + b"\x00" * 30
            sk, pk = scheme.keygen(pp, seed)
            csks.append(sk)
            cpks.append(pk)
        pk_table.append(cpks)
        all_sks.append(csks)
    return pp, pk_table, all_sks


# ===========================================================================
#  Unit tests
# ===========================================================================

# ---- keygen --------------------------------------------------------------

def test_keygen_determinism():
    """Same seed produces same keypair."""
    scheme = _get_scheme()
    pp = scheme.setup(b"\x00" * 32)
    sk1, pk1 = scheme.keygen(pp, b"\xAB" * 32)
    sk2, pk2 = scheme.keygen(pp, b"\xAB" * 32)
    assert sk1 == sk2
    assert pk1 == pk2


def test_keygen_different_seeds():
    """Different seeds produce different keys."""
    scheme = _get_scheme()
    pp = scheme.setup(b"\x00" * 32)
    _, pk1 = scheme.keygen(pp, b"\x01" * 32)
    _, pk2 = scheme.keygen(pp, b"\x02" * 32)
    assert pk1 != pk2


def test_keygen_public_key_relation():
    """pk = [A | I] * sk  holds."""
    scheme = _get_scheme()
    par = TEST_PARAMS
    Rq = scheme.Rq
    pp = scheme.setup(b"\x00" * 32)
    sk, pk = scheme.keygen(pp, b"\xCC" * 32)

    A = scheme._expand_A(pp)
    A_bar = scheme._augment_I(A, par.k)
    pk_check = Rq.mat_vec(A_bar, sk)
    assert pk == pk_check


# ---- kagg ----------------------------------------------------------------

def test_kagg_determinism():
    scheme = _get_scheme()
    par = TEST_PARAMS
    pp, pk_table, _ = _make_ring(par)
    agg1 = scheme.kagg(pk_table)
    agg2 = scheme.kagg(pk_table)
    assert agg1 == agg2


# ---- sign1 ---------------------------------------------------------------

def test_sign1_determinism():
    scheme = _get_scheme()
    par = TEST_PARAMS
    pp, pk_table, all_sks = _make_ring(par)
    ell = 0
    rho = b"\xDD" * 32
    local_seed = b"\xEE" * 32
    st1, com1 = scheme.sign1(
        pp, all_sks[ell][0], 0, ell, b"msg", pk_table, rho, 0, local_seed)
    st2, com2 = scheme.sign1(
        pp, all_sks[ell][0], 0, ell, b"msg", pk_table, rho, 0, local_seed)
    assert com1 == com2


def test_sign1_private_session_randomness():
    """Shared proof randomness does not determine a signer's local masks."""
    scheme = _get_scheme()
    pp, table, sks = _make_ring(TEST_PARAMS)
    rho = b"\xDD" * 32
    args = (pp, sks[0][0], 0, 0, b"private masks", table, rho, 0)
    first, com1 = scheme.sign1(*args, b"\x11" * 32)
    second, com2 = scheme.sign1(*args, b"\x22" * 32)
    assert first["rho"] == second["rho"]
    assert first["y_list"] != second["y_list"]
    assert first["r_list"] != second["r_list"]
    assert com1 != com2


def test_pk_table_column_injectivity():
    """Distinct keys are required within columns; cross-column reuse is valid."""
    scheme = _get_scheme()
    pp, table, _ = _make_ring(TEST_PARAMS)
    assert scheme._valid_pk_table(table)
    repeated_columns = [table[0] for _ in range(TEST_PARAMS.N)]
    assert scheme._valid_pk_table(repeated_columns)
    repeated_rows = [[col[0]] * TEST_PARAMS.T for col in table]
    assert not scheme._valid_pk_table(repeated_rows)
    assert not scheme.verify(pp, b"invalid table", {}, repeated_rows)
    try:
        scheme.sign(pp, [None] * TEST_PARAMS.T, 0, b"invalid table",
                    repeated_rows, b"\x33" * 32)
    except ValueError:
        pass
    else:
        raise AssertionError("sign must validate the table before using keys")


# ===========================================================================
#  End-to-end tests
# ===========================================================================

def test_honest_sign_verify():
    """Full signing ceremony followed by verification."""
    scheme = _get_scheme()
    par = TEST_PARAMS
    pp, pk_table, all_sks = _make_ring(par)

    ell = 1
    mu = b"end-to-end test"
    sks = all_sks[ell]

    sig = scheme.sign(pp, sks, ell, mu, pk_table, b"\xEE" * 32)
    assert sig is not None, "signing should succeed"
    assert scheme.verify(pp, mu, sig, pk_table), \
        "honest signature must verify"


def test_wrong_message_rejects():
    """Verification must fail for a different message."""
    scheme = _get_scheme()
    par = TEST_PARAMS
    pp, pk_table, all_sks = _make_ring(par)

    ell = 0
    sks = all_sks[ell]

    sig = scheme.sign(pp, sks, ell, b"real message", pk_table,
                      b"\x11" * 32)
    assert not scheme.verify(pp, b"wrong message", sig, pk_table)


def test_corrupted_z_rejects():
    """Flipping a coefficient in z_tilde should break verification."""
    scheme = _get_scheme()
    par = TEST_PARAMS
    pp, pk_table, all_sks = _make_ring(par)

    ell = 2
    mu = b"tamper test"
    sks = all_sks[ell]

    sig = scheme.sign(pp, sks, ell, mu, pk_table, b"\x22" * 32)
    assert scheme.verify(pp, mu, sig, pk_table)

    # corrupt one coefficient
    z = sig["z_tilde"]
    z[0] = list(z[0])                    # make mutable
    z[0][0] = (z[0][0] + 1) % par.q
    sig["z_tilde"] = z

    assert not scheme.verify(pp, mu, sig, pk_table)


def test_kat_determinism():
    """
    Two independent sign() calls with the same seed must produce
    byte-identical signatures.
    """
    scheme = _get_scheme()
    par = TEST_PARAMS
    pp, pk_table, all_sks = _make_ring(par)

    ell = 1
    mu = b"KAT check"
    sks = all_sks[ell]
    seed = b"\x33" * 32

    sig1 = scheme.sign(pp, sks, ell, mu, pk_table, seed)
    sig2 = scheme.sign(pp, sks, ell, mu, pk_table, seed)

    assert sig1["z_tilde"] == sig2["z_tilde"]
    assert sig1["r_tilde"] == sig2["r_tilde"]
    assert sig1["e_tilde"] == sig2["e_tilde"]
    assert sig1["pi"]["x"] == sig2["pi"]["x"]
    assert sig1["pi"]["f1"] == sig2["pi"]["f1"]
    assert sig1["pi"]["z_b"] == sig2["pi"]["z_b"]


def test_different_columns():
    """Signing with different hidden columns should all verify."""
    scheme = _get_scheme()
    par = TEST_PARAMS
    pp, pk_table, all_sks = _make_ring(par)

    mu = b"multi-column"
    for ell in range(par.N):
        sks = all_sks[ell]
        sig = scheme.sign(pp, sks, ell, mu, pk_table,
                          bytes([ell]) * 32)
        assert scheme.verify(pp, mu, sig, pk_table), \
            f"verification failed for ell={ell}"


# ===========================================================================
#  Runner
# ===========================================================================

if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    print(f"Running {len(tests)} tests (CDT build may take a few seconds) ...")
    for t in tests:
        t()
        print(f"  {t.__name__}: ok")
    print(f"test_lotrs.py: {len(tests)} tests passed")
