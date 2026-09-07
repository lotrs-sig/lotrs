"""Sage regression checks joining estimator bounds to the actual verifier.

Run `make test`; this does not run the expensive lattice-cost estimators.
"""
import contextlib
import io
import math
from pathlib import Path
import sys
import unittest

from lotrs_estimate import artifact_parameters
from lotrs_finder import (setBinASISBounds, mergeToFiveBuckets,
                          setDualMSASISBounds, calculate_PK, number_reps)
from lotrs_param_checks import check_q_prime_5_mod_8, checkRangeProofCondition

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lotrs-py"))
from params import PRODUCTION_PARAMS


class AlignmentTests(unittest.TestCase):
    def setUp(self):
        self.output = contextlib.redirect_stdout(io.StringIO())
        self.output.__enter__()
        self.addCleanup(self.output.__exit__, None, None, None)
        self.p = PRODUCTION_PARAMS

    def test_manifest_and_exact_primes(self):
        for field, value in artifact_parameters().items():
            self.assertEqual(getattr(self.p, field), value)
        self.assertTrue(check_q_prime_5_mod_8(self.p.q))
        self.assertTrue(check_q_prime_5_mod_8(self.p.q_hat))
        self.assertFalse(check_q_prime_5_mod_8(45))  # composite, 5 mod 8

    def test_binary_buckets_preserve_every_column(self):
        p = self.p
        buckets = setBinASISBounds(p.beta, p.kappa, p.d, p.w, p.n_hat,
                                  p.k_hat, p.phi_a, p.phi_b, p.K_B, p.eps_tot)
        expected = sorted([(p.B_f1, p.beta-1), (p.B_f0, 1),
                           (p.B_g1, p.beta-1), (p.B_g0, 1),
                           (6*p.sigma_b, p.n_hat+p.k_hat)])
        actual = sorted((float(b), int(m)) for b, m in buckets
                        if int(m) != 4*p.n_hat)
        for (bound, width), (want, columns) in zip(actual, expected):
            self.assertTrue(math.isclose(bound, want, rel_tol=1e-12))
            self.assertEqual(width, columns)
        merged = mergeToFiveBuckets(buckets)
        self.assertEqual(len(merged), 5)
        self.assertEqual(sum(m for _, m in merged), 271)
        self.assertEqual(sum(m for _, m in buckets), 271)
        # Each bound relaxation must preserve at least as many columns
        # at every original threshold.
        for bound, _ in buckets:
            self.assertGreaterEqual(sum(m for b, m in merged if b >= bound),
                                    sum(m for b, m in buckets if b >= bound))

    def test_dualms_buckets_use_verifier_infinity_bounds(self):
        p = self.p
        buckets = setDualMSASISBounds(p.T, p.kappa, p.d, p.w, p.k, p.l,
            p.l_prime, p.eta, p.eta_p, p.tail_t, math.log2(p.q), p.phi,
            p.K_w, True, t_inf=p.tail_inf)
        determinant = 2*p.w  # kappa=1
        factor = 4*determinant
        expected = sorted([(2*determinant**2, 1),
            (factor*p.B_tilde_z_inf, p.l), (factor*p.B_tilde_r_inf, p.l_prime),
            (factor*p.B_tilde_e_inf, p.k), (factor*p.B_eta_w, p.k)])
        self.assertEqual(sum(m for _, m in buckets), 1+p.l+p.l_prime+2*p.k)
        for (bound, width), (want, columns) in zip(sorted(buckets), expected):
            self.assertTrue(math.isclose(float(bound), want, rel_tol=1e-12))
            self.assertEqual(width, columns)

    def test_public_key_sizes_use_whole_bits(self):
        p = self.p
        pk, table = calculate_PK(p.T, p.N, p.k, p.d, math.log2(p.q))
        self.assertEqual(pk, 77056)
        self.assertEqual(table, p.T*p.N*pk)
        with self.assertRaises(ValueError):
            calculate_PK(p.T, p.N, p.k, p.d, math.log2(p.q), M=p.T-1)

    def test_soundness_branch_and_repetition_model(self):
        p = self.p
        self.assertFalse(checkRangeProofCondition(p.d, 1, p.phi_a, p.w,
                                                  p.q_hat, N=10**6))
        reps = number_reps(p.T, p.phi_a, p.phi_b, p.phi, p.n_hat, p.d,
                          p.w, p.K_A, p.K_B, p.K_w, p.eps_tot, True)
        self.assertTrue(4.77 < reps < 4.78)


if __name__ == "__main__":
    unittest.main()
