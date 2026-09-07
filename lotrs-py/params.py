"""
params.py -- Parameter sets for LoTRS.

Defines base parameters and computes all derived bounds from Table 2
of the LoTRS paper.
"""

import math
from dataclasses import dataclass


@dataclass(frozen=True)
class LoTRSParams:
    """
    LoTRS parameter set.  See Table 2 in the paper.

    All derived quantities (bounds, Gaussian widths, etc.) are computed
    from the base parameters listed here.
    """

    # -- identifier --------------------------------------------------------
    name: str

    # -- ring geometry -----------------------------------------------------
    d: int                 # ring dimension  (power of 2)
    q: int                 # main modulus    (prime)
    q_hat: int             # binary-proof modulus  (prime)

    # -- structure ---------------------------------------------------------
    kappa: int             # log_beta(N)   (number of base-beta digits)
    beta: int              # base for column-index encoding
    T: int                 # threshold  (number of real signers)

    # -- matrix dimensions -------------------------------------------------
    k: int                 # rows of  A
    l: int                 # columns of  A  (signing-key dimension)
    l_prime: int           # columns of  B  (dual-key dimension)
    n_hat: int             # rows of  G  (binary proof)
    k_hat: int             # extra columns in  G

    # -- challenge / key ---------------------------------------------------
    w: int                 # challenge weight   ||x||_1 = w
    eta: int               # secret-key bound   ||s||_inf <= eta

    # -- rejection sampling ------------------------------------------------
    phi: float             # slack factor for z_u  (phi_0 = phi)
    phi_a: float           # slack factor for f_1
    phi_b: float           # slack factor for z_b

    # -- bit-dropping (Bai-Galbraith compression) --------------------------
    K_A: int
    K_B: int
    K_w: int

    # -- tunables ----------------------------------------------------------
    lam: int = 128         # security parameter  (bits)
    max_attempts: int = 2000

    # -- dual secret bound (eta_prime_s in the estimator) -----------------
    # Defaults to eta; required to match lotrs_estimate.py for the
    # dual-side B_0_prime when a separate bound is used.
    eta_prime: int = -1    # sentinel: use eta

    # -- Gaussian tail factor for aggregated l2-norm bounds ---------------
    # Estimator uses t = 1.2 (high-probability tail bound).  For small
    # test dimensions this tail is reached occasionally, so TEST_PARAMS
    # overrides with a larger value.
    tail_t: float = 1.2

    # Coefficientwise aggregate-response bounds used by the infinity-norm
    # DualMS reduction (September paper, Table 2).
    tail_inf: float = 12.0

    # -- Mask Gaussian backend ---------------------------------------------
    # Declares which Gaussian sampler `LoTRS` uses for the two masking
    # widths sigma_0 / sigma_0_prime.  Kept explicit per parameter set
    # rather than auto-selected from a sigma threshold inside the scheme
    # constructor — `lotrs.py::LoTRS.__init__` reads this field directly.
    # sigma_a / sigma_b are always CDT and do not depend on this field.
    # Allowed values: "cdt", "facct".
    mask_sampler: str = "cdt"

    # -- Tail-budget for the binary-proof infinity-norm checks ------------
    # Paper (Appendix, "Choice of B_{f_1}, B_{f_0}, B_{g_0}, B_{g_1}")
    # splits a total failure budget eps_tot uniformly across the four
    # checks (eps_each = eps_tot / 4).  Used to size B_f1 / B_f0.
    # Default 0.01 matches estimator/lotrs_finder.py:350 convention:
    # the bound checks are honest-restart triggers, not cryptographic
    # security bounds, so a ~1% per-attempt restart budget is adequate.
    eps_tot: float = 0.01

    # ---- derived properties ----------------------------------------------

    @property
    def N(self):
        """Ring size  N = beta^kappa."""
        return self.beta ** self.kappa

    @property
    def eta_p(self):
        """Dual secret bound; defaults to eta if not explicitly set."""
        return self.eta if self.eta_prime < 0 else self.eta_prime

    # -- Gaussian widths  (Table 2) ----------------------------------------

    @property
    def B_a(self):
        """sqrt(kappa * w)  -- base mask scale for a_{j,i}."""
        return math.sqrt(self.kappa * self.w)

    @property
    def B_b(self):
        """sqrt(d * (n_hat + k_hat)) * w  -- base scale for z_b.

        Bounds  ||x * r_b||_2  over the (n_hat + k_hat)-vector
        r_b in S_1^{n_hat+k_hat}: each ring entry has ||r_b[i]||_inf <= 1
        and ||x||_1 = w, so ||x*r_b[i]||_2 <= sqrt(d) * w; aggregating
        over the (n_hat+k_hat) entries gives sqrt(d * (n_hat+k_hat)) * w.
        Matches the paper bound for B_b.
        """
        return math.sqrt(self.d * (self.n_hat + self.k_hat)) * self.w

    @property
    def B_0(self):
        """
        Shift bound for z_u rejection sampling (kappa = 1).

        B_0 = sqrt(d(l+k)) * eta * w^{kappa+1}

        Matches lotrs_estimate.py line 105.  For kappa > 1, the paper's
        formula adds a 6*sigma_s*(kappa-1)*w^{kappa-1} term but we do
        not support that case.
        """
        if self.kappa != 1:
            raise NotImplementedError("B_0 derivation for kappa > 1")
        return (math.sqrt(self.d * (self.l + self.k))
                * self.eta
                * self.w ** (self.kappa + 1))

    @property
    def B_0_prime(self):
        """
        Shift bound for r_u (dual side).

        B_0' = sqrt(d(l'+k)) * eta_prime * w^{kappa+1}

        Matches lotrs_estimate.py line 106.
        """
        if self.kappa != 1:
            raise NotImplementedError("B_0' derivation for kappa > 1")
        return (math.sqrt(self.d * (self.l_prime + self.k))
                * self.eta_p
                * self.w ** (self.kappa + 1))

    @property
    def sigma_0(self):
        """Gaussian width for  y_{u,0}  and  z_u  masking."""
        return self.phi * self.B_0

    @property
    def sigma_0_prime(self):
        """Gaussian width for  r_{u,0}  masking."""
        return self.phi * self.B_0_prime

    @property
    def sigma_a(self):
        """Gaussian width for  f_1  in Sign_bin."""
        return self.phi_a * self.B_a

    @property
    def sigma_b(self):
        """Gaussian width for  z_b  in Sign_bin."""
        return self.phi_b * self.B_b

    @property
    def sigma_tilde_z(self):
        return self.sigma_0 * math.sqrt(self.T)

    @property
    def sigma_tilde_r(self):
        return self.sigma_0_prime * math.sqrt(self.T)

    @property
    def sigma_tilde_e(self):
        """Independent error variances add (B_hat_0 in Table 2)."""
        return math.sqrt(self.sigma_0 ** 2 + self.sigma_0_prime ** 2) * math.sqrt(self.T)

    @property
    def B_tilde_z(self):
        return self.tail_t * self.sigma_tilde_z * math.sqrt(self.d * self.l)

    @property
    def B_tilde_r(self):
        return self.tail_t * self.sigma_tilde_r * math.sqrt(self.d * self.l_prime)

    @property
    def B_tilde_e(self):
        return self.tail_t * self.sigma_tilde_e * math.sqrt(self.d * self.k)

    @property
    def B_tilde_z_inf(self):
        return self.tail_inf * self.sigma_tilde_z

    @property
    def B_tilde_r_inf(self):
        return self.tail_inf * self.sigma_tilde_r

    @property
    def B_tilde_e_inf(self):
        return self.tail_inf * self.sigma_tilde_e

    # -- regularity widths (sigma_s, sigma_s_prime) ------------------------

    @property
    def sigma_s(self):
        """DualMS regularity width for primary side.

        sigma_s := (2d / sqrt(2*pi)) * q^{k/(l+k) + 2/(d*(l+k))}

        Required by condition 2 in Section 3.1; checked by
        check_sigma() via estimator/lotrs_param_checks.py.
        """
        exp = (self.k / (self.l + self.k)
               + 2.0 / (self.d * (self.l + self.k)))
        return (2 * self.d / math.sqrt(2 * math.pi)) * (self.q ** exp)

    @property
    def sigma_s_prime(self):
        """DualMS regularity width for dual side (uses l' instead of l)."""
        exp = (self.k / (self.l_prime + self.k)
               + 2.0 / (self.d * (self.l_prime + self.k)))
        return (2 * self.d / math.sqrt(2 * math.pi)) * (self.q ** exp)

    # -- restart multipliers -----------------------------------------------

    def mu(self, phi_val):
        """mu(phi) = exp(12/phi + 1/(2 phi^2))."""
        return math.exp(12.0 / phi_val + 1.0 / (2.0 * phi_val ** 2))

    @property
    def mu_phi(self):
        return self.mu(self.phi)

    # -- binary-proof bounds -----------------------------------------------
    #
    # The paper (Appendix "Choice of B_{f_1}, B_{f_0}, B_{g_0}, B_{g_1}")
    # derives high-probability tail bounds for f_1, f_0 from a coefficient-
    # wise Gaussian argument and then propagates them through the quadratic
    # form  g_{j,i} = f_{j,i} (x - f_{j,i})  using Lemma 2 (||x||_1 = w,
    # ||f^2||_inf <= d * ||f||_inf^2).  This supersedes the earlier
    # lotrs_finder.py formulas (6*phi_a*B_a, d*((beta-1)*B_f1)^2, ...).

    @property
    def _eps_each(self):
        """Per-check tail budget = eps_tot / 4 (four bound checks)."""
        return self.eps_tot / 4.0

    @property
    def _tau_f1(self):
        """sqrt(2 ln(2 M_{f_1} / eps_each))  with  M_{f_1} = kappa(beta-1)d."""
        M = self.kappa * (self.beta - 1) * self.d
        return math.sqrt(2.0 * math.log(2.0 * M / self._eps_each))

    @property
    def _tau_f0(self):
        """sqrt(2 ln(2 M_{f_0} / eps_each))  with  M_{f_0} = kappa d."""
        M = self.kappa * self.d
        return math.sqrt(2.0 * math.log(2.0 * M / self._eps_each))

    @property
    def B_f1(self):
        """Per-coefficient bound on transmitted f_{j,i} (i >= 1).

            B_{f_1} = 1 + tau_{f_1} * sigma_a

        where  sigma_a = phi_a * sqrt(kappa*w)  and the "+1" accounts for
        the  x*delta_{ell_j,i}  shift.  Union-bounded over kappa(beta-1)d
        coefficients.
        """
        return 1.0 + self._tau_f1 * self.sigma_a

    @property
    def B_f0(self):
        """Per-coefficient bound on the reconstructed  f_{j,0}.

            B_{f_0} = 1 + tau_{f_0} * sqrt(beta-1) * sigma_a

        f_{j,0} = x*delta_{ell_j,0} - sum_{i=1..beta-1} a_{j,i} is the
        sum of (beta-1) independent discrete Gaussians of width sigma_a
        plus a deterministic shift of magnitude <= 1.  Union-bounded
        over  M_{f_0} = kappa d  coefficients.
        """
        return 1.0 + self._tau_f0 * math.sqrt(self.beta - 1) * self.sigma_a

    @property
    def B_g0(self):
        """Bound on g_{j,0} = f_{j,0} (x - f_{j,0}).

            B_{g_0} = w * B_{f_0} + d * B_{f_0}^2
        """
        return self.w * self.B_f0 + self.d * self.B_f0 * self.B_f0

    @property
    def B_g1(self):
        """Bound on g_{j,i} = f_{j,i} (x - f_{j,i}) for i >= 1.

            B_{g_1} = w * B_{f_1} + d * B_{f_1}^2
        """
        return self.w * self.B_f1 + self.d * self.B_f1 * self.B_f1

    @property
    def B_eta_w(self):
        """Verifier residual bound  B_{eta,w}."""
        return (1 << (self.K_w - 1)) * self.kappa * self.w ** max(
            self.kappa - 1, 0)

    # -- matrix G column count ---------------------------------------------

    @property
    def G_cols(self):
        return self.n_hat + self.k_hat + 2 * self.kappa * self.beta

    # -- sanity checks -----------------------------------------------------

    def check(self):
        """Verify correctness-relevant parameter consistency.

        Checks primes mod 8, power-of-2 ring dimension, and that each
        Gaussian width fits inside the ring it samples into.  Does NOT
        check security/regularity (see :meth:`check_security`); a
        toy parameter set can satisfy correctness without being
        cryptographically secure.
        """
        assert self.d > 0 and (self.d & (self.d - 1)) == 0, \
            "d must be a power of 2"
        assert self.N == self.beta ** self.kappa
        assert self.q % 8 == 5, f"q = {self.q} must be 5 mod 8 (Lemma 1)"
        assert self.q_hat % 8 == 5, \
            f"q_hat = {self.q_hat} must be 5 mod 8 (Lemma 1)"

        # Gaussian widths must fit comfortably inside q/2 of the ring
        # they sample into.  sigma_0, sigma_0' are for DualMS (R_q);
        # sigma_a, sigma_b are for the binary proof (R_qhat).
        _checks = [
            ("sigma_0",  self.sigma_0,        self.q,     "q"),
            ("sigma_0'", self.sigma_0_prime,  self.q,     "q"),
            ("sigma_a",  self.sigma_a,        self.q_hat, "q_hat"),
            ("sigma_b",  self.sigma_b,        self.q_hat, "q_hat"),
        ]
        for label, sigma, modulus, mod_name in _checks:
            headroom = modulus // (12 * max(1, sigma))
            assert headroom >= 1, \
                f"{label}={sigma:.0f} too large for {mod_name}={modulus}"

        # mask_sampler must be declared and consistent with sigma_0 /
        # sigma_0_prime.  We don't auto-dispatch on the threshold at
        # scheme-construction time — the declaration has to match.
        assert self.mask_sampler in ("cdt", "facct"), \
            f"unsupported mask_sampler = {self.mask_sampler!r}"
        # Local import avoids a top-level cycle: params.py is imported
        # by sample.py via tests; sample.py imports params indirectly
        # through lotrs.py in a few places.
        from sample import needs_large_gaussian_sampler
        if self.mask_sampler == "cdt":
            for label, sigma in (("sigma_0", self.sigma_0),
                                 ("sigma_0_prime", self.sigma_0_prime)):
                assert not needs_large_gaussian_sampler(sigma), (
                    f"{self.name}: declared mask_sampler=\"cdt\" but "
                    f"{label}={sigma:.0f} would need a table of "
                    f">1,000,000 entries — declare \"facct\" instead")

    def check_security(self):
        """Check security-relevant conditions from Section 3.1.

        Runs correctness and regularity checks plus the range-proof
        condition from Lemma 1:
            q_hat > max{ d * (2 + 12*phi_a*B_a)^2,  2*N^2 }.
        Does NOT claim to replace the sage-based estimator — for real
        security validation use estimator/lotrs_estimate.py.
        """
        self.check()

        for label, width, threshold in (
                ("sigma_0", self.sigma_0, self.sigma_s),
                ("sigma_0_prime", self.sigma_0_prime, self.sigma_s_prime)):
            assert width > threshold, (
                f"regularity: {label}={width} must exceed {threshold}")

        # Range-proof / well-formedness condition (Lemma 1).
        # Mirrors estimator/lotrs_param_checks.py
        # checkRangeProofCondition for the first branch.
        rhs1 = self.d * (2 + 12 * self.phi_a * self.B_a) ** 2
        rhs2 = 2 * self.N ** 2
        rhs = max(rhs1, rhs2)
        if not self.q_hat > rhs:
            raise AssertionError(
                f"range-proof: q_hat={self.q_hat} "
                f"not > max(d*(2+12*phi_a*B_a)^2, 2*N^2)={rhs:.0f}")

        # Challenge-difference invertibility (Lemma 1):
        #   2 * ||x||_inf < sqrt(q/2) and sqrt(q_hat/2)
        # x_inf_norm = 1 for our challenge set.
        if not 2 < math.sqrt(self.q / 2):
            raise AssertionError(
                f"challenge invertibility mod q: q={self.q} too small")
        if not 2 < math.sqrt(self.q_hat / 2):
            raise AssertionError(
                f"challenge invertibility mod q_hat: q_hat={self.q_hat}")


# ---- concrete parameter sets ---------------------------------------------

# Small test set  (fast, NOT secure -- for correctness testing only).
# N=4, T=2, d=32.  q != q_hat to exercise both rings.
TEST_PARAMS = LoTRSParams(
    name="test-32",
    d=32,
    q=4194389,           # prime,  5 mod 8,  ~2^22
    q_hat=7000061,       # distinct prime,  5 mod 8,  ~2^23
    kappa=1,
    beta=4,
    T=2,
    k=2,
    l=2,
    l_prime=3,
    n_hat=2,
    k_hat=3,
    w=4,
    eta=1,
    phi=12.0,
    phi_a=12.0,
    phi_b=12.0,
    K_A=13,
    K_B=4,
    K_w=5,
    lam=128,
    max_attempts=2000,
    tail_t=2.0,    # loose tail factor for small test dimensions
    mask_sampler="cdt",
)


# Production parameter set: 50-of-100 threshold signature.
# Base values match parameters.json and estimator/lotrs_estimate.py.
# Revised lattice dimensions and exact primes for the September paper.
# Security and restart estimates must use the verifier's actual bounds.
PRODUCTION_PARAMS = LoTRSParams(
    name="lotrs-128",
    d=128,
    q=8796093022141,    # largest prime < 2^43 with q ≡ 5 mod 8
    q_hat=34359737917,  # largest prime < 2^35 with q_hat ≡ 5 mod 8
                         # (prime_5_mod_8(35) in lotrs_estimate.py)
    kappa=1,
    beta=100,
    T=50,
    k=14,
    l=20,
    l_prime=21,
    n_hat=12,
    k_hat=11,
    w=31,
    eta=1,
    phi=1100.0,          # 22 * T  per lotrs_estimate.py
    phi_a=24.0,          # fixed across T
    phi_b=24.0,
    K_A=28,              # ceil(log2(n̂·d·(w·2^K_B−1)/ln μ_BG_target))
                         # with μ_BG_target = 1.01
    K_B=5,
    K_w=5,
    lam=128,
    max_attempts=200,
    mask_sampler="facct",    # sigma_0 ≈ 6.97e7 — CDT would be multi-GB
)


# Benchmark parameter set: 16-of-32 threshold signature.
# Shares the PRODUCTION lattice.
BENCH_PARAMS = LoTRSParams(
    name="lotrs-bench-16of32",
    d=128,
    q=8796093022141,
    q_hat=34359737917,
    kappa=1,
    beta=32,
    T=16,
    k=14,
    l=20,
    l_prime=21,
    n_hat=12,
    k_hat=11,
    w=31,
    eta=1,
    phi=1100.0,          # max(22 * T, 1100): regularity floor
    phi_a=24.0,
    phi_b=24.0,
    K_A=28,
    K_B=5,
    K_w=5,
    lam=128,
    max_attempts=200,
    mask_sampler="facct",
)


# 4-of-32 benchmark-only variant.  Shares the BENCH lattice; phi_a
# is identical because the finder doesn't scale phi_a with T.
BENCH_4OF32 = LoTRSParams(
    name="lotrs-bench-4of32",
    d=128,
    q=8796093022141,
    q_hat=34359737917,
    kappa=1,
    beta=32,
    T=4,
    k=14,
    l=20,
    l_prime=21,
    n_hat=12,
    k_hat=11,
    w=31,
    eta=1,
    phi=1100.0,          # max(22 * T, 1100): regularity floor
    phi_a=24.0,
    phi_b=24.0,
    K_A=28,
    K_B=5,
    K_w=5,
    lam=128,
    max_attempts=200,
    mask_sampler="facct",
)


# --------------------------------------------------------------------------
if __name__ == "__main__":
    for label, p in [("TEST_PARAMS", TEST_PARAMS),
                     ("BENCH_PARAMS", BENCH_PARAMS),
                     ("PRODUCTION_PARAMS", PRODUCTION_PARAMS)]:
        p.check()
        print(f"--- {label} ({p.name}) ---")
        print(f"  N={p.N}  T={p.T}  d={p.d}  q≈2^{p.q.bit_length()}")
        print(f"  sigma_0    = {p.sigma_0:.1f}")
        print(f"  sigma_0'   = {p.sigma_0_prime:.1f}")
        print(f"  sigma_a    = {p.sigma_a:.1f}")
        print(f"  sigma_b    = {p.sigma_b:.1f}")
        print(f"  mu(phi)    = {p.mu_phi:.6f}")
        print(f"  mu(phi)^T  = {p.mu_phi ** p.T:.3f}")
        print(f"  G columns  = {p.G_cols}")
        print()
    print("params.py: all self-tests passed")
