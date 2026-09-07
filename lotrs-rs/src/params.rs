//! Parameter sets — port of `lotrs-py/params.py`.
//!
//! Four concrete parameter sets are provided.  The three d=128 sets
//! track `estimator/lotrs_estimate.py` and share the same lattice
//! (`k=14, l=20, l'=21, n̂=12, k̂=11`,
//! `phi_a=24`, `phi_b=24`, `K_A=28`, `K_B=5`, `K_w=5`,
//! `q = largest prime < 2^43 with q ≡ 5 mod 8`,
//! `q_hat = largest prime < 2^35 with q_hat ≡ 5 mod 8`).  Only
//! `T`, `beta`, and `phi = max(22·T, 1100)` vary between them.
//!
//! * [`TEST_PARAMS`]       — small (d=32, N=4, T=2) for correctness testing.
//! * [`BENCH_4OF32`]       — 4-of-32 threshold, d=128.
//!                           Probes smaller `T` at fixed `N=32`.
//! * [`BENCH_PARAMS`]      — 16-of-32 threshold, d=128.
//! * [`PRODUCTION_PARAMS`] — 50-of-100, d=128.
//!
//! All derived quantities (bounds, Gaussian widths, etc.) are exposed
//! as `const fn` methods where possible and as regular methods
//! otherwise.  Floating-point derivations follow the Python reference
//! exactly.

#![allow(non_snake_case)]

use core::f64;

/// Which Gaussian backend `LoTRS` uses for the mask widths
/// (`sigma_0`, `sigma_0_prime`).  Declared explicitly on each
/// [`LoTRSParams`] so the scheme constructor doesn't need a threshold
/// dispatch; mirrors the `mask_sampler: str` field on the Python side.
///
/// `sigma_a` and `sigma_b` are always CDT and do not depend on this
/// enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaskSamplerKind {
    Cdt,
    Facct,
}

/// Static LoTRS parameter set.  Every field matches the Python `LoTRSParams`
/// dataclass.
#[derive(Debug, Clone, Copy)]
pub struct LoTRSParams {
    pub name: &'static str,

    // ring geometry
    pub d: usize,
    pub q: u64,
    pub q_hat: u64,

    // structure
    pub kappa: usize,
    pub beta: usize,
    pub T: usize,

    // matrix dimensions
    pub k: usize,
    pub l: usize,
    pub l_prime: usize,
    pub n_hat: usize,
    pub k_hat: usize,

    // challenge / key
    pub w: usize,
    pub eta: i32,

    // rejection sampling slack
    pub phi: f64,
    pub phi_a: f64,
    pub phi_b: f64,

    // Bai-Galbraith bit-dropping
    pub K_A: u32,
    pub K_B: u32,
    pub K_w: u32,

    // tunables
    pub lam: u32,
    pub max_attempts: u32,
    /// Sentinel `< 0` ⇒ defaults to `eta` via [`Self::eta_p`].
    pub eta_prime: i32,
    pub tail_t: f64,
    /// Coefficientwise aggregate-response tail factor (September Table 2).
    pub tail_inf: f64,

    /// Declared Gaussian backend for the two mask widths.  See
    /// [`MaskSamplerKind`].
    pub mask_sampler: MaskSamplerKind,

    /// Total tail budget for the four binary-proof bound checks
    /// (`B_{f_1}, B_{f_0}, B_{g_0}, B_{g_1}`); each check is sized so
    /// that it is violated with probability at most `eps_tot / 4` in an
    /// honest execution.  Mirrors the Python `eps_tot` field.
    pub eps_tot: f64,
}

impl LoTRSParams {
    /// Ring size `N = beta^kappa`.
    pub const fn N(&self) -> usize {
        // For kappa == 1 (the only supported value) this is simply beta.
        // General case kept for symmetry with Python.
        let mut n = 1usize;
        let mut i = 0usize;
        while i < self.kappa {
            n *= self.beta;
            i += 1;
        }
        n
    }

    /// Dual secret bound; defaults to `eta` if `eta_prime` is the sentinel.
    pub const fn eta_p(&self) -> i32 {
        if self.eta_prime < 0 {
            self.eta
        } else {
            self.eta_prime
        }
    }

    // ---- Gaussian widths (Table 2) --------------------------------------

    /// `sqrt(kappa * w)` — base mask scale for `a_{j,i}`.
    pub fn B_a(&self) -> f64 {
        ((self.kappa * self.w) as f64).sqrt()
    }

    /// `sqrt(d * (n_hat + k_hat)) * w` — base scale for `z_b`.
    /// Bounds `||x * r_b||_2` over the (n_hat + k_hat)-vector
    /// `r_b ∈ S_1^{n_hat+k_hat}`.  Matches the paper bound for B_b.
    pub fn B_b(&self) -> f64 {
        ((self.d * (self.n_hat + self.k_hat)) as f64).sqrt() * self.w as f64
    }

    /// `sqrt(d * (l + k)) * eta * w^(kappa + 1)`.
    pub fn B_0(&self) -> f64 {
        assert!(self.kappa == 1, "B_0 derivation requires kappa == 1");
        ((self.d * (self.l + self.k)) as f64).sqrt()
            * self.eta as f64
            * (self.w as f64).powi(self.kappa as i32 + 1)
    }

    /// `sqrt(d * (l' + k)) * eta_prime * w^(kappa + 1)`.
    pub fn B_0_prime(&self) -> f64 {
        assert!(self.kappa == 1, "B_0' derivation requires kappa == 1");
        ((self.d * (self.l_prime + self.k)) as f64).sqrt()
            * self.eta_p() as f64
            * (self.w as f64).powi(self.kappa as i32 + 1)
    }

    pub fn sigma_0(&self) -> f64 {
        self.phi * self.B_0()
    }
    pub fn sigma_0_prime(&self) -> f64 {
        self.phi * self.B_0_prime()
    }
    pub fn sigma_a(&self) -> f64 {
        self.phi_a * self.B_a()
    }
    pub fn sigma_b(&self) -> f64 {
        self.phi_b * self.B_b()
    }

    pub fn sigma_tilde_z(&self) -> f64 {
        self.sigma_0() * (self.T as f64).sqrt()
    }
    pub fn sigma_tilde_r(&self) -> f64 {
        self.sigma_0_prime() * (self.T as f64).sqrt()
    }
    /// Independent error variances add (B_hat_0 in Table 2).
    pub fn sigma_tilde_e(&self) -> f64 {
        (self.sigma_0().powi(2) + self.sigma_0_prime().powi(2)).sqrt() * (self.T as f64).sqrt()
    }
    pub fn B_tilde_z(&self) -> f64 {
        self.tail_t * self.sigma_tilde_z() * ((self.d * self.l) as f64).sqrt()
    }
    pub fn B_tilde_r(&self) -> f64 {
        self.tail_t * self.sigma_tilde_r() * ((self.d * self.l_prime) as f64).sqrt()
    }
    pub fn B_tilde_e(&self) -> f64 {
        self.tail_t * self.sigma_tilde_e() * ((self.d * self.k) as f64).sqrt()
    }
    pub fn B_tilde_z_inf(&self) -> f64 {
        self.tail_inf * self.sigma_tilde_z()
    }
    pub fn B_tilde_r_inf(&self) -> f64 {
        self.tail_inf * self.sigma_tilde_r()
    }
    pub fn B_tilde_e_inf(&self) -> f64 {
        self.tail_inf * self.sigma_tilde_e()
    }

    // ---- binary-proof bounds --------------------------------------------
    //
    // The paper (Appendix "Choice of B_{f_1}, B_{f_0}, B_{g_0}, B_{g_1}")
    // derives high-probability tail bounds for f_1, f_0 via coefficient-
    // wise Gaussian tail + union bound, then propagates them through the
    // quadratic form  g_{j,i} = f_{j,i}(x - f_{j,i})  using Lemma 2:
    // ||x*f||_inf <= w*||f||_inf, ||f*f||_inf <= d*||f||_inf^2.

    /// `eps_each = eps_tot / 4` — per-check tail budget.
    fn eps_each(&self) -> f64 {
        self.eps_tot / 4.0
    }

    /// `tau_{f_1} = sqrt(2 ln(2 M_{f_1} / eps_each))`, `M_{f_1} = kappa(beta-1)d`.
    fn tau_f1(&self) -> f64 {
        let m = (self.kappa * (self.beta - 1) * self.d) as f64;
        (2.0 * (2.0 * m / self.eps_each()).ln()).sqrt()
    }

    /// `tau_{f_0} = sqrt(2 ln(2 M_{f_0} / eps_each))`, `M_{f_0} = kappa d`.
    fn tau_f0(&self) -> f64 {
        let m = (self.kappa * self.d) as f64;
        (2.0 * (2.0 * m / self.eps_each()).ln()).sqrt()
    }

    /// Per-coefficient bound on transmitted `f_{j,i}` (i >= 1).
    ///
    /// `B_{f_1} = 1 + tau_{f_1} * sigma_a` where `sigma_a = phi_a*sqrt(kappa*w)`.
    pub fn B_f1(&self) -> f64 {
        1.0 + self.tau_f1() * self.sigma_a()
    }

    /// Per-coefficient bound on the reconstructed `f_{j,0}`.
    ///
    /// `B_{f_0} = 1 + tau_{f_0} * sqrt(beta-1) * sigma_a`.
    pub fn B_f0(&self) -> f64 {
        1.0 + self.tau_f0() * ((self.beta - 1) as f64).sqrt() * self.sigma_a()
    }

    /// `B_{g_0} = w * B_{f_0} + d * B_{f_0}^2`.
    pub fn B_g0(&self) -> f64 {
        let bf = self.B_f0();
        self.w as f64 * bf + self.d as f64 * bf * bf
    }

    /// `B_{g_1} = w * B_{f_1} + d * B_{f_1}^2`.
    pub fn B_g1(&self) -> f64 {
        let bf = self.B_f1();
        self.w as f64 * bf + self.d as f64 * bf * bf
    }

    /// Verifier residual bound `B_{eta, w}`.
    pub fn B_eta_w(&self) -> f64 {
        let exponent = if self.kappa > 0 { self.kappa - 1 } else { 0 };
        ((1u64 << (self.K_w - 1)) as f64)
            * self.kappa as f64
            * (self.w as f64).powi(exponent as i32)
    }

    /// Column count of the binary-proof matrix G.
    pub const fn G_cols(&self) -> usize {
        self.n_hat + self.k_hat + 2 * self.kappa * self.beta
    }

    // ---- restart multipliers --------------------------------------------

    pub fn mu(&self, phi_val: f64) -> f64 {
        (12.0 / phi_val + 1.0 / (2.0 * phi_val * phi_val)).exp()
    }

    pub fn mu_phi(&self) -> f64 {
        self.mu(self.phi)
    }
}

// ---- concrete parameter sets --------------------------------------------

/// Default `eps_tot = 0.01`.  Mirrors the Python `LoTRSParams.eps_tot`
/// and `estimator/lotrs_finder.py` convention: the B_{f_1} / B_{f_0} /
/// B_{g_0} / B_{g_1} checks are honest-restart triggers, not
/// cryptographic security bounds, so a 1%-per-attempt budget is
/// adequate.
pub const EPS_TOT_DEFAULT: f64 = 0.01;

/// Small test parameter set (d=32, N=4, T=2).  Fast; **not secure**.
/// Uses distinct `q != q_hat` to exercise both rings.  NTT fast path is
/// not enabled for d=32; schoolbook multiplication is used internally.
pub const TEST_PARAMS: LoTRSParams = LoTRSParams {
    name: "test-32",
    d: 32,
    q: 4_194_389,
    q_hat: 7_000_061,
    kappa: 1,
    beta: 4,
    T: 2,
    k: 2,
    l: 2,
    l_prime: 3,
    n_hat: 2,
    k_hat: 3,
    w: 4,
    eta: 1,
    phi: 12.0,
    phi_a: 12.0,
    phi_b: 12.0,
    K_A: 13,
    K_B: 4,
    K_w: 5,
    lam: 128,
    max_attempts: 2000,
    eta_prime: -1,
    tail_t: 2.0,
    tail_inf: 12.0,
    mask_sampler: MaskSamplerKind::Cdt,
    eps_tot: EPS_TOT_DEFAULT,
};

/// Production 50-of-100 parameter set.  Matches
/// `estimator/lotrs_estimate.py` (output:
/// `estimator/LoTRS-Estimate-Output-N100T50.txt`).  Signature
/// estimates must use the verifier's actual bounds and rejection rules.
pub const PRODUCTION_PARAMS: LoTRSParams = LoTRSParams {
    name: "lotrs-128",
    d: 128,
    q: 8_796_093_022_141,  // largest prime < 2^43, 5 mod 8
    q_hat: 34_359_737_917, // largest prime < 2^35, 5 mod 8
    kappa: 1,
    beta: 100,
    T: 50,
    k: 14,
    l: 20,
    l_prime: 21,
    n_hat: 12,
    k_hat: 11,
    w: 31,
    eta: 1,
    phi: 1100.0, // 22 * T
    phi_a: 24.0, // fixed across T
    phi_b: 24.0,
    K_A: 28, // ceil(log2(n_hat·d·(w·2^K_B − 1)/ln μ_BG_target)),
    //   μ_BG_target = 1.01
    K_B: 5,
    K_w: 5,
    lam: 128,
    max_attempts: 200,
    eta_prime: -1,
    tail_t: 1.2,
    tail_inf: 12.0,
    mask_sampler: MaskSamplerKind::Facct, // sigma_0 ≈ 6.97e7 — CDT infeasible
    eps_tot: EPS_TOT_DEFAULT,
};

/// 16-of-32 benchmark.  Shares the PRODUCTION lattice.
pub const BENCH_PARAMS: LoTRSParams = LoTRSParams {
    name: "lotrs-bench-16of32",
    d: 128,
    q: 8_796_093_022_141,
    q_hat: 34_359_737_917,
    kappa: 1,
    beta: 32,
    T: 16,
    k: 14,
    l: 20,
    l_prime: 21,
    n_hat: 12,
    k_hat: 11,
    w: 31,
    eta: 1,
    phi: 1100.0, // max(22*T, 1100): regularity floor
    phi_a: 24.0,
    phi_b: 24.0,
    K_A: 28,
    K_B: 5,
    K_w: 5,
    lam: 128,
    max_attempts: 200,
    eta_prime: -1,
    tail_t: 1.2,
    tail_inf: 12.0,
    mask_sampler: MaskSamplerKind::Facct,
    eps_tot: EPS_TOT_DEFAULT,
};

/// 4-of-32 benchmark.  Shares the BENCH lattice.  `phi_a` identical
/// because the finder script doesn't scale `phi_a` with `T`.
pub const BENCH_4OF32: LoTRSParams = LoTRSParams {
    name: "lotrs-bench-4of32",
    d: 128,
    q: 8_796_093_022_141,
    q_hat: 34_359_737_917,
    kappa: 1,
    beta: 32,
    T: 4,
    k: 14,
    l: 20,
    l_prime: 21,
    n_hat: 12,
    k_hat: 11,
    w: 31,
    eta: 1,
    phi: 1100.0, // max(22*T, 1100): regularity floor
    phi_a: 24.0,
    phi_b: 24.0,
    K_A: 28,
    K_B: 5,
    K_w: 5,
    lam: 128,
    max_attempts: 200,
    eta_prime: -1,
    tail_t: 1.2,
    tail_inf: 12.0,
    mask_sampler: MaskSamplerKind::Facct,
    eps_tot: EPS_TOT_DEFAULT,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mod_8_constraint() {
        for p in &[TEST_PARAMS, BENCH_4OF32, BENCH_PARAMS, PRODUCTION_PARAMS] {
            assert_eq!(p.q % 8, 5, "q must be 5 mod 8");
            assert_eq!(p.q_hat % 8, 5, "q_hat must be 5 mod 8");
        }
    }

    #[test]
    fn power_of_two_d() {
        for p in &[TEST_PARAMS, BENCH_4OF32, BENCH_PARAMS, PRODUCTION_PARAMS] {
            assert!(p.d.is_power_of_two());
        }
    }

    #[test]
    fn n_equals_beta_pow_kappa() {
        for p in &[TEST_PARAMS, BENCH_4OF32, BENCH_PARAMS, PRODUCTION_PARAMS] {
            let mut n = 1usize;
            for _ in 0..p.kappa {
                n *= p.beta;
            }
            assert_eq!(p.N(), n);
        }
    }

    #[test]
    fn mask_sampler_declared_per_parameter_set() {
        assert_eq!(TEST_PARAMS.mask_sampler, MaskSamplerKind::Cdt);
        assert_eq!(BENCH_4OF32.mask_sampler, MaskSamplerKind::Facct);
        assert_eq!(BENCH_PARAMS.mask_sampler, MaskSamplerKind::Facct);
        assert_eq!(PRODUCTION_PARAMS.mask_sampler, MaskSamplerKind::Facct);
    }

    /// Spec Lemma 1:
    ///   q_hat > max{ d * (2 + 12 * phi_a * B_a)^2,  2 * N^2 }
    /// and 2 * ||x||_inf < sqrt(q/2), sqrt(q_hat/2) for our challenge
    /// set with ||x||_inf = 1.
    #[test]
    fn range_proof_and_invertibility_conditions() {
        for p in &[BENCH_4OF32, BENCH_PARAMS, PRODUCTION_PARAMS] {
            let rhs1 = (p.d as f64) * (2.0 + 12.0 * p.phi_a * p.B_a()).powi(2);
            let rhs2 = 2.0 * (p.N() as f64).powi(2);
            let rhs = rhs1.max(rhs2);
            assert!(
                (p.q_hat as f64) > rhs,
                "{}: q_hat={} not > max(d*(2+12*phi_a*B_a)^2, 2*N^2)={:.0}",
                p.name,
                p.q_hat,
                rhs
            );
            assert!(2.0 < ((p.q as f64) / 2.0).sqrt());
            assert!(2.0 < ((p.q_hat as f64) / 2.0).sqrt());
        }
    }
}
