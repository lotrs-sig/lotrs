//! The published parameter manifest must match both concrete implementations.
use lotrs::{BENCH_4OF32, BENCH_PARAMS, PRODUCTION_PARAMS};

#[test]
fn artifact_parameter_manifest() {
    let expected: serde_json::Value =
        serde_json::from_str(include_str!("../../parameters.json")).unwrap();
    let p = PRODUCTION_PARAMS;
    macro_rules! check {
        ($($field:ident),* $(,)?) => {
            $(assert_eq!(serde_json::json!(p.$field), expected[stringify!($field)],
                         "parameter {}", stringify!($field));)*
        };
    }
    check!(
        name,
        d,
        q,
        q_hat,
        kappa,
        beta,
        T,
        k,
        l,
        l_prime,
        n_hat,
        k_hat,
        w,
        eta,
        phi,
        phi_a,
        phi_b,
        K_A,
        K_B,
        K_w,
        lam,
        max_attempts,
        eta_prime,
        tail_t,
        tail_inf,
        eps_tot
    );
    assert_eq!(expected["mask_sampler"], "facct");
    assert_eq!(p.mask_sampler, lotrs::MaskSamplerKind::Facct);
    for bench in [BENCH_4OF32, BENCH_PARAMS] {
        assert_eq!(
            (bench.q, bench.q_hat, bench.k, bench.l, bench.l_prime),
            (p.q, p.q_hat, p.k, p.l, p.l_prime)
        );
        assert_eq!(bench.phi, (22.0 * bench.T as f64).max(1100.0));
    }
}
