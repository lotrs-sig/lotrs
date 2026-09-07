from estimator import *
from sage.all import *
import json
from pathlib import Path

from kd_estimates.MSIS_security import MSIS_summarize_attacks, MSISParameterSet
from kd_estimates.model_BKZ import delta_BKZ
from ASIS_sec_estimate.ASIS_MSIS_security import MSIS_summarize_attacks as ASIS_summarize_attacks
from ASIS_sec_estimate.ASIS_MSIS_security import MSISParameterSet as ASISParameterSet
from ASIS_sec_estimate.ASIS_model_BKZ import delta_BKZ as ASIS_delta_BKZ

from lotrs_finder import calculate_PK, calculate_sig_size, number_reps, setBinASISBounds, setDualMSASISBounds,setDualMSMSISBounds, mergeToFiveBuckets

from lotrs_param_checks import *


"""Auxiliary functions"""
def prime_5_mod_8(bits):
    """Largest prime < 2^bits that is congruent to 5 mod 8.

    Lemma 2.2 (Lyubashevsky) requires q == 5 (mod 8) so that
    R_q = Z_q[X]/(X^d + 1) is "almost a field" at d a power of 2,
    which we need for invertibility of challenge differences and
    for the binary-proof and DualMS hardness reductions.
    """
    q = int(previous_prime(int(2) ** int(bits)))
    while q % 8 != 5:
        q = int(previous_prime(q))
    return q

def artifact_parameters():
    """PDF Table 3 profile shared with the reference implementations.

    N=100, T=50, l=20, l_prime=21; see README.md for numerical limitations.
    """
    path = Path(__file__).resolve().parent.parent / "parameters.json"
    p = json.loads(path.read_text())
    assert p["q"] == prime_5_mod_8(43)
    assert p["q_hat"] == prime_5_mod_8(35)
    assert p["kappa"] == 1
    return p


def main():
    p = artifact_parameters()
    print("LoTRS artifact profile: N=%s T=%s" % (p["beta"], p["T"]))
    RHF_max = 1.0045

    """Parameter variables"""
    #Common parameters
    beta, kappa = p["beta"], p["kappa"]
    N, T = beta**kappa, p["T"]
    t = p["tail_t"]

    x_inf_norm = 1 #Infinity norm of secret and error in MLWE instances
    w = p["w"]

    eta_s = p["eta"]
    eta_prime_s = eta_s if p["eta_prime"] < 0 else p["eta_prime"]

    d = p["d"]

    lam = p["lam"]
    # SampleInBall-style challenge: only a lambda-bit seed x_seed is
    # transmitted on the wire; the verifier expands the sparse signed
    # challenge x deterministically from x_seed via the same XOF the
    # signer used.  See lotrs-py/sample.py::xof_sample_challenge and
    # codec.py::_expand_challenge_seed (Rust mirrors).
    size_x = lam

    #Binary proof dimensions + parameters
    nhat, khat = p["n_hat"], p["k_hat"]

    # Largest prime < 2^35 with q_hat == 5 (mod 8).
    qhat = p["q_hat"]
    logq_hat = RR(qhat).log2()
    print("Binary proof MLWE modulus q_hat =", qhat, "logq_hat", logq_hat)
    print("nhat =", nhat, "khat =", khat)

    phi_a, phi_b = p["phi_a"], p["phi_b"]
    mu_BG_target = RR(1.01)

    #Dropped bits
    K_b, K_w0 = p["K_B"], p["K_w"]
    K_a = ceil(log((nhat*d*(w*pow(2, K_b)-1))/log(mu_BG_target), 2))
    print("mu_BG_target", mu_BG_target)
    assert K_a == p["K_A"]
    print("K_a", K_a)

    #Set probability that bounds on f_0, f_1, g_0, g_1 will reject
    eps_total = RR(p["eps_tot"])

    #Binary proof bounds
    bin_arr = setBinASISBounds(beta, kappa, d, w, nhat, khat, phi_a, phi_b, K_b, eps_total, mu_BG_target)

    #Merge the 6 binary-proof buckets down to the 5 the ASIS estimator takes,
    #rather than discarding one bucket together with its columns.
    bin_merged = mergeToFiveBuckets(bin_arr)

    B1, m1 = bin_merged[0]
    B2, m2 = bin_merged[1]
    B3, m3 = bin_merged[2]
    B4, m4 = bin_merged[3]
    B5, m5 = bin_merged[4]

    #The merged instance must still carry every column of the paper's item (5):
    #m_f1 + m_f0 + m_g1 + m_g0 + m_zb + m_BG
    bin_width_expected = 2*kappa*(beta-1) + 2*kappa + (nhat + khat) + 4*nhat
    assert m1+m2+m3+m4+m5 == bin_width_expected, \
        "binary AMSIS width mismatch: %s != %s" % (m1+m2+m3+m4+m5, bin_width_expected)
    print("Binary AMSIS total width =", m1+m2+m3+m4+m5)

    #Binary std deviations
    B_b = sqrt(d*(nhat + khat))*w
    B_a = sqrt(kappa*w)
    sigma_zb = phi_b*B_b
    sigma_f = phi_a*B_a

    #DualMS dimensions + parameters
    k, l, l_prime = p["k"], p["l"], p["l_prime"]

    # Largest prime < 2^43 with q == 5 (mod 8).
    q_dualms = p["q"]
    logq = RR(log(q_dualms, 2))
    print("\nDualMS modulus q =", q_dualms, "logq = ", logq)
    print("l =", l, "l_prime =", l_prime, "k =", k)

    phi = p["phi"]
    assert phi == max(22*T, 1100)

    b2KB = pow(2,13) #Convert bits to bytes

    #Check whether to compress \tilde{w}_0
    compress_w = True

    #DualMS bounds
    sigma_s =  ceil(RR(((2*d)/sqrt(2*pi))*pow(q_dualms, (k/(l+k)+2/(d*(l+k))))))
    sigma_s_prime = ceil(RR(((2*d)/sqrt(2*pi))*pow(q_dualms, (k/(l_prime+k)+2/(d*(l_prime+k))))))

    B_zero = RR(sqrt(d*(l+k))*(eta_s*pow(w, kappa+1)+6*sigma_s*(kappa-1)*pow(w, kappa-1)))
    B_zero_prime = RR(sqrt(d*(l_prime+k))*(eta_prime_s*pow(w, kappa+1)+6*sigma_s_prime*(kappa-1)*pow(w, kappa-1)))
    B_hat_0 = RR(sqrt(pow(B_zero, 2) + pow(B_zero_prime, 2)))

    B_z = RR(t*phi*B_zero*sqrt(d*l))
    B_tilde_z = RR(sqrt(T)*B_z)
    #print("B_tilde_z =", log(pow(B_tilde_z, 2), 2))

    B_r = RR(t*phi*B_zero_prime*sqrt(d*l_prime))
    B_tilde_r = RR(sqrt(T)*B_r)
    #print("B_tilde_r =", log(pow(B_tilde_r, 2), 2))

    B_e = RR(t*phi*B_hat_0*sqrt(d*k))
    B_tilde_e = RR(sqrt(T)*B_e)
    #print("B_tilde_e =", log(pow(B_tilde_e, 2), 2))

    B_det = RR(pow((2*w), kappa*(kappa+1)/2))
    print("log2(B_det) =", log(pow(B_det, 2), 2))

    B_Gamma = RR(pow((2*w), kappa*(kappa-1)/2))

    #MSIS bound for DualMS MSIS instance
    #Compression residual bound for kappa = 1 case only
    #l2 MSIS bound for the DualMS instance.  Informational only -- the ASIS/AMSIS
    #run below is the authoritative DualMS-side number.  Call the finder rather
    #than re-deriving beta_sis here, so the two can never drift apart again.
    # beta_sis = setDualMSMSISBounds(T, kappa, d, w, k, l, l_prime, eta_s, eta_prime_s, t, logq, phi, K_w0, compress_w)
    # print("log2(beta_sis) =", log(beta_sis, 2))
    # _, l2_ok = setDualMSMSISRank(d, k, l, l_prime, RHF_max, logq, beta_sis, compress_w)
    # print("l2-MSIS clears RHF_max:", l2_ok)

    #DualMS MLWE std deviation
    sigma_b0 = phi*B_zero
    sigma_tilde_z = phi*B_zero*sqrt(T)
    sigma_tilde_r = phi*B_zero_prime*sqrt(T)
    sigma_tilde_e = phi*B_hat_0*sqrt(T)

    print("\n=== Binary Proof LWE Estimator ===")
    bin_lwe_params = LWE.Parameters(n=(d*khat), q=qhat, Xs=ND.Uniform(-1,1), Xe=ND.Uniform(-1,1), m=(d*nhat))
    print(bin_lwe_params)
    results_bin_lwe = LWE.estimate.rough(bin_lwe_params)
    print(results_bin_lwe)

    print("\n\n=== Binary Proof ASIS Estimator ===")
    # Report all three bundled cost-model variants separately.
    for attack_variant in [0, 1, 2]:
        # function below assumes B1>=B2>=B3>=B4>=B5
        print("***** Attack Variant", attack_variant, " *********")
        params = ASISParameterSet(d, m1+m2+m3+m4+m5, nhat, B1, B2, B3, B4, B5, m1, m2, m3, m4, m5, qhat, norm="linf")
        (m_pq, b_pq, c_pq) = ASIS_summarize_attacks(params, attack_variant=attack_variant)
        print("BKZ block size =", b_pq)
        print("RHF =", round(ASIS_delta_BKZ(b_pq),5))
        print("Cost=", round(c_pq,5))
        print()


    print("\n=== DualMS LWE Estimator ===")
    dualms_lwe_params = LWE.Parameters(n=(d*l), q=q_dualms, Xs=ND.Uniform(-1,1), Xe=ND.Uniform(-1,1), m=(d*k))
    print(dualms_lwe_params)
    results_dualms_params = LWE.estimate.rough(dualms_lwe_params)
    print(results_dualms_params)

    # The DualMS side is bounded by the ASIS estimator below
    # rather than the L2-MSIS estimator: AMSIS gives tighter
    # bucket-wise control because different parts of the signature
    # have very different norms.  beta_sis (the L2-MSIS bound) is
    # computed but not run here; the ASIS attack-cost output below
    # is the authoritative DualMS-side security number.

    print("\n\n=== DualMS ASIS Estimator ===")
    arrDualMS = setDualMSASISBounds(T, kappa, d, w, k, l, l_prime, eta_s, eta_prime_s, t, logq, phi, K_w0, compress_w, t_inf=p["tail_inf"])
    B1, m1 = arrDualMS[0]
    B2, m2 = arrDualMS[1]
    B3, m3 = arrDualMS[2]
    B4, m4 = arrDualMS[3]
    B5, m5 = arrDualMS[4]

    for attack_variant in [0, 1, 2]:
        # function below assumes B1>=B2>=B3>=B4>=B5
        print("***** Attack Variant", attack_variant, " *********")
        params = ASISParameterSet(d, m1+m2+m3+m4+m5, k, B1, B2, B3, B4, B5, m1, m2, m3, m4, m5, q_dualms, norm="linf")
        (m_pq, b_pq, c_pq) = ASIS_summarize_attacks(params, attack_variant=attack_variant)
        print("BKZ block size =", b_pq)
        print("RHF =", round(ASIS_delta_BKZ(b_pq),5))
        print("Cost=", round(c_pq,5))
        print()
    
    sig_size = calculate_sig_size(kappa, beta, nhat, khat, k, l, l_prime, d, logq_hat, logq, K_b, K_w0, size_x, sigma_f, sigma_zb, sigma_tilde_z, sigma_tilde_r, sigma_tilde_e, compress_w)
    print("\nSignature size:", RR(sig_size/b2KB), "KiB\n")

    size_single_pk, size_PK = calculate_PK(T, N, k, d, logq)
    print("Single public key size:", RR(size_single_pk/b2KB), "KiB\n")
    print("Ring PK size:", RR(size_PK/b2KB), "KiB\n")

    number_lotrs_reps = number_reps(T, phi_a, phi_b, phi, nhat, d, w, K_a, K_b, K_w0, eps_total, compress_w)
    print("\nNumber of repetitions for rejection sampling:", number_lotrs_reps)

    print("\n\n=== Perform condition checks ===")
    assert check_q_prime_5_mod_8(qhat)
    assert check_q_prime_5_mod_8(q_dualms)
    assert checkChallengeDiff(qhat, q_dualms, x_inf_norm)
    reg_z = check_sigma(RR(phi*B_zero), d, q_dualms, k, l)
    print("Regularity for sigma_0 :", reg_z)
    assert reg_z
    reg_r = check_sigma(RR(phi*B_zero_prime), d, q_dualms, k, l_prime)
    print("Regularity for sigma_0':", reg_r)
    assert reg_r
    assert checkRangeProofCondition(d, kappa, phi_a, w, qhat, N)

    

"""------------------------------------------------------------------------------------------------------------------"""
if __name__ == "__main__":
    main()
