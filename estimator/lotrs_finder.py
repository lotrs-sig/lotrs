from estimator import *
from sage.all import *

from kd_estimates.MSIS_security import MSIS_summarize_attacks, MSISParameterSet
from kd_estimates.model_BKZ import delta_BKZ
from ASIS_sec_estimate.ASIS_MSIS_security import MSIS_summarize_attacks as ASIS_summarize_attacks
from ASIS_sec_estimate.ASIS_MSIS_security import MSISParameterSet as ASISParameterSet
from ASIS_sec_estimate.ASIS_model_BKZ import delta_BKZ as ASIS_delta_BKZ

# format: (lambda, ring dimension) --> weight, challenge infinity norm
infnorm_weight={
 (16, 8)    : (6, 2),
 (16, 16)   : (5, 1),
 (16, 32)   : (4, 1),
 (16, 64)   : (3, 1),
 (16, 128)  : (3, 1),
 (16, 256)  : (2, 1),
 (16, 512)  : (2, 1),
 (16, 1024) : (2, 1),
 (16, 2048) : (2, 1),
 (16, 4096) : (2, 1),
 (32, 8)    : (8, 8),
 (32, 16)   : (10, 2),
 (32, 32)   : (9, 1),
 (32, 64)   : (6, 1),
 (32, 128)  : (5, 1),
 (32, 256)  : (5, 1),
 (32, 512)  : (4, 1),
 (32, 1024) : (4, 1),
 (32, 2048) : (3, 1),
 (32, 4096) : (3, 1),
 (64, 8)    : (8, 128),
 (64, 16)   : (15, 8),
 (64, 32)   : (18, 2),
 (64, 64)   : (16, 1),
 (64, 128)  : (12, 1),
 (64, 256)  : (10, 1),
 (64, 512)  : (8, 1),
 (64, 1024) : (7, 1),
 (64, 2048) : (7, 1),
 (64, 4096) : (6, 1),
 (128, 4)   : (8, 2^31),
 (128, 8)   : (8, 32768),
 (128, 16)  : (16, 128),
 (128, 32)  : (29, 8),
 (128, 64)  : (34, 2),
 (128, 128) : (31, 1),
 (128, 256) : (23, 1),
 (128, 512) : (19, 1),
 (128, 1024): (16, 1),
 (128, 2048): (14, 1),
 (128, 4096): (13, 1),
 (192, 16)  : (-1, -1),
 (192, 32)  : (32, 32),
 (192, 64)  : (48, 4),
 (192, 128) : (69, 1),
 (192, 256) : (39, 1),
 (192, 512) : (31, 1),
 (192, 1024): (26, 1),
 (192, 2048): (22, 1),
 (192, 4096): (20, 1),
 (256, 8)   : (8, 2^31),
 (256, 16)  : (16, 32768),
 (256, 32)  : (32, 128),
 (256, 64)  : (56, 8),
 (256, 128) : (66, 2),
 (256, 256) : (60, 1),
 (256, 512) : (44, 1),
 (256, 1024): (36, 1),
 (256, 2048): (31, 1),
 (256, 4096): (27, 1)}

# format: (lambda, logq, maxinfnorm)
LWE_dim_uniform = {
 (1.0045, 24, 1):  997,
 (1.0045, 24, 2):  947,
 (1.0045, 24, 3):  917,
 (1.0045, 24, 5):  880,
 (1.0045, 25, 1): 1035,
 (1.0045, 25, 2):  985,
 (1.0045, 25, 3):  956,
 (1.0045, 25, 5):  918,
 (1.0045, 26, 1): 1074,
 (1.0045, 26, 2): 1024,
 (1.0045, 26, 3):  937,
 (1.0045, 26, 5):  957,
 (1.0045, 27, 1): 1112,
 (1.0045, 27, 2): 1063,
 (1.0045, 27, 3):  976,
 (1.0045, 27, 5):  995,
 (1.0045, 28, 1): 1151,
 (1.0045, 28, 2): 1101,
 (1.0045, 28, 3): 1014,
 (1.0045, 28, 5): 1034,
 (1.0045, 29, 1): 1190,
 (1.0045, 29, 2): 1140,
 (1.0045, 29, 3): 1053,
 (1.0045, 29, 5): 1072,
 (1.0045, 30, 1): 1228,
 (1.0045, 30, 2): 1178,
 (1.0045, 30, 3): 1091,
 (1.0045, 30, 5): 1111,
 (1.0045, 31, 1): 1267,
 (1.0045, 31, 2): 1217,
 (1.0045, 31, 3): 1130,
 (1.0045, 31, 5): 1149,
 (1.0045, 32, 1): 1305,
 (1.0045, 32, 2): 1255,
 (1.0045, 32, 3): 1168,
 (1.0045, 32, 5): 1188,
 (1.0045, 33, 1): 1344,
 (1.0045, 33, 2): 1294,
 (1.0045, 33, 3): 1207,
 (1.0045, 33, 5): 1226,
 (1.0045, 34, 1): 1382,
 (1.0045, 34, 2): 1332,
 (1.0045, 34, 3): 1245,
 (1.0045, 34, 5): 1264,
 (1.0045, 35, 1): 1421,
 (1.0045, 35, 2): 1371,
 (1.0045, 35, 3): 1284,
 (1.0045, 35, 5): 1303,
 (1.0045, 36, 1): 1459,
 (1.0045, 36, 2): 1409,
 (1.0045, 36, 3): 1322,
 (1.0045, 36, 5): 1341,
 (1.0045, 37, 1): 1498,
 (1.0045, 37, 2): 1448,
 (1.0045, 37, 3): 1361,
 (1.0045, 37, 5): 1380,
 (1.0045, 38, 1): 1536,
 (1.0045, 38, 2): 1487,
 (1.0045, 38, 3): 1399,
 (1.0045, 38, 5): 1418,
 (1.0045, 39, 1): 1575,
 (1.0045, 39, 2): 1525,
 (1.0045, 39, 3): 1438,
 (1.0045, 39, 5): 1457,
 (1.0045, 40, 1): 1613,
 (1.0045, 40, 2): 1564,
 (1.0045, 40, 3): 1476,
 (1.0045, 40, 5): 1495,
 (1.0045, 41, 1): 1652,
 (1.0045, 41, 2): 1602,
 (1.0045, 41, 3): 1515,
 (1.0045, 41, 5): 1534,
 (1.0045, 42, 1): 1691,
 (1.0045, 42, 2): 1641,
 (1.0045, 42, 3): 1553,
 (1.0045, 42, 5): 1572,
 (1.0045, 43, 1): 1729,
 (1.0045, 43, 2): 1679,
 (1.0045, 43, 3): 1592,
 (1.0045, 43, 5): 1611,
 (1.0045, 44, 1): 1768,
 (1.0045, 44, 2): 1718,
 (1.0045, 44, 3): 1630,
 (1.0045, 44, 5): 1649,
 (1.0045, 45, 1): 1806,
 (1.0045, 45, 2): 1756,
 (1.0045, 45, 3): 1669,
 (1.0045, 45, 5): 1688,
 (1.0045, 46, 1): 1845,
 (1.0045, 46, 2): 1795,
 (1.0045, 46, 3): 1707,
 (1.0045, 46, 5): 1726,
 (1.0045, 47, 1): 1883,
 (1.0045, 47, 2): 1833,
 (1.0045, 47, 3): 1746,
 (1.0045, 47, 5): 1765,
 (1.0045, 48, 1): 1922,
 (1.0045, 48, 2): 1872,
 (1.0045, 48, 3): 1785,
 (1.0045, 48, 5): 1803,
 (1.0045, 49, 1): 1960,
 (1.0045, 49, 2): 1910,
 (1.0045, 49, 3): 1823,
 (1.0045, 49, 5): 1842,
 (1.0045, 50, 1): 1999,
 (1.0045, 50, 2): 1949,
 (1.0045, 50, 3): 1862,
 (1.0045, 50, 5): 1880,
 (1.0045, 51, 1): 2037,
 (1.0045, 52, 1): 2076,
 (1.0045, 53, 1): 2115,
 (1.0045, 54, 1): 2153,
 (1.0045, 55, 1): 2192,
 (1.0045, 56, 1): 2230,
 (1.0045, 57, 1): 2269,
 (1.0045, 58, 1): 2307,
 (1.0045, 59, 1): 2346,
 (1.0045, 60, 1): 2384,
 (1.0045, 61, 1): 2423,
 (1.0045, 62, 1): 2461,
 (1.0045, 63, 1): 2500,
 (1.0045, 64, 1): 2538,
 (1.0045, 65, 1): 2577,
 (1.0045, 66, 1): 2616,
 (1.0045, 67, 1): 2654,
 (1.0045, 68, 1): 2693,
 (1.0045, 69, 1): 2731,
 (1.0045, 70, 1): 2770,
 (1.0045, 71, 1): 2808,
 (1.0045, 72, 1): 2847,
 (1.0045, 73, 1): 2885,
 (1.0045, 74, 1): 2924,
 (1.0045, 75, 1): 2962,
 (1.0045, 76, 1): 3001,
 (1.0045, 77, 1): 3040,
 (1.0045, 78, 1): 3078,
 (1.0045, 79, 1): 3117,
 (1.0045, 80, 1): 3155}
 
LWE_dim_gaussian = {
 (1.0045, 24, 1): 936,
 (1.0045, 24, 2): 860,
 (1.0045, 25, 1): 975,
 (1.0045, 25, 2): 898,
 (1.0045, 26, 1): 1013,
 (1.0045, 26, 2): 937,
 (1.0045, 27, 1): 1052,
 (1.0045, 27, 2): 975,
 (1.0045, 28, 1): 1090,
 (1.0045, 28, 2): 1014,
 (1.0045, 29, 1): 1129,
 (1.0045, 29, 2): 1052,
 (1.0045, 30, 1): 1167,
 (1.0045, 30, 2): 1091,
 (1.0045, 31, 1): 1206,
 (1.0045, 31, 2): 1129,
 (1.0045, 32, 1): 1244,
 (1.0045, 32, 2): 1168,
 (1.0045, 33, 1): 1283,
 (1.0045, 33, 2): 1206,
 (1.0045, 34, 1): 1321,
 (1.0045, 34, 2): 1245,
 (1.0045, 35, 1): 1360,
 (1.0045, 35, 2): 1283,
 (1.0045, 36, 1): 1399,
 (1.0045, 36, 2): 1322,
 (1.0045, 37, 1): 1437,
 (1.0045, 37, 2): 1360,
 (1.0045, 38, 1): 1476,
 (1.0045, 38, 2): 1399,
 (1.0045, 39, 1): 1514,
 (1.0045, 39, 2): 1437,
 (1.0045, 40, 1): 1553,
 (1.0045, 40, 2): 1476,
 (1.0045, 41, 1): 1591,
 (1.0045, 41, 2): 1514,
 (1.0045, 42, 1): 1630,
 (1.0045, 42, 2): 1553,
 (1.0045, 43, 1): 1668,
 (1.0045, 43, 2): 1591,
 (1.0045, 44, 1): 1707,
 (1.0045, 44, 2): 1630,
 (1.0045, 45, 1): 1745,
 (1.0045, 45, 2): 1668,
 (1.0045, 46, 1): 1784,
 (1.0045, 46, 2): 1707,
 (1.0045, 47, 1): 1823,
 (1.0045, 47, 2): 1746,
 (1.0045, 48, 1): 1861,
 (1.0045, 48, 2): 1784,
 (1.0045, 49, 1): 1900,
 (1.0045, 49, 2): 1823,
 (1.0045, 50, 1): 1938,
 (1.0045, 50, 2): 1861}

"""------------------------------------------------------------------------------------------------------------------"""
"""LWE functions"""
#Set LWE rank (columns determine hardness)
#~ LWE_dim = { (delta, logq, B) : LWE Dimension }
def setLWERank(RHF, d, logq, B, uniform=True):
    rhf_key = round(RHF, 4)
    fail = -1

    table = LWE_dim_uniform if uniform else LWE_dim_gaussian
    table_name = "LWE_dim_uniform" if uniform else "LWE_dim_gaussian"

    print("\n=== set LWE Rank ===")
    print("RHF input       =", RHF)
    print("RHF rounded key =", rhf_key)
    print("d               =", d)
    print("logq            =", logq)
    print("B               =", B)
    print("table           =", table_name)

    key = (rhf_key, logq, B)
    print("Trying exact lookup with key =", key)
    if key in table:
        full_dim = table[key]
        rank = int(ceil(full_dim / d))
        print("Exact lookup succeeded")
        print("full LWE dimension =", full_dim)
        print("module rank        =", rank)
        return rank

    print("Exact lookup failed")

    # Extrapolation rules
    anchor_logq = None
    step_size = None

    if uniform:
        if rhf_key == 1.0045 and logq > 50:
            anchor_logq = 50
            step_size = 39
        elif rhf_key == 1.0070 and logq > 20:
            anchor_logq = 20
            step_size = 25
    else:
        if logq > 50:
            anchor_logq = 50
            step_size = 39

    if anchor_logq is None:
        print("No extrapolation rule available")
        print("Returning", fail)
        return fail

    anchor_key = (rhf_key, anchor_logq, B)
    print("Trying extrapolation from anchor key =", anchor_key)
    print("step size =", step_size)

    if anchor_key not in table:
        print("Anchor lookup failed")
        print("Returning", fail)
        return fail

    anchor_dim = table[anchor_key]
    full_dim = anchor_dim + (logq - anchor_logq) * step_size
    rank = int(ceil(full_dim / d))

    print("Anchor lookup succeeded")
    print("anchor full dimension =", anchor_dim)
    print("extrapolated full dim =", full_dim)
    print("module rank           =", rank)
    return rank

"""------------------------------------------------------------------------------------------------------------------"""
"""Bin ASIS functions"""
#Reduce a bucket list to exactly `target` buckets for the ASIS estimator.
#The binary proof has 6 blocks but ASISParameterSet takes 5.  Deleting a
#block removes its columns from the AMSIS instance, which makes the
#instance HARDER and over-states security.  Merging two adjacent blocks
#into (max(B_i,B_j), m_i+m_j) instead only relaxes the bound on the
#smaller-bound block, so the estimated instance is at least as easy as
#the real one and the security number is a conservative lower bound.
#We merge the adjacent pair whose merge is cheapest, the cost of merging
#block j+1 into block j being m_{j+1} * log2(B_j / B_{j+1}), i.e. the
#number of extra "bit-columns" of freedom handed to the attacker.
def mergeToFiveBuckets(arr, target=5):
    merged = sorted([[a[0], a[1]] for a in arr], key=lambda x: x[0], reverse=True)
    while len(merged) > target:
        costs = [merged[j+1][1] * log(merged[j][0]/merged[j+1][0], 2)
                 for j in range(len(merged)-1)]
        j = costs.index(min(costs))
        print("Merging bucket", j+1, "(log2B =", round(log(merged[j+1][0], 2), 3),
              ", m =", merged[j+1][1], ") into bucket", j,
              "(log2B =", round(log(merged[j][0], 2), 3), ", m =", merged[j][1],
              "); cost =", round(costs[j], 3), "bit-columns")
        merged[j] = [max(merged[j][0], merged[j+1][0]), merged[j][1] + merged[j+1][1]]
        del merged[j+1]
    print("Merged bucket widths:", [a[1] for a in merged],
          " total =", sum(a[1] for a in merged))
    return merged

#Set ASIS bounds (B_i, m_i) for binary proof
def setBinASISBounds(beta, kappa, d, w, nhat, khat, phi_a, phi_b, K_b, eps_total, mu_BG_target=RR(1.01)):
    #Initialise 2d array to be sorted (since ASIS code requires it)
    arr = []

    print("\n=== set ASIS bounds HP ===") # These bounds are used for the case of accepting with high probability
    sigma_a = phi_a * sqrt(kappa * w)
    eps_each = eps_total / 4 # We are saying joint acceptance is 99%

    M_f1 = kappa * (beta - 1) * d
    tau_f1 = sqrt(2 * log((2 * M_f1) / eps_each))
    B_f1 = RR(1 + tau_f1 * sigma_a)
    m_f1 = kappa*(beta-1)
    arr.append([B_f1, m_f1])
    print("B_f1 =", log(B_f1, 2))

    M_f0 = kappa * d
    tau_f0 = sqrt(2 * log((2 * M_f0) / eps_each))
    B_f0 = RR(1 + tau_f0 * sqrt(beta - 1) * sigma_a)

    m_f0 = kappa
    arr.append([B_f0, m_f0])
    print("B_f0 =", log(B_f0, 2))

    B_g1 = RR(w * B_f1 + d * pow(B_f1,2))
    m_g1 = kappa*(beta-1)
    arr.append([B_g1, m_g1])
    print("B_g1 =", log(B_g1, 2))

    B_g0 = RR(w * B_f0 + d * pow(B_f0,2))
    m_g0 = kappa
    arr.append([B_g0, m_g0])
    print("B_g0 =", log(B_g0, 2))

    B_b = sqrt(d*(nhat + khat))*w

    B_zb = RR(6*phi_b*B_b)
    m_zb = nhat+khat
    arr.append([B_zb, m_zb])
    print("B_zb =", log(B_zb, 2))

    # choose / derive K_a so that mu_BG is close to the target
    mu_BG_target = RR(mu_BG_target)
    K_a = ceil(log((nhat*d*(w*pow(2, K_b)-1))/log(mu_BG_target), 2))
    print("mu_BG_target =", mu_BG_target)
    print("K_a =", K_a)

    # actual dropped-bit bounds from the compressed binding proof
    B_B0 = RR(pow(2, K_b - 1))
    B_A0 = RR(pow(2, K_a - 1))
    B_be = RR(pow(2, K_a) - 2 * w * pow(2, K_b - 1))
    B_ae = RR(2 * w * (pow(2, K_a - 1) - w * pow(2, K_b - 1)))

    if B_ae <= 0:
        raise ValueError("Compression parameters invalid: 2^(K_a-1) - w*2^(K_b-1) must be positive.")

    # collapse the four dropped-bit bounds into one ASIS block:
    # max of the bounds, sum of the widths (4*nhat), so no columns are lost
    B_BG = max(B_B0, B_A0, B_be, B_ae)
    m_BG = 4 * nhat
    arr.append([B_BG, m_BG])

    arr.sort(key=lambda x: x[0], reverse=True)
    return arr

#Set ASIS rank(rows determine hardness)
def setBinASISRank(d, nhat, khat, RHF_max, logqhat, arr):
    extra = 0.00005
    print("\n=== Ordered ASIS bounds (all buckets, before merge) ===")
    for i in range(len(arr)):
        print("B" + str(i+1), "=", log(arr[i][0], 2), " m" + str(i+1), "=", arr[i][1])

    marr = mergeToFiveBuckets(arr)

    print("=== Merged ASIS bounds (5 buckets) ===")
    B1, m1 = marr[0]
    B2, m2 = marr[1]
    B3, m3 = marr[2]
    B4, m4 = marr[3]
    B5, m5 = marr[4]
    for i in range(5):
        print("B" + str(i+1), "=", log(marr[i][0], 2), " m" + str(i+1), "=", marr[i][1])
    
    attack_variant = 0  # The attack variant should be in {0,1,2}. '0' is the "traditional attack". The for-loop below runs over all attacks
    sisrank = nhat

    print("sisrank  =", sisrank)
    for attack_variant in [0]:
        # function below assumes B1>=B2>=B3>=B4>=B5
        q_hat = pow(2, logqhat)
        print("logq_hat =", logqhat)

        params = ASISParameterSet(d, m1+m2+m3+m4+m5, sisrank, B1, B2, B3, B4, B5, m1, m2, m3, m4, m5, q_hat, norm="linf")
        try:
            print("Running ASIS_summarize_attacks...")
            (m_pq, b_pq, c_pq) = ASIS_summarize_attacks(params, attack_variant=attack_variant)
        except Exception as e:
            print("ASIS_summarize_attacks failed:", e)
            return sisrank, False
           
        if(round(ASIS_delta_BKZ(b_pq),5) <= (RHF_max+extra)):
            print("***** Attack Variant", attack_variant, " *********")
            print("BKZ block size =", b_pq)
            print("RHF =", round(ASIS_delta_BKZ(b_pq),5))
            print("Cost=", round(c_pq,5))
            print()
            # ~ ********************** Results ********************************
            print("sisrank  =", sisrank)
            print("log2(q)  =", round(log(q_hat,2),2))
            print("log2(B1) =", round(log(B1,2),2))
            print("log2(B2) =", round(log(B2,2),2))
            print("log2(B3) =", round(log(B3,2),2))
            print("log2(B4) =", round(log(B4,2),2))
            print("log2(B5) =", round(log(B5,2),2))
            print()
            return sisrank, True
        else:
            return sisrank, False

#Get params for binary proof MLWE and MSIS
def findBinParams(beta, kappa, logq_min, logq_max, RHF_max, phi_a, phi_b, K_b, eps_total, mu_BG_target=RR(1.01)):
    d_arr = [128,256] #Ring dim
    w = -1 #Challenge Hamming weight
    x_inf_norm = -1 #Challenge infinity norm
    B = 1 #Bound on secret coefficients for MLWE
    
    bound_arr = []
    output_arr = []
    
    # Parameter search loop: standard ASIS / approximate-SIS attack-cost sweep over candidate dimensions.
    for d in d_arr:
        try:
            w, x_inf_norm = infnorm_weight[128, d]
            print("w =", w, "x_inf_norm =", x_inf_norm)
        except:
            continue
        for logq in range(logq_min, logq_max):          
            khat = setLWERank(RHF_max, d, logq, B, uniform=True)
            print("k_hat =", khat)
            if khat == -1:
                print("Skipping: no valid LWE rank found")
                continue
            nhat = 1
            boolChecks = False
            while((nhat*d <= 8192) and not boolChecks):
                #print("nhat =", nhat, "x", "d =", d, "=", nhat*d)
                bound_arr = setBinASISBounds(beta, kappa, d, w, nhat, khat, phi_a, phi_b, K_b, eps_total, mu_BG_target)
                _, boolChecks = setBinASISRank(d, nhat, khat, RHF_max, logq, bound_arr)
                if (boolChecks == False):
                    nhat += 10           
            if(nhat*d > 8192):
                print("Could not find parameters")
            while boolChecks and nhat > 0:
                output_arr.append([d, logq, khat, nhat, boolChecks])
                nhat-=1
                bound_arr = setBinASISBounds(beta, kappa, d, w, nhat, khat, phi_a, phi_b, K_b, eps_total, mu_BG_target)
                nhat, boolChecks = setBinASISRank(d, nhat, khat, RHF_max, logq, bound_arr)  
    
    return output_arr

"""------------------------------------------------------------------------------------------------------------------"""
"""DualMS (MSIS) functions"""
def setDualMSMSISBounds(T, kappa, d, w, k, l, l_prime, eta_s, eta_prime_s, t, logq, phi, K_w0, compress_w):
    
    #Calculate q from logq
    q = pow(2, logq)

    #DualMS bounds
    sigma_s =  ceil(RR(((2*d)/sqrt(2*pi))*pow(q, (k/(l+k)+2/(d*(l+k))))))
    sigma_s_prime = ceil(RR(((2*d)/sqrt(2*pi))*pow(q, (k/(l_prime+k)+2/(d*(l_prime+k))))))

    B_zero = RR(sqrt(d*(l+k))*(eta_s*pow(w, kappa+1)+6*sigma_s*(kappa-1)*pow(w, kappa-1)))
    B_zero_prime = RR(sqrt(d*(l_prime+k))*(eta_prime_s*pow(w, kappa+1)+6*sigma_s_prime*(kappa-1)*pow(w, kappa-1)))
    B_hat_0 = RR(sqrt(pow(B_zero, 2) + pow(B_zero_prime, 2)))

    B_z = RR(t*phi*B_zero*sqrt(d*l))
    B_tilde_z = RR(sqrt(T)*B_z)
    print("log2(B_tilde_z) =", log(pow(B_tilde_z, 2), 2))

    B_r = RR(t*phi*B_zero_prime*sqrt(d*l_prime))
    B_tilde_r = RR(sqrt(T)*B_r)
    print("log2(B_tilde_r) =", log(pow(B_tilde_r, 2), 2))

    B_e = RR(t*phi*B_hat_0*sqrt(d*k))
    B_tilde_e = RR(sqrt(T)*B_e)
    print("log2(B_tilde_e) =", log(pow(B_tilde_e, 2), 2))

    B_det = RR(pow((2*w), kappa*(kappa+1)/2))
    print("log2(B_det) =", log(pow(B_det, 2), 2))

    B_Gamma = RR(pow((2*w), kappa*(kappa-1)/2))

    #Compression residual bound for kappa = 1 case only
    if(compress_w):
        B_eta_w = RR(pow(2, K_w0-1))
        print("log2(k*B_eta_w) =", log((k*pow(B_eta_w,2)), 2)) #Need to compare other terms with k*pow(B_eta_w,2)
        beta_sis = RR(sqrt(4*d*pow(B_det, 4)+ 4*d*pow((kappa+1),2)*pow(B_det,2)*(pow(B_Gamma,2)*(pow(B_tilde_z, 2)+pow(B_tilde_r, 2)+pow(B_tilde_e, 2)+k*pow(B_eta_w, 2)))))
    else:
        #k*pow(B_eta_w, 2) term missing when no compression on \tilde{w}_j0 done
        beta_sis = RR(sqrt(4*d*pow(B_det, 4)+ 4*d*pow((kappa+1),2)*pow(B_det,2)*(pow(B_Gamma,2)*(pow(B_tilde_z, 2)+pow(B_tilde_r, 2)+pow(B_tilde_e, 2)))))

    return beta_sis

#Set SIS bound
def setDualMSMSISRank(d, k, l, l_prime, RHF_max, logq, sis_bound, compress_w):
    extra = 0.00005
    
    print("\n=== set MSIS Rank l2 ===")
    print("RHF input       =", RHF_max)
    print("d               =", d)
    print("k               =", k)
    print("l               =", l)
    print("l_prime         =", l_prime)
    print("logq            =", logq)
    print("log sis_bound   =", log(sis_bound, 2), 2)

    q = int(pow(2,logq)) #Set q from logq

    if (compress_w):
        total_width = 1+l+l_prime+2*k
    else:
        total_width = 1+l+l_prime+k

    try:
        print("Running MSIS_summarize_attacks w.r.t. l2 norm...")
        params = MSISParameterSet(d, total_width, k, sis_bound, q, norm="l2")
        bkz_block = MSIS_summarize_attacks(params)[0]
        RHF = round(delta_BKZ(bkz_block),5)
        print("Root Hermite Factor =", RHF)
    except Exception as e:
        print("MSIS_summarize_attacks failed:", e)
        return k, False
    
    if(round(delta_BKZ(bkz_block),5) <= (RHF_max+extra)):
        return k, True
    else:
        return k, False

#Get params for binary proof MLWE and MSIS
def findDualMSParams(T, kappa, B, eta_s, eta_prime_s, t, logq_min, logq_max, RHF_max, phi, K_w0, compress_w):
    d_arr = [128, 256] #Ring dim
    w = -1 #Challenge Hamming weight
    x_inf_norm = -1 #Challenge infinity norm
    
    output_arr = []
    
    # Parameter search loop: standard ASIS / approximate-SIS attack-cost sweep over candidate dimensions.
    for d in d_arr:
        try:
            w, x_inf_norm = infnorm_weight[128, d]
            print("w =", w, "x_inf_norm =", x_inf_norm, "\n")
        except:
            continue
        for logq in range(logq_min, logq_max):          
            l = setLWERank(RHF_max, d, logq, B, uniform=True)
            if l == -1:
                print("Skipping: no valid LWE rank found")
                continue
            k = 1
            boolChecks = False
            while((k*d <= 8192) and boolChecks==False):
                l_prime = l+1
                sis_bound = setDualMSMSISBounds(T, kappa, d, w, k, l, l_prime, eta_s, eta_prime_s, t, logq, phi, K_w0, compress_w)
                k, boolChecks = setDualMSMSISRank(d, k, l, l_prime, RHF_max, logq, sis_bound, compress_w)
                if (boolChecks == False):
                    k += 10           
            if(k*d > 8192):
                print("Could not find parameters")
            print("Refining k...")
            while boolChecks and k > 0:
                output_arr.append([d, logq, l, k, boolChecks])
                k-=1
                sis_bound = setDualMSMSISBounds(T, kappa, d, w, k, l, l_prime, eta_s, eta_prime_s, t, logq, phi, K_w0, compress_w)
                k, boolChecks = setDualMSMSISRank(d, k, l, l_prime, RHF_max, logq, sis_bound, compress_w)
    return output_arr

"""------------------------------------------------------------------------------------------------------------------"""
"""DualMS (ASIS) functions"""
def setDualMSASISBounds(T, kappa, d, w, k, l, l_prime, eta_s, eta_prime_s, t, logq, phi, K_w0, compress_w, t_inf=12):
    arr = []

    print("\n=== set DualMS ASIS bounds ===")

    q = RR(pow(2,logq))

    # Regularity-style Gaussian widths
    sigma_s =  ceil(RR(((2*d)/sqrt(2*pi))*pow(q, (k/(l+k)+2/(d*(l+k))))))
    sigma_s_prime = ceil(RR(((2*d)/sqrt(2*pi))*pow(q, (k/(l_prime+k)+2/(d*(l_prime+k))))))

    print("t_inf  =", t_inf)
    print("log2(sigma_s)       =", log(sigma_s, 2))
    print("log2(sigma_s_prime) =", log(sigma_s_prime, 2))

    #Intermediate bounds
    B_zero = RR(sqrt(d*(l+k))*(eta_s*pow(w, kappa+1)+6*sigma_s*(kappa-1)*pow(w, kappa-1)))
    B_zero_prime = RR(sqrt(d*(l_prime+k))*(eta_prime_s*pow(w, kappa+1)+6*sigma_s_prime*(kappa-1)*pow(w, kappa-1)))
    B_hat_0 = RR(sqrt(pow(B_zero, 2) + pow(B_zero_prime, 2)))

    #Gaussian widths of the AGGREGATED responses
    sigma_tilde_z = RR(phi*B_zero*sqrt(T))
    sigma_tilde_r = RR(phi*B_zero_prime*sqrt(T))
    sigma_tilde_e = RR(phi*B_hat_0*sqrt(T))

    #The AMSIS instance below is stated in the infinity norm, so it must be fed the
    #ell_inf bounds that Vf actually checks -- not the ell_2 bounds. Using the ell_2
    #bounds here hands the extractor a spurious factor of 1.2*sqrt(d*k) ~= 53.
    B_tilde_z = RR(t_inf*sigma_tilde_z)
    B_tilde_r = RR(t_inf*sigma_tilde_r)
    B_tilde_e = RR(t_inf*sigma_tilde_e)

    B_det = RR(pow((2*w), kappa*(kappa+1)/2))

    B_Gamma = RR(pow((2*w), kappa*(kappa-1)/2))

    # --- ASIS infinity-norm buckets ---
    # 1) determinant/aggregation scalar term
    #    ||det(Vx)det(Vx')(alpha_u - alpha'_u)||_inf <= 2 * B_det^2
    B_alpha = RR(2 * pow(B_det, 2))
    m_alpha = 1
    arr.append([B_alpha, m_alpha])
    print("log2(B_alpha) =", log(B_alpha, 2), "m_alpha =", m_alpha)

    #Note that for the below bounds, we can only use the upper bounds that the verifier checks!
    #So we cannot arbitrarily replace these by smaller bounds for honest signatures.
    #Essentially, the d and d*k terms are left out from the bounds computed in l_2 MSIS instance
    # 2) z-hat difference
    #    coefficientwise bound from ||ab||_inf <= ||a||_1 ||b||_inf
    #    and ||tilde_z||_inf <= ||tilde_z|| <= B_tilde_z
    B_zhat = RR(2*(kappa + 1)*B_det*B_Gamma*B_tilde_z)
    m_zhat = l
    arr.append([B_zhat, m_zhat])
    print("log2(B_zhat)  =", log(B_zhat, 2), "m_zhat  =", m_zhat)

    # 3) r-hat difference
    B_rhat = RR(2*(kappa + 1)*B_det*B_Gamma*B_tilde_r)
    m_rhat = l_prime
    arr.append([B_rhat, m_rhat])
    print("log2(B_rhat)  =", log(B_rhat, 2), "m_rhat  =", m_rhat)

    # 4) e-hat difference
    B_ehat = RR(2*(kappa + 1)*B_det*B_Gamma*B_tilde_e)
    m_ehat = k
    arr.append([B_ehat, m_ehat])
    print("log2(B_ehat)  =", log(B_ehat, 2), "m_ehat  =", m_ehat)


    if (compress_w):
    # 5) eta-hat_w difference
        B_eta_w = RR(pow(2,(K_w0 - 1)))
        B_etahat = RR(2*(kappa + 1)*B_det*B_Gamma*B_eta_w)
        m_etahat = k
        arr.append([B_etahat, m_etahat])
        print("log2(B_etahat) =", log(B_etahat, 2), "m_etahat =", m_etahat)
    else:
        # no eta-hat block exists
        # add a dummy bucket only because the ASIS code insists on 5 buckets
        B_dummy = min(B_alpha, B_zhat, B_rhat, B_ehat)
        m_dummy = 0
        arr.append([B_dummy, m_dummy])

    arr.sort(key=lambda x: x[0], reverse=True)
    return arr

def setDualMSASISRank(d, k, l, l_prime, RHF_max, logq, arr, compress_w):
    extra = 0.00005
    print("\n=== Ordered DualMS ASIS bounds ===")

    B1, m1 = arr[0]
    B2, m2 = arr[1]
    B3, m3 = arr[2]
    B4, m4 = arr[3]
    B5, m5 = arr[4]

    print("B1 =", log(B1, 2), "m1 =", m1)
    print("B2 =", log(B2, 2), "m2 =", m2)
    print("B3 =", log(B3, 2), "m3 =", m3)
    print("B4 =", log(B4, 2), "m4 =", m4)
    print("B5 =", log(B5, 2), "m5 =", m5)

    q = pow(2, logq)
    total_width = m1 + m2 + m3 + m4 + m5

    if (compress_w):
        # This should equal 1 + l + l_prime + 2*k
        print("total_width =", total_width, "expected =", 1 + l + l_prime + 2*k)
    else:
        # This should equal 1 + l + l_prime + k
        print("total_width =", total_width, "expected =", 1 + l + l_prime + k)

    # k is sisrank
    params = ASISParameterSet(d, total_width, k, B1, B2, B3, B4, B5, m1, m2, m3, m4, m5, q, norm="linf")

    try:
        print("Running ASIS_summarize_attacks for DualMS...")
        (m_pq, b_pq, c_pq) = ASIS_summarize_attacks(params, attack_variant=0)
    except Exception as e:
        print("ASIS_summarize_attacks failed:", e)
        return k, False

    rhf = round(ASIS_delta_BKZ(b_pq), 5)

    print("BKZ block size =", b_pq)
    print("RHF            =", rhf)
    print("Cost           =", round(c_pq, 5))

    if rhf <= (RHF_max + extra):
        return k, True
    else:
        return k, False

def findDualMSASISParams(T, kappa, B, eta_s, eta_prime_s, t, logq_min, logq_max, RHF_max, phi, K_w, compress_w):
    d_arr = [128, 256]
    w = -1
    x_inf_norm = -1

    output_arr = []

    for d in d_arr:
        try:
            w, x_inf_norm = infnorm_weight[128, d]
            print("w =", w, "x_inf_norm =", x_inf_norm, "\n")
        except KeyError:
            continue

        for logq in range(logq_min, logq_max):
            l = setLWERank(RHF_max, d, logq, B, uniform=True)
            if l == -1:
                print("Skipping: no valid LWE rank found")
                continue

            k = 1
            boolChecks = False

            while (k*d <= 8192) and (not boolChecks):
                l_prime = l + 1
                print("Trying parameters: d =", d, "logq =", logq, "l =", l, "k =", k)
                arr = setDualMSASISBounds(T, kappa, d, w, k, l, l_prime, eta_s, eta_prime_s, t, logq, phi, K_w, compress_w)
                _, boolChecks = setDualMSASISRank(d, k, l, l_prime, RHF_max, logq, arr, compress_w)
                if not boolChecks:
                    k += 10

            if k*d > 8192:
                print("Could not find parameters")
                continue

            print("Refining k...")
            while boolChecks and k > 0:
                output_arr.append([d, logq, l, k, True])
                k -= 1
                l_prime = l + 1
                arr = setDualMSASISBounds(T, kappa, d, w, k, l, l_prime, eta_s, eta_prime_s, t, logq, phi, K_w, compress_w)
                _, boolChecks = setDualMSASISRank(d, k, l, l_prime, RHF_max, logq, arr, compress_w)

    return output_arr

"""------------------------------------------------------------------------------------------------------------------"""
""" Auxiliary signature functions"""
#Calculate signature size
def calculate_sig_size(kappa, beta, n_hat, k_hat, k, l, l_prime, d, b_qhat, b_q, K_b, K_w0, const_size_x, sigma_f, sigma_z_b, sigma_tilde_z, sigma_tilde_r, sigma_tilde_e, compress_w):
    const = 4.13
    b2KB = pow(2,13) #Convert bits to bytes

    size_B_bin_1 = n_hat*d*(ceil(b_qhat) - K_b)

    #Only kappa = 1 case
    if (kappa == 1):
        size_w_0 = 0
    else:
        size_w_0 = (kappa-1)*k*d*(ceil(b_q) - K_w0)

    size_f_1 = RR(kappa*(beta-1)*d*log(const*sigma_f,2))
    size_z_b = RR((n_hat+k_hat)*d*log(const*sigma_z_b,2))
    size_tilde_z = RR(l*d*log(const*sigma_tilde_z,2))
    size_tilde_r = RR(l_prime*d*log(const*sigma_tilde_r,2))
    size_tilde_e = RR(k*d*log(const*sigma_tilde_e,2))

    print("=== Parts of signature ===")
    print("size_B_bin_1:", RR(size_B_bin_1/b2KB), "KiB\n")
    print("size_w_0:", RR(size_w_0/b2KB), "KiB\n")
    print("size_f_1:", RR(size_f_1/b2KB), "KiB\n")
    print("size_z_b:", RR(size_z_b/b2KB), "KiB\n")
    print("size_tilde_z:", RR(size_tilde_z/b2KB), "KiB\n")
    print("size_tilde_r:", RR(size_tilde_r/b2KB), "KiB\n")
    print("size_tilde_e:", RR(size_tilde_e/b2KB), "KiB\n")

    sig_size = size_B_bin_1 + size_w_0 + const_size_x + size_f_1 + size_z_b + size_tilde_z + size_tilde_r + size_tilde_e
    return RR(sig_size)

#Calculate number of repetitions
def number_reps(T, phi_a, phi_b, phi, nhat, d, w, K_a, K_b, K_w0, eps_total, compress_w):

    mu_a = exp(12/phi_a + 1/(2*pow(phi_a, 2)))
    mu_b = exp(12/phi_b + 1/(2*pow(phi_b, 2)))
    mu = exp(12/phi + 1/(2*pow(phi, 2)))
    mu_BG = exp(nhat*d*((w*pow(2, K_b)-1)/pow(2, K_a)))

    #mu_w = 1 is valid ONLY for kappa = 1: there hat{w}_0 = tilde{w}_0, so
    #w-compression enforces no stability condition and adds no restart event.
    #For kappa > 1 the Sign_bin check ||tilde{w}_0||_inf > 2^{K_w0-1} - M_w is a
    #genuine restart factor that this function does not model.
    mu_w = 1

    mu_fg = RR(1/(1-eps_total))

    mu_total = mu_a * mu_b * pow(mu, T) * mu_BG * mu_w * mu_fg

    return mu_total


#Calculate the size of PK (structured ring)
#After the Section 4 revision PK = (R, Psi): R holds M <= T*N DISTINCT registered
#keys and Psi is a column-injective cell labelling pi : [0,T-1]x[0,N-1] -> R.
#Key material therefore scales with M, not T*N; the labelling costs T*N indices
#of ceil(log2 M) bits on top.  M = T*N recovers the all-distinct case exactly
#(the labelling is then the identity and costs nothing).
def calculate_PK(T, N, k, d, logq, M=None):
    if M is None:
        M = T * N
    if not T <= M <= T * N:
        raise ValueError("column-injectivity requires T <= M <= T*N")

    single_pk = k * d * ceil(logq)
    size_keys = M * single_pk
    size_labelling = 0 if M >= T*N else T * N * ceil(log(M, 2))
    size_PK = size_keys + size_labelling

    print("Distinct registered keys M =", M, "out of T*N =", T*N)
    print("  key material  =", RR(size_keys/pow(2,13)), "KiB")
    print("  labelling Psi =", RR(size_labelling/pow(2,13)), "KiB")

    return single_pk, size_PK
"""------------------------------------------------------------------------------------------------------------------"""
"""Main function"""
def main():
    RHF_max = 1.0045

    T = 50 #Threshold size
    N = 100 #Ring size; n = beta^kappa
    kappa = 1
    beta = 100
    B = 1 #All MLWE instances use B = 1

    K_b = 5 #Dropped bits from B_bin
    K_w0 = 5 #Dropped bits from \tilde{w}

    t = 1.2 #Gaussian tail bound param
    eta_s, eta_prime_s = 1, 1 #Smoothing param

    #Rej sampling slack factors
    phi_a = 24
    phi_b = 24
    phi = 22 * T
    mu_BG_target = RR(1.01)

    #Set probability that bounds on f_0, f_1, g_0, g_1 will reject
    eps_total = RR(0.01)

    #Bin logqhat logq range to search over
    logqhat_min = 35
    logqhat_max = 45

    #DualMS logq range to search over
    logq_min = 35
    logq_max = 45

    #Check whether to compress \tilde{w}_0
    compress_w = True

    # Binary proof MLWE + ASIS sweep.  Sister sweeps for the DualMS
    # side are exposed via findDualMSParams() (L2 MSIS bound) and
    # findDualMSASISParams() (per-bucket ASIS bound); the latter is
    # what lotrs_estimate.py runs at the chosen point.  Enable here
    # if you need to re-derive the DualMS dimensions from scratch
    # rather than validate at the published parameters.
    output_bin_arr = findBinParams(beta, kappa, logqhat_min, logqhat_max, RHF_max,
                                   phi_a, phi_b, K_b, eps_total, mu_BG_target)

if __name__ == "__main__":
    main()

