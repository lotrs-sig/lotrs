# LoTRS Parameter Estimator

The production profile is [`../parameters.json`](../parameters.json),
shared with the Python and Rust implementations. The estimator computes
parameter conditions, Gaussian bounds, analytic sizes, signing-repetition
heuristics, and lattice attack costs.

## Requirements and execution

SageMath must be available as `sage` (tested with SageMath 10.9; override
with `make SAGE=/path/to/sage`). The main estimate reads the shared
manifest; regression tests also load the Python implementation. No
network access or external datasets are required after installation.

```bash
cd estimator
make test           # five estimator/verifier consistency regressions
make                # LWE and ASIS estimates, sizes, and conditions
make reference      # save LoTRS-Estimate-Output-N100T50.generated.txt
```

The full estimate takes about 18 minutes on the reference workstation.
Compare the generated output with `LoTRS-Estimate-Output-N100T50.txt`.
Ignore elapsed times, local paths, and final-digit numerical differences;
compare parameter fields exactly and printed numerical results to their
reported precision. The Makefile propagates estimator failures through
the output pipeline.

## Profile and expected results

`N=100, T=50, d=128, kappa=1`, `k=14, l=20, l_prime=21`,
`n_hat=12, k_hat=11`, `q=2^43-67`, `q_hat=2^35-451`, `w=31`,
`eta=eta_prime=1`, `phi=1100`, `phi_a=phi_b=24`, `K_A=28`,
`K_B=K_w=5`, `tail_t=1.2`, `tail_inf=12`, `eps_tot=0.01`.

| Quantity | Result |
|---|---:|
| Analytic signature | 52.6574 KiB |
| Single public key | 9.40625 KiB |
| Full ring public keys | 47,031.25 KiB |
| Expected attempts (heuristic) | 4.7728 |
| Binary-proof PQ ASIS cost (variant 0) | 100.7978 bits |
| DualMS PQ ASIS cost (variant 0) | 94.16636 bits |
| Binary-proof PQ ASIS cost (variants 1 and 2) | 88.86122 bits |
| DualMS PQ ASIS cost (variants 1 and 2) | 86.20864 bits |

All three ASIS cost-model variants are reported separately. Their outputs
do not substantiate 128-bit post-quantum security. Passing the parameter
condition checks is not a security certification; the reported attack
models and cost conventions must be considered separately.

The analytic signature size uses `log2(4.13*sigma)` per Gaussian
coefficient. The [Rust benchmark](../lotrs-rs/bench-out/README.md) measures
53.53 KiB on the wire. Lossless Rice coding, fixed-width fields, byte
alignment, and sampled coefficients determine the emitted size.

## Calculations and checks

- Binary-proof ASIS merging retains all 271 columns of six blocks,
  relaxing adjacent bounds to fit the estimator's five-block interface.
- DualMS ASIS uses coefficientwise verifier bounds, both determinant
  factors, and the sum of the two error variances.
- LWE estimates use ternary secrets and errors with finite sample counts.
- Repetition estimates include ordinary `Rej` for `z_b` and the binary
  proof's bound checks. The `kappa=1` stability check adds no restarts.
- Public keys and commitments use whole coefficient bit widths.
  Registry-size calculations enforce `T <= M <= T*N`.
- Primality, challenge invertibility, regularity, and both range-proof
  branches are checked; failed conditions stop the main estimate.

`lotrs_estimate.py` is the entry point. `lotrs_finder.py` contains size,
bound, and parameter-search helpers; `lotrs_param_checks.py` implements
condition checks. `test_alignment.py` connects ASIS buckets to verifier
bounds. Use `make clean` to remove caches and logs.

## Bundled dependencies

The package includes the lattice/LWE estimator in `estimator/`,
security-estimation helpers in `kd_estimates/`, and asymmetric-SIS
estimation code in `ASIS_sec_estimate/`. Their upstream attribution and
license notices are retained with the source files.
