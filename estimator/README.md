# LoTRS Parameter Estimator

This directory contains the scripts used to reproduce the concrete
parameter estimates reported for the LoTRS paper, including the
`N = 100`, `T = 50` parameter set.

## Requirements

- SageMath with Python support available as `sage`.
- No network access or external datasets are required at run time.

## Reproducing the Paper Parameter Estimate

From the repository root, run:

```bash
cd estimator
make
```

The scripts import `sage.all`, so running them with plain `python3` will
fail unless that Python environment is the Sage Python environment.

The Makefile invokes:

```bash
sage -c "exec(open('lotrs_estimate.py').read()); main()"
```

This command is used because it runs from this directory, makes the
local helper modules importable, and explicitly invokes the script entry
point.

The script prints:

- MLWE estimates for the binary-proof and DualMS components,
- ASIS/MSIS-style estimates for the binary-proof and DualMS components,
- the concrete signature size,
- the single public-key and full ring public-key sizes,
- the expected number of rejection-sampling repetitions,
- basic parameter-condition checks.

For the paper parameter point (`N = 100`, `T = 50`, `κ = 1`,
`d = 128`, `n̂ = 11`, `k̂ = 8`, `l = 5`, `l' = 6`, `k = 12`,
`q = q̂ = 274877906837`, `φ = 22·T = 1100`,
`φ_a = 24`, `φ_b = 4`, `K_A = 28`, `K_B = 5`, `K_w = 5`,
`μ_BG target = 1.01`), the expected headline values are:

```text
Signature size: about 35.06 KB
Single public key size: about 7.13 KB
Ring PK size: about 35,625 KB
Number of repetitions for rejection sampling: about 2.98 (estimator heuristic)
Binary-proof PQ ASIS cost: about 87 bits
DualMS      PQ ASIS cost: about 90 bits
```

The "number of repetitions" is the estimator's restart-rate
heuristic μ_total; the empirical attempt count in the reference
implementations may be higher because the signer additionally
performs a `w̃₀`-stability restart on top of the rejection
checks counted here.

The checked-in reference output `LoTRS-Estimate-Output-N100T50.txt`
is intended only as a comparison log. The first line is a
hand-written scrubbing comment (`# Reference output of: ...`); the
remaining 113 lines are the verbatim Sage output. Before including
fresh output logs in the artifact, scrub them so they do not contain
shell prompts, usernames, hostnames, local paths, timestamps, or
other environment metadata.

To write a fresh comparison log, run:

```bash
make reference
```

This writes `LoTRS-Estimate-Output-N100T50.generated.txt` next to
the committed reference. Diff the two to confirm the run reproduces
the published parameters; for byte-exact comparison, strip the
leading scrub-comment line from the committed file first
(`diff <(tail -n +2 LoTRS-Estimate-Output-N100T50.txt) LoTRS-Estimate-Output-N100T50.generated.txt`).

To remove generated caches and logs, run:

```bash
make clean
```

## Files

- `lotrs_estimate.py`: main script for the concrete LoTRS parameter
  point (`N = 100`, `T = 50`). Pins the moduli, lattice dimensions,
  and rejection-sampling slack factors used by the paper and by the
  reference implementations in `lotrs-py/` and `lotrs-rs/`. The
  Python and Rust parameter sets must agree with what this script
  prints.
- `lotrs_finder.py`: search routines and helper formulas used to
  derive the chosen point (LWE-rank lookup tables, ASIS bound
  buckets, signature-size and repetition formulas). The
  helper functions (`setBinASISBounds`, `setDualMSASISBounds`,
  `calculate_sig_size`, `number_reps`, `calculate_PK`) are imported
  by `lotrs_estimate.py`. Running it as a script
  (`sage -c "exec(open('lotrs_finder.py').read()); main()"`)
  re-runs the binary-proof MLWE / ASIS dimension sweep; the DualMS
  sweep helpers are also exported but not invoked by default.
- `lotrs_param_checks.py`: consistency checks for the chosen moduli,
  challenge differences, regularity bounds, and range-proof
  condition.
- `LoTRS-Estimate-Output-N100T50.txt`: scrubbed reference output for
  the concrete paper parameter point.

## Provenance of External Components

This directory includes local copies or adaptations of public estimator
code so the artifact can be evaluated without fetching dependencies:

- `estimator/`: bundled lattice/LWE estimator code used through
  `from estimator import *`.
- `kd_estimates/`: security-estimation helper scripts derived from
  public post-quantum security-estimation code.
- `ASIS_sec_estimate/`: asymmetric-SIS estimation scripts adapted from
  Dilithium/security-estimates scripts, as noted in
  `ASIS_sec_estimate/README.md`.

The LoTRS-specific entry points are `lotrs_estimate.py`,
`lotrs_finder.py`, and `lotrs_param_checks.py`. When preparing a public
artifact, preserve the provenance notes and any applicable license
notices for the bundled external estimator components.
