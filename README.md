# GP-MHAC

This repository implements the scheme in *GP-MHAC: Multi-Holder Anonymous Credentials With General Access Structures and Committee Pseudonyms* and the comparison schemes MHAC and TZ23, using arkworks 0.4 over BLS12-381 and SHA-256 for hashing.

## Features

- The issuer distributes one BBS credential among holders using linear secret sharing under a general monotone access structure.
- Any authorized committee can present the credential jointly in five rounds. For a fixed attribute and disclosure pattern, the presentation size and the verifier's cost are independent of committee size.
- For the same credential and context, all authorized committees derive the same committee pseudonym without pooling the shares of the pseudonym secret. Presentations under distinct contexts are unlinkable.
- Private attributes remain secret-shared throughout joint presentation.
- If presentation aborts, all honest active holders reach the same verdict: at least one misbehaving holder is identified, and no honest holder is blamed.

## Comparison schemes

| Scheme | Paper | Venue | Implementation |
|---|---|---|---|
| MHAC | *Multi-Holder Anonymous Credentials from BBS Signatures*, Flamini, Lee and Lysyanskaya | CRYPTO 2025 | Issuance of threshold-shared credentials with the share-size optimization from Appendix H, joint presentation and verification. Its detector checks the honest path before the blame path, in the same order as GP-MHAC. |
| TZ23 | *Revisiting BBS Signatures*, Tessaro and Zhu | EUROCRYPT 2023 | BBS issuance, single-holder presentation with selective disclosure, and verification. |

## Requirements

- Rust 1.94.1, selected by `rust-toolchain.toml`; `Cargo.lock` pins the crate dependencies.
- Python 3.11, Matplotlib 3.8.4 and NumPy 2.2.6. The Python package versions are pinned in `scripts/requirements.txt`. The figures use Times New Roman (regular and italic); without it, the plotting script uses STIXGeneral.
- The paper's measurements used a MacBook Pro with an Apple M2 Pro and 32 GB RAM running macOS 14.6.1.
- The latency experiment runs each holder as a separate process over loopback TCP and keeps up to 492 holder processes alive; the host must allow this many processes and open sockets.

## Installation

From the repository root:

```sh
cargo build --release --all-targets --locked
python3.11 -m venv .venv
. .venv/bin/activate
python -m pip install -r scripts/requirements.txt
```

## Running the tests

```sh
cargo test --release --all-targets --locked
MPLBACKEND=Agg python -B -m unittest discover -s scripts -p 'test_*.py'
```

## Running the benchmarks

Run the benchmarks on an idle machine. List the commands, then run the whole set in a new directory:

```sh
scripts/run_all.sh --dry-run out
scripts/run_all.sh out
```

The script runs the network experiment once. It collects all 14 CSV files directly under `out/`, writes the table summary to `out/tables.md`, and writes eight PDFs to `out/figures/`.

To run individual experiments instead, create a new empty directory with `mkdir out` and use the commands below. The latency command supplies both latency datasets; run it only once.

| Experiment | Command | CSV output, relative to `out/` |
|---|---|---|
| Primitive costs | `target/release/bench_primitives out/primitives.csv` | `primitives.csv` |
| Per-role cost | `target/release/bench_roles out/roles.csv` | `roles.csv` |
| End-to-end latency and network latency | `target/release/bench_network out/latency` | `latency/e2e.csv` (Local), `latency/network.csv` (Local, LAN and WAN) |
| Verification by attribute count and committee size | `target/release/bench_verify out/verify.csv` | `verify.csv`, `verify_committee.csv` |
| Detection paths | `target/release/bench_detection out/detection.csv` | `detection.csv` |
| Access structures: Cases A–F | `target/release/bench_access out/access.csv` | `access.csv` |
| Effect of policy size | `target/release/bench_policy out/policy.csv` | `policy.csv` |
| Communication overhead and holder storage | `target/release/bench_sizes out/sizes.csv` | `sizes.csv` |
| Cost tables: group operations and serialized lengths | `target/release/count_ops out` | `gp_ops.csv`, `gp_bytes.csv`, `mhac_tz_ops.csv`, `mhac_tz_lengths.csv` |

For a manually collected dataset, place the two latency CSVs beside the other twelve with `cp out/latency/e2e.csv out/latency/network.csv out/`.

**Workload and policies.** The default workload uses a 5-of-10 policy and 14 non-reserved attributes: two privately shared, four hidden public, and eight revealed. Including reserved coordinates, GP-MHAC has 16 attributes (four private, eight hidden), MHAC has 15 (three private, seven hidden), and TZ23 has 14 (six hidden). The threshold sweep uses 6, 10, 20, 40, 70 and 100 holders, with half active and one row per holder. In each threshold trial, the active holders are drawn uniformly without replacement; GP-MHAC and MHAC use the same draw and compute reconstruction coefficients by Lagrange interpolation.

**Experiment grids.** Verification varies the non-reserved attribute count over 8, 16, 24, 32, 48 and 64, with half revealed and two privately shared. Detection compares 10, 40 and 100 holders. The access-structure experiment compares six policies: A, 3-of-6; B, 6-of-12; C, 1-of-12; D, a disjunction of four disjoint 3-of-3 clauses; E, 6-of-12 rows with two rows per holder; and F, a 3-of-6 and a 2-of-6 clause on disjoint holders. The policy-size experiment uses 4, 8, 12, 16 and 24 rows, with three reconstruction rows and three active holders. Communication compares two and four privately shared non-reserved attributes.

**Timing and network.** Timings are means over 100 runs after ten warm-ups; primitive timings use 1,000 runs after 100 warm-ups. Error bars are two-sided 95% Student’s *t* intervals. End-to-end latency runs from the request to the detector's release. Local, LAN and WAN trials are interleaved. Local adds no delay; the emulated LAN uses 1 Gbps and a 1 ms round trip, and the emulated WAN uses 200 Mbps and a 20 ms round trip. Each synchronization barrier adds one round trip plus transmission time for the received messages: five barriers for GP-MHAC and four for MHAC.

## Figures and tables

The CSV files in `results/` contain the measurements in the paper. To regenerate the figures in a separate directory and print the primitive, storage, communication and operation-count tables:

```sh
python scripts/plot_figures.py --results results --output out-figures
python scripts/summarize_tables.py --results results
```

## Directory structure

```text
.
├── README.md                          # Build, use and evaluate the schemes.
├── Cargo.toml                         # Crate manifest and dependencies.
├── Cargo.lock                         # Exact Rust dependency versions.
├── rust-toolchain.toml                # Pinned Rust compiler version.
├── .gitignore                         # Ignore local build and development files.
├── src/
│   ├── lib.rs                         # Public crate modules.
│   ├── access.rs                      # CompileAccess and reconstruction witnesses.
│   ├── lsss.rs                        # Formula compiler, secret sharing and Recon.
│   ├── issuance.rs                    # IssSetup, CredIss and row authentication.
│   ├── presentation.rs                # CredPres, VfPres and committee pseudonyms.
│   ├── detect.rs                      # Detector W on the honest path and blame path.
│   ├── primitives/
│   │   ├── mod.rs                     # Primitive module declarations.
│   │   ├── auth.rs                    # Schnorr signing and verification for Auth.
│   │   └── hash.rs                    # Hash-to-field, hash-to-group and commitments.
│   ├── baselines/
│   │   ├── mod.rs                     # Comparison scheme modules.
│   │   ├── mhac/
│   │   │   ├── mod.rs                 # Threshold holder operations and shared MHAC types.
│   │   │   ├── issuance.rs            # MHAC issuance and compact credential shares.
│   │   │   └── presentation.rs        # MHAC presentation, verification and fault attribution.
│   │   └── tz23.rs                    # Single-holder BBS signatures and disclosure proofs.
│   ├── ops.rs                         # Counted group operations and pairings.
│   ├── workload.rs                    # Attribute workloads and reproducible committee draws.
│   └── bin/
│       ├── bench_access.rs            # Compare six access structures.
│       ├── bench_detection.rs         # Measure honest, prefix and full blame paths.
│       ├── bench_network.rs           # Run Local, LAN and WAN latency trials together.
│       ├── bench_policy.rs            # Vary the number of policy rows.
│       ├── bench_primitives.rs        # Measure seven cryptographic primitives.
│       ├── bench_roles.rs             # Measure Primary and non-Primary holder costs.
│       ├── bench_sizes.rs             # Record credential shares and broadcast bytes.
│       ├── bench_verify.rs            # Measure verification in both sweeps.
│       ├── count_ops.rs               # Count protocol operations and message lengths.
│       └── support/
│           ├── local.rs               # Workloads, timing and CSV output for local trials.
│           ├── mhac_cost.rs           # MHAC workloads, holder costs and sizes.
│           ├── mhac_counts.rs         # Operation and byte counts for MHAC and TZ23.
│           ├── network.rs             # Holder workers, coordinator and barrier timing.
│           └── net/
│               ├── schedule.rs         # Randomized trial order, process pools and output.
│               └── wire.rs             # Packet encodings and framed TCP transport.
├── examples/
│   └── basic.rs                       # Present one credential with two authorized committees.
├── tests/
│   ├── domain_vectors.rs              # Seeded session and proof encodings.
│   ├── gp_mhac_abort_attribution.rs   # Sender attribution on the blame path.
│   ├── gp_mhac_cached_costs.rs        # Cached reconstruction and holder costs.
│   ├── gp_mhac_detection.rs           # Honest-path costs and attribution of faults.
│   ├── gp_mhac_detector_timing.rs     # Equivalence of timed and untimed detector outcomes.
│   ├── gp_mhac_disjunction_costs.rs   # Reconstruction and operation counts for disjunctions.
│   ├── gp_mhac_formula_compiler.rs    # Authorization for nested threshold formulas.
│   ├── gp_mhac_issuance.rs            # Issuance costs, row integrity and credential sizes.
│   ├── gp_mhac_policy_detection.rs    # Honest detection across access structures.
│   ├── gp_mhac_presentation.rs        # Presentation stages, verification and cost counts.
│   ├── gp_mhac_reconstruction.rs      # Witnesses, coefficients and reconstruction equivalence.
│   ├── gp_mhac_session_binding.rs     # Session identifier binding.
│   ├── gp_mhac_setup_costs.rs         # Operation counts for issuer setup.
│   ├── gp_mhac_support_and_prefix.rs  # Reconstruction support and prefix detection.
│   ├── gp_mhac_threshold_encoding.rs  # Threshold presentation encodings.
│   ├── mhac_issuance.rs               # Issuance, factor authentication and share lengths.
│   ├── mhac_presentation.rs           # MHAC honest presentation and blame decisions.
│   └── tz23.rs                        # TZ23 costs, lengths and invalid proof rejection.
├── results/
│   ├── access.csv                     # Stage timings for access structures A–F.
│   ├── detection.csv                  # Detection path timings.
│   ├── e2e.csv                        # Local latency trials from the network campaign.
│   ├── gp_bytes.csv                   # Serialized GP-MHAC lengths and predictions.
│   ├── gp_ops.csv                     # Counted and predicted GP-MHAC operations.
│   ├── mhac_tz_lengths.csv            # Serialized MHAC and TZ23 lengths and predictions.
│   ├── mhac_tz_ops.csv                # Counted and predicted MHAC and TZ23 operations.
│   ├── network.csv                    # Local, LAN and WAN timings and barrier delays.
│   ├── policy.csv                     # Stage timings over policy sizes.
│   ├── primitives.csv                 # Per-operation timings and repetition order.
│   ├── roles.csv                      # Holder-role timings.
│   ├── sizes.csv                      # Holder storage and joint communication in bytes.
│   ├── verify.csv                     # Verification times by attribute count.
│   └── verify_committee.csv           # Verification times by committee size.
├── figures/
│   ├── communication_cost.pdf         # Presentation communication by committee size.
│   ├── comp_access.pdf                # Issuance, presentation and detection by access structure.
│   ├── comp_detection.pdf             # Cost of the detection paths.
│   ├── comp_e2e.pdf                   # End-to-end presentation latency.
│   ├── comp_policy.pdf                # Issuance, presentation and detection by policy size.
│   ├── comp_role.pdf                  # Per-role cost by committee size.
│   ├── comp_verify.pdf                # Verification cost by attribute count.
│   └── network_latency.pdf            # Presentation latency under LAN and WAN emulation.
└── scripts/
    ├── run_all.sh                     # Run all measurements, summarize tables and draw figures.
    ├── plot_access.py                 # Draw the access-structure panel.
    ├── plot_bar_groups.py             # Draw grouped timings, error bars and numeric labels.
    ├── plot_bars.py                   # Bar styles and shared labels.
    ├── plot_data.py                   # Load observations and compute confidence intervals.
    ├── plot_figures.py                # Generate all eight PDFs and optionally export plot values.
    ├── plot_lines.py                  # Draw role, scheme, communication and latency comparisons.
    ├── summarize_tables.py            # Summarize timings and lengths and verify cost formulas.
    ├── test_plot_data.py              # Test input validation and timing statistics.
    ├── test_plot_figures.py           # Test panel contents, geometry and numerical labels.
    ├── test_summarize_tables.py       # Test primitive, byte and operation-count summaries.
    └── requirements.txt               # Pinned Python plotting dependencies.
```

## Usage example

The director alone, or two of the three finance officers together with one of the two legal officers, can present the same credential. The example verifies presentations from both committees in the same context and compares their pseudonyms.

```sh
cargo run --release --example basic
```

```rust
use ark_bls12_381::Fr;
use ark_std::rand::{rngs::OsRng, RngCore};
use gp_mhac::access::compile_access;
use gp_mhac::issuance::{cred_iss, cred_iss_attributes, iss_setup};
use gp_mhac::lsss::{compile_formula, Formula};
use gp_mhac::presentation::{cred_pres, vf_pres};

fn main() {
    let mut rng = OsRng;
    // IssSetup: two business attributes plus the reserved pseudonym and mask coordinates.
    let (pp, keys) = iss_setup(4, &mut rng);

    // CompileAccess: director 0, finance officers 1–3, legal officers 4–5.
    use Formula::{Leaf, Thr};
    let finance = Thr(2, (1..=3).map(Leaf).collect());
    let legal = Thr(1, (4..=5).map(Leaf).collect());
    let policy = Thr(1, vec![Leaf(0), Thr(2, vec![finance, legal])]);
    let access = compile_access(compile_formula(&policy), 6);

    // CredIss: business attribute 0 is private, and attribute 1 is revealed.
    let (shares, prv, rev, j_pid) = {
        let business = [Fr::from(7u64), Fr::from(42u64)];
        let a = cred_iss_attributes(&business, &[0], &[1], &mut rng).unwrap();
        let shares = cred_iss(&pp, &keys, &a.attrs, &a.prv, &access, &mut rng).unwrap();
        (shares, a.prv, a.rev, a.j_pid)
    };

    let ctx = b"purchase-approval";
    // Only public values come from the credential; CredPres uses row shares for private slots.
    let mut public = vec![Fr::from(0u64); pp.h.len()];
    for &(j, value) in &shares[0].pub_attrs {
        public[j] = value;
    }
    let revealed: Vec<_> = rev.iter().map(|&j| (j, public[j])).collect();
    let mut present = |holders: &[usize]| {
        let rows: Vec<_> = access
            .lsss
            .rho
            .iter()
            .enumerate()
            .filter_map(|(row, holder)| holders.contains(holder).then_some(row))
            .collect();
        let mut nonce = [0; 32];
        rng.fill_bytes(&mut nonce);
        let (proof, _) = cred_pres(
            &pp, &keys.ipk, &shares, &public, &prv, &access, &rows, &rev, ctx, nonce, &mut rng,
        )
        .unwrap();
        // VfPres receives the public coordinate index j_pid, not the pseudonym secret.
        assert!(vf_pres(
            &pp, &keys.ipk, &proof, &revealed, j_pid, ctx, nonce
        ));
        proof.nym
    };

    let director_nym = present(&[0]);
    let officers_nym = present(&[1, 2, 4]);
    assert_eq!(director_nym, officers_nym);
    println!("Both committees verified with the same pseudonym in this context.");
}
```

## License

See [LICENSE](LICENSE).
