use ark_bls12_381::Fr;
use ark_ff::{One, Zero};
use ark_std::rand::{rngs::StdRng, seq::SliceRandom, Rng, SeedableRng};
use gp_mhac::workload::draw_threshold;
use gp_mhac::{
    access::{compile_access, CompiledAccess},
    detect::canonicalize_cached,
    lsss::{compile_formula, disjunction, threshold, Formula, Lsss},
};

fn same(access: &CompiledAccess, rows: &[usize]) {
    let expected = access.lsss.recon_general(rows);
    let actual = access.lsss.recon_coeffs(rows);
    assert_eq!(actual, expected, "ordered sparse vector for {rows:?}");
    if rows.windows(2).all(|w| w[0] < w[1]) {
        let witness = access.reconstruct(rows);
        assert_eq!(
            witness.as_ref().map(|v| v.coefficients()),
            expected.as_deref()
        );
    }
}

#[test]
fn threshold_sweeps_match_elimination_in_every_draw() {
    for (t, n) in [
        (1, 12),
        (2, 4),
        (3, 4),
        (3, 6),
        (3, 8),
        (3, 12),
        (3, 16),
        (3, 24),
        (5, 8),
        (5, 10),
        (6, 12),
        (7, 14),
        (10, 20),
        (20, 40),
        (35, 70),
        (50, 100),
    ] {
        let access = compile_access(threshold(t, n), n);
        for round in 0..110 {
            let rows = draw_threshold(n, t, round);
            same(&access, &rows);
        }
    }
    let access = compile_access(
        Lsss {
            matrix: threshold(6, 12).matrix,
            rho: (0..12).map(|i| i / 2).collect(),
        },
        12,
    );
    for mask in 0u32..64 {
        if mask.count_ones() != 3 {
            continue;
        }
        let rows: Vec<_> = (0..12).filter(|i| mask & (1 << (i / 2)) != 0).collect();
        same(&access, &rows);
    }
    let multi = compile_access(
        Lsss {
            matrix: threshold(5, 8).matrix,
            rho: vec![0, 0, 1, 1, 2, 0, 1, 3],
        },
        4,
    );
    for mask in 0u32..256 {
        let rows: Vec<_> = (0..8).filter(|&i| mask & (1 << i) != 0).collect();
        same(&multi, &rows);
    }
    let extra = compile_access(threshold(2, 4), 4);
    same(&extra, &[0, 1, 2]);
}

#[test]
fn random_thresholds_match_elimination_for_short_and_redundant_sets() {
    let mut rng = StdRng::seed_from_u64(0x5448_5245_5348);
    for _ in 0..140 {
        let n = rng.gen_range(1..=36);
        let t = rng.gen_range(1..=n);
        let access = compile_access(threshold(t, n), n);
        let mut ids: Vec<_> = (0..n).collect();
        ids.shuffle(&mut rng);
        for k in [t - 1, t, rng.gen_range(t..=n), n] {
            same(&access, &ids[..k]);
            let mut ordered = ids[..k].to_vec();
            ordered.sort_unstable();
            same(&access, &ordered);
            if k >= t {
                let weights = access.reconstruct(&ordered).unwrap();
                assert_eq!(
                    weights
                        .coefficients()
                        .iter()
                        .map(|x| x.0)
                        .collect::<Vec<_>>(),
                    ordered[..t]
                );
                assert!(weights.coefficients().iter().all(|(_, v)| !v.is_zero()));
            }
        }
        same(&access, &[ids[0], ids[0]]);
        same(&access, &[n]);
    }
}

#[test]
fn general_policies_and_malformed_sets_agree_with_elimination() {
    let nested = Formula::Thr(
        2,
        vec![
            Formula::Thr(3, (0..6).map(Formula::Leaf).collect()),
            Formula::Thr(2, (6..12).map(Formula::Leaf).collect()),
        ],
    );
    let one = Fr::one();
    // The second row is a scalar multiple of the first: selected rows need not span the secret.
    let dependent = Lsss {
        matrix: vec![
            vec![one, one],
            vec![one + one, one + one],
            vec![one, Fr::zero()],
        ],
        rho: vec![0, 1, 2],
    };
    let mut almost = threshold(2, 6);
    almost.matrix[5][1] = Fr::from(2u64);
    for policy in [
        disjunction(4, 3),
        compile_formula(&nested),
        dependent,
        almost,
    ] {
        let n = policy.matrix.len();
        let access = compile_access(policy, n);
        for mask in 0..(1usize << n.min(6)) {
            let rows: Vec<_> = (0..n).filter(|i| mask & (1 << i) != 0).collect();
            same(&access, &rows);
        }
        for k in [0, 1, n / 2, n - 1, n] {
            same(&access, &(0..k).collect::<Vec<_>>());
        }
    }
    for invalid in [
        Lsss {
            matrix: vec![],
            rho: vec![],
        },
        Lsss {
            matrix: vec![vec![]],
            rho: vec![0],
        },
        Lsss {
            matrix: vec![vec![one], vec![one, one]],
            rho: vec![0, 1],
        },
        Lsss {
            matrix: vec![vec![one]],
            rho: vec![],
        },
    ] {
        assert_eq!(invalid.recon_coeffs(&[0]), None);
        assert_eq!(invalid.recon_coeffs(&[0]), invalid.recon_general(&[0]));
    }
}

#[test]
fn row_witness_checks_its_policy_and_requested_row_set() {
    let a = compile_access(threshold(2, 4), 4);
    let rows = [0, 2];
    let w = a.reconstruct(&rows).unwrap();
    let canonical = |access: &CompiledAccess, active: &[usize]| {
        canonicalize_cached(access, active, &w, &[], &[], &[0], 1, b"session")
    };
    assert_eq!(canonical(&a, &rows).first_bad_round, Some(1));
    assert!(std::panic::catch_unwind(|| canonical(&a, &[0, 1])).is_err());
    let different = compile_access(threshold(3, 4), 4);
    assert!(std::panic::catch_unwind(|| canonical(&different, &rows)).is_err());
    let mut mismatched = different;
    mismatched.asid = a.asid;
    assert!(std::panic::catch_unwind(|| canonical(&mismatched, &rows)).is_err());
    assert!(a.reconstruct(&[2, 0]).is_none());
    assert!(a.reconstruct(&[1, 1]).is_none());
    assert!(a.reconstruct(&[0, 4]).is_none());
}
