use ark_bls12_381::Fr;
use ark_ff::{One, UniformRand, Zero};
use ark_std::test_rng;
use gp_mhac::lsss::disjunction;
use gp_mhac::ops::{reset, snapshot, OpCounts};

fn reconstruct(rows: &[usize], coeffs: &[(usize, Fr)], shares: &[Fr]) -> Fr {
    rows.iter().fold(Fr::zero(), |sum, row| {
        let coeff = coeffs
            .iter()
            .find(|(candidate, _)| candidate == row)
            .map(|(_, value)| *value)
            .unwrap_or_else(Fr::zero);
        sum + coeff * shares[*row]
    })
}

#[test]
fn variable_width_disjunction_reconstructs_clause_with_all_one_coefficients() {
    let mut rng = test_rng();
    for (clauses, width) in [(2usize, 3usize), (2, 5), (2, 7), (2, 9), (8, 3), (12, 3)] {
        reset();
        let lsss = disjunction(clauses, width);
        assert_eq!(lsss.matrix.len(), clauses * width);
        assert_eq!(lsss.rho, (0..clauses * width).collect::<Vec<_>>());
        assert!(lsss
            .matrix
            .iter()
            .all(|row| row.len() == 1 + (width - 1) * clauses));

        let secret = Fr::rand(&mut rng);
        let shares = lsss.share(secret, &mut rng);
        for clause in 0..clauses {
            let rows: Vec<_> = (clause * width..(clause + 1) * width).collect();
            let coeffs = lsss.recon_coeffs(&rows).expect("whole clause reconstructs");
            assert_eq!(coeffs.len(), width);
            assert!(coeffs.iter().all(|(_, coeff)| *coeff == Fr::one()));
            assert_eq!(reconstruct(&rows, &coeffs, &shares), secret);

            let incomplete: Vec<_> = rows.iter().copied().take(width - 1).collect();
            if !incomplete.is_empty() {
                assert_eq!(lsss.recon_coeffs(&incomplete), None);
            }
        }

        if clauses > 1 {
            let mixed: Vec<_> = (0..width - 1).chain([width]).collect();
            assert_eq!(lsss.recon_coeffs(&mixed), None);
        }
        assert_eq!(snapshot(), OpCounts::default());
    }
}
