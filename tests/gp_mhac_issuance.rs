use ark_bls12_381::Fr;
use ark_ff::{One, UniformRand, Zero};
use ark_std::test_rng;
use gp_mhac::access::{compile_access, CompiledAccess};
use gp_mhac::issuance::{
    cred_iss, credential_size_bytes, holder_verify, iss_keygen, row_tag_message, setup, IssuerKeys,
    Parameters, PreCred,
};
use gp_mhac::lsss::{dnf_example, threshold, Lsss};
use gp_mhac::ops::{self, reset, snapshot, OpCounts};

#[test]
fn iss_setup_agrees_with_split_issuer_setup() {
    use ark_std::rand::{rngs::StdRng, RngCore, SeedableRng};
    use gp_mhac::issuance::iss_setup;
    let mut rng = StdRng::seed_from_u64(13);
    let mut reference = rng.clone();
    let (params, keys) = iss_setup(4, &mut rng);
    let expected_params = setup(4, &mut reference);
    let expected_keys = iss_keygen(&expected_params, &mut reference);
    assert_eq!(params.h, expected_params.h);
    assert_eq!(
        (params.g1, params.g2),
        (expected_params.g1, expected_params.g2)
    );
    assert_eq!((keys.x, keys.x2), (expected_keys.x, expected_keys.x2));
    assert_eq!(keys.auth_pk, expected_keys.auth_pk);
    assert_eq!(keys.auth_sk.0, expected_keys.auth_sk.0);
    assert_eq!(rng.next_u64(), reference.next_u64());
}

#[test]
fn setup_draws_distinct_nonidentity_generators() {
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    let mut rng = StdRng::seed_from_u64(2026);
    let first = setup(4, &mut rng);
    let second = setup(4, &mut rng);
    assert!(!first.g1.is_zero() && !first.g2.is_zero());
    assert!(!second.g1.is_zero() && !second.g2.is_zero());
    assert_ne!(first.g1, second.g1);
    assert_ne!(first.g2, second.g2);
    assert_eq!(first.h, second.h);
}

#[test]
fn header_binds_public_parameters_both_public_keys_and_framed_context() {
    use gp_mhac::issuance::{iss_setup, IssuerPublicKey};
    let (pp, keys) = iss_setup(3, &mut test_rng());
    let ctx = b"service";
    let hdr = keys.ipk.header(ctx);
    assert!(keys.ipk.matches_params(&pp.clone()));
    assert!(keys
        .ipk
        .matches_params(&Parameters::from_parts(pp.g1, pp.h.clone(), pp.g2)));
    let public = |params: &Parameters, x2, avk| IssuerPublicKey::from_parts(params, x2, avk);
    assert_eq!(hdr.len(), 40 + ctx.len());
    assert_eq!(&hdr[32..40], &(ctx.len() as u64).to_be_bytes());
    assert_eq!(&hdr[40..], ctx);
    assert_eq!(public(&pp, keys.x2, keys.auth_pk.clone()).header(ctx), hdr);
    for index in 0..5 {
        let mut changed = (*pp).clone();
        match index {
            0 => changed.g1 = -changed.g1,
            1 => changed.g2 = -changed.g2,
            2 => changed.h.swap(0, 1),
            3 => changed.h.truncate(1),
            _ => changed.h[0] = -changed.h[0],
        }
        let changed = Parameters::from_parts(changed.g1, changed.h, changed.g2);
        assert!(!keys.ipk.matches_params(&changed));
        assert_ne!(
            public(&changed, keys.x2, keys.auth_pk.clone()).header(ctx),
            hdr
        );
    }
    let mut other_key = keys.auth_pk.clone();
    other_key.0 = -other_key.0;
    assert_ne!(public(&pp, keys.x2, other_key).header(ctx), hdr);
    assert_ne!(public(&pp, -keys.x2, keys.auth_pk.clone()).header(ctx), hdr);
    reset();
    let other = keys.ipk.header(b"service\0");
    assert_eq!(snapshot(), OpCounts::default());
    assert_ne!(other, hdr);
    assert_eq!(hdr[..32], other[..32]);
}

#[test]
fn iss_setup_retries_zero_issuer_key() {
    use ark_std::rand::{Error, RngCore};
    use gp_mhac::issuance::iss_keygen;
    use std::io::Read;

    struct Draws<'a>(&'a [u8]);
    impl RngCore for Draws<'_> {
        fn next_u32(&mut self) -> u32 {
            let mut bytes = [0; 4];
            self.fill_bytes(&mut bytes);
            u32::from_le_bytes(bytes)
        }
        fn next_u64(&mut self) -> u64 {
            let mut bytes = [0; 8];
            self.fill_bytes(&mut bytes);
            u64::from_le_bytes(bytes)
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            self.0.read_exact(dest).unwrap();
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    // Three field draws: zero, then two distinct nonzero values for IssSetup and Auth.
    let mut bytes = [0u8; 96];
    bytes[32] = 1;
    bytes[64] = 2;
    let mut expected = Draws(&bytes);
    assert!(Fr::rand(&mut expected).is_zero());
    let second = Fr::rand(&mut expected);
    let third = Fr::rand(&mut expected);
    assert!(!second.is_zero() && !third.is_zero() && second != third);
    let mut draws = Draws(&bytes);
    let params = setup(2, &mut test_rng());
    let keys = iss_keygen(&params, &mut draws);
    assert_eq!((keys.x, keys.auth_sk.0), (second, third));
    assert!(draws.0.is_empty());
}

#[test]
fn cred_iss_requires_the_parameters_bound_to_the_issuer_key() {
    use gp_mhac::issuance::Error;
    let mut rng = test_rng();
    let pp = setup(2, &mut rng);
    let keys = iss_keygen(&pp, &mut rng);
    let unrelated = setup(2, &mut rng);
    let access = compile_access(threshold(1, 1), 1);
    let attrs = [Fr::one(), Fr::zero()];
    reset();
    assert_eq!(
        cred_iss(&unrelated, &keys, &attrs, &[0, 1], &access, &mut rng),
        Err(Error::IssuerParameterMismatch)
    );
    assert_eq!(snapshot(), OpCounts::default());
    let imported = Parameters::from_parts(pp.g1, pp.h.clone(), pp.g2);
    assert!(cred_iss(&imported, &keys, &attrs, &[0, 1], &access, &mut rng).is_ok());
}

#[test]
fn cred_iss_rejects_identity_message_base() {
    use gp_mhac::issuance::Error;
    let mut rng = test_rng();
    let pp = setup(2, &mut rng);
    let params = Parameters::from_parts(pp.g1, vec![-pp.g1, pp.h[1]], pp.g2);
    let keys = iss_keygen(&params, &mut rng);
    let access = compile_access(threshold(1, 1), 1);
    let issue =
        |pid, rng: &mut _| cred_iss(&params, &keys, &[pid, Fr::zero()], &[0, 1], &access, rng);
    assert_eq!(issue(Fr::one(), &mut rng), Err(Error::IdentityMessageBase));
    assert!(issue(Fr::from(2u64), &mut rng).is_ok());
}

#[test]
fn cred_iss_reserves_private_coordinates_and_shifts_business_indices() {
    use ark_std::rand::{rngs::StdRng, RngCore, SeedableRng};
    use gp_mhac::issuance::{cred_iss_attributes, Error};
    use gp_mhac::workload::Business;
    let business = Business::fixture(3, 1, 1);
    let mut rng = StdRng::seed_from_u64(32);
    let mut reference = rng.clone();
    let input = cred_iss_attributes(&business.attrs, &[0], &[2], &mut rng).unwrap();
    let measured = business.gp(&mut reference);
    assert_eq!(input.attrs, measured.attrs);
    assert_eq!(rng.next_u64(), reference.next_u64());
    assert_eq!((input.j_pid, input.j_mask), (0, 1));
    assert_eq!(measured.j_pid, Some(input.j_pid));
    assert!(!input.attrs[input.j_pid].is_zero());
    assert_eq!(&input.attrs[2..], &business.attrs);
    assert_eq!(input.prv, [0, 1, 2]);
    assert_eq!(input.rev, [4]);
    assert!(matches!(
        cred_iss_attributes(&business.attrs, &[3], &[], &mut rng),
        Err(Error::InvalidPrivateSet)
    ));
    for rev in [&[0][..], &[3], &[2, 2]] {
        assert!(matches!(
            cred_iss_attributes(&business.attrs, &[0], rev, &mut rng),
            Err(Error::InvalidDisclosureSet)
        ));
    }
}

fn combinations(n: usize, count: usize) -> Vec<Vec<usize>> {
    fn visit(
        next: usize,
        n: usize,
        remaining: usize,
        current: &mut Vec<usize>,
        output: &mut Vec<Vec<usize>>,
    ) {
        if remaining == 0 {
            output.push(current.clone());
            return;
        }
        for value in next..=n - remaining {
            current.push(value);
            visit(value + 1, n, remaining - 1, current, output);
            current.pop();
        }
    }

    let mut output = Vec::new();
    visit(0, n, count, &mut Vec::new(), &mut output);
    output
}

fn reconstruct(lsss: &Lsss, rows: &[usize], shares: &[Fr]) -> Option<Fr> {
    lsss.recon_coeffs(rows).map(|coefficients| {
        coefficients
            .iter()
            .fold(Fr::zero(), |sum, (row, coefficient)| {
                sum + *coefficient * shares[*row]
            })
    })
}

#[test]
fn threshold_reconstruction_and_count_silence() {
    let mut rng = test_rng();
    let lsss = threshold(3, 5);
    let secret = Fr::rand(&mut rng);
    reset();
    let shares = lsss.share(secret, &mut rng);
    for rows in combinations(5, 3) {
        assert_eq!(reconstruct(&lsss, &rows, &shares), Some(secret));
    }
    for rows in combinations(5, 2) {
        assert_eq!(lsss.recon_coeffs(&rows), None);
    }
    assert_eq!(snapshot(), OpCounts::default());
}

#[test]
fn dnf_reconstruction_sets_and_count_silence() {
    let mut rng = test_rng();
    let lsss = dnf_example();
    let secret = Fr::rand(&mut rng);
    reset();
    let shares = lsss.share(secret, &mut rng);
    for rows in [vec![0, 1], vec![2, 3, 4], vec![0, 1, 2]] {
        assert_eq!(reconstruct(&lsss, &rows, &shares), Some(secret));
    }
    for rows in [vec![0, 2], vec![1, 3, 4]] {
        assert_eq!(lsss.recon_coeffs(&rows), None);
    }
    assert_eq!(snapshot(), OpCounts::default());
}

fn expected_issuance(message_count: usize, private_count: usize, rows: usize) -> OpCounts {
    OpCounts {
        e1: (message_count + 1 + rows * (private_count + 1)) as u64,
        s_sig: rows as u64,
        ..OpCounts::default()
    }
}

fn expected_holder(row_count: usize, private_count: usize) -> OpCounts {
    OpCounts {
        e1: (row_count * (private_count + 1)) as u64,
        v_sig: row_count as u64,
        ..OpCounts::default()
    }
}

fn all_rows(precredentials: &[PreCred]) -> Vec<&gp_mhac::issuance::Row> {
    let mut rows: Vec<_> = precredentials
        .iter()
        .flat_map(|precredential| &precredential.rows)
        .collect();
    rows.sort_unstable_by_key(|row| row.index);
    rows
}

fn assert_reconstructed_signature_exponent(
    params: &Parameters,
    keys: &IssuerKeys,
    attrs: &[Fr],
    lsss: &Lsss,
    authorized_rows: &[usize],
    precredentials: &[PreCred],
) {
    let rows = all_rows(precredentials);
    let e_shares: Vec<_> = rows.iter().map(|row| row.e_share).collect();
    let reconstructed_e =
        reconstruct(lsss, authorized_rows, &e_shares).expect("authorized set reconstructs e");

    // `cred_iss` intentionally does not expose e. The BBS verification equation uniquely
    // checks that the reconstructed scalar is the exponent used for A_sig.
    let mut commitment = params.g1;
    for (base, attribute) in params.h.iter().zip(attrs) {
        commitment += ops::g1_mul(base, attribute);
    }
    let g2_exponent = ops::g2_mul(&params.g2, &reconstructed_e) + keys.x2;
    assert_eq!(
        ops::pair(&precredentials[0].a_sig, &g2_exponent),
        ops::pair(&commitment, &params.g2)
    );
}

#[test]
fn issuance_matrix_counts_verifies_reconstructs_and_sizes() {
    let cases = vec![
        ("threshold-8-1", threshold(3, 5), 8usize, 1usize),
        ("threshold-16-2", threshold(3, 5), 16, 2),
        ("threshold-32-4", threshold(3, 5), 32, 4),
        ("dnf-16-2", dnf_example(), 16, 2),
    ];

    for (name, lsss, message_count, private_count) in cases {
        let mut rng = test_rng();
        let params = setup(message_count, &mut rng);
        reset();
        let keys = iss_keygen(&params, &mut rng);
        assert_eq!(
            snapshot(),
            OpCounts {
                e2: 1,
                h: 1,
                ..OpCounts::default()
            },
            "IssKeyGen count mismatch for {name}"
        );
        let attrs: Vec<_> = (0..message_count).map(|_| Fr::rand(&mut rng)).collect();
        let prv: Vec<_> = (0..private_count).collect();
        let access = compile_access(lsss.clone(), 5);

        reset();
        let precredentials = cred_iss(&params, &keys, &attrs, &prv, &access, &mut rng).unwrap();
        let issuance_counts = snapshot();
        assert_eq!(
            issuance_counts,
            expected_issuance(message_count, private_count, lsss.matrix.len()),
            "Iss count mismatch for {name}"
        );
        assert_eq!(issuance_counts.h, 0, "Iss must not hash for {name}");
        if name == "threshold-16-2" {
            println!("Issuance (m=16, p=2, threshold(3,5)) snapshot: {issuance_counts:?}");
        }

        assert_eq!(precredentials.len(), 5);
        for (holder, precredential) in precredentials.iter().enumerate() {
            reset();
            assert!(holder_verify(
                &params,
                &keys.auth_pk,
                &access,
                holder,
                precredential,
                &prv
            ));
            let holder_counts = snapshot();
            assert_eq!(
                holder_counts,
                expected_holder(precredential.rows.len(), private_count),
                "HolderVerify count mismatch for {name}, holder {holder}"
            );
            if name == "threshold-16-2" && holder == 0 {
                println!("HolderVerify (m=16, p=2, threshold(3,5)) snapshot: {holder_counts:?}");
            }
            assert_eq!(
                precredential.credential_bytes().len(),
                credential_size_bytes(precredential, private_count),
                "credential size mismatch for {name}, holder {holder}"
            );
            assert_eq!(precredential.pub_attrs.len(), message_count - private_count);
        }

        reset();
        let authorized_rows: &[usize] = if name.starts_with("threshold") {
            &[0, 1, 2]
        } else {
            &[2, 3, 4]
        };
        assert_reconstructed_signature_exponent(
            &params,
            &keys,
            &attrs,
            &lsss,
            authorized_rows,
            &precredentials,
        );
    }
}

struct Fixture {
    params: Parameters,
    keys: IssuerKeys,
    access: CompiledAccess,
    prv: Vec<usize>,
    precredentials: Vec<PreCred>,
}

fn fixture() -> Fixture {
    let mut rng = test_rng();
    let params = setup(16, &mut rng);
    let keys = iss_keygen(&params, &mut rng);
    let attrs: Vec<_> = (0..16).map(|_| Fr::rand(&mut rng)).collect();
    let prv = vec![1, 9];
    let access = compile_access(threshold(3, 5), 5);
    let precredentials = cred_iss(&params, &keys, &attrs, &prv, &access, &mut rng).unwrap();
    Fixture {
        params,
        keys,
        access,
        prv,
        precredentials,
    }
}

#[test]
fn rejects_changed_d_factor() {
    let mut fixture = fixture();
    fixture.precredentials[0].rows[0].d_factor += fixture.params.g1;
    assert!(!holder_verify(
        &fixture.params,
        &fixture.keys.auth_pk,
        &fixture.access,
        0,
        &fixture.precredentials[0],
        &fixture.prv
    ));
}

#[test]
fn holder_accepts_exactly_its_assigned_rows_in_any_order() {
    let mut rng = test_rng();
    let params = setup(3, &mut rng);
    let keys = iss_keygen(&params, &mut rng);
    let mut lsss = threshold(2, 3);
    lsss.rho = vec![0, 0, 1];
    let access = compile_access(lsss, 2);
    let prv = [0, 1];
    let shares = cred_iss(&params, &keys, &[Fr::one(); 3], &prv, &access, &mut rng).unwrap();
    let accepts =
        |credential: &PreCred| holder_verify(&params, &keys.auth_pk, &access, 0, credential, &prv);
    assert!(accepts(&shares[0]));
    let mut reordered = shares[0].clone();
    reordered.rows.reverse();
    assert!(accepts(&reordered));
    let mut missing = shares[0].clone();
    missing.rows.pop();
    assert!(!accepts(&missing));
    let mut foreign = shares[0].clone();
    foreign.rows.push(shares[1].rows[0].clone());
    assert!(!accepts(&foreign));
    let mut duplicate = shares[0].clone();
    duplicate.rows[1] = duplicate.rows[0].clone();
    assert!(!accepts(&duplicate));
    assert!(!holder_verify(
        &params,
        &keys.auth_pk,
        &access,
        access.n,
        &shares[0],
        &prv
    ));
}

#[test]
fn rejects_changed_tag() {
    let mut fixture = fixture();
    fixture.precredentials[0].rows[0].tag.response += Fr::one();
    assert!(!holder_verify(
        &fixture.params,
        &fixture.keys.auth_pk,
        &fixture.access,
        0,
        &fixture.precredentials[0],
        &fixture.prv
    ));
}

#[test]
fn rejects_tag_from_another_row() {
    let mut fixture = fixture();
    fixture.precredentials[0].rows[0].tag = fixture.precredentials[1].rows[0].tag.clone();
    assert!(!holder_verify(
        &fixture.params,
        &fixture.keys.auth_pk,
        &fixture.access,
        0,
        &fixture.precredentials[0],
        &fixture.prv
    ));
}

#[test]
fn rejects_changed_e_share() {
    let mut fixture = fixture();
    fixture.precredentials[0].rows[0].e_share += Fr::one();
    assert!(!holder_verify(
        &fixture.params,
        &fixture.keys.auth_pk,
        &fixture.access,
        0,
        &fixture.precredentials[0],
        &fixture.prv
    ));
}

#[test]
fn row_tag_cannot_be_replayed_across_credentials_with_the_same_asid() {
    let mut rng = test_rng();
    let params = setup(8, &mut rng);
    let keys = iss_keygen(&params, &mut rng);
    let access = compile_access(threshold(3, 5), 5);
    let attrs: Vec<_> = (0..8).map(|_| Fr::rand(&mut rng)).collect();
    let prv = vec![0];
    let first = cred_iss(&params, &keys, &attrs, &prv, &access, &mut rng).unwrap();
    let second = cred_iss(&params, &keys, &attrs, &prv, &access, &mut rng).unwrap();
    assert_ne!(first[0].a_sig, second[0].a_sig);
    let row = &first[0].rows[0];
    assert!(!gp_mhac::primitives::auth::verify(
        &keys.auth_pk,
        &row_tag_message(
            &access.asid,
            &second[0].a_sig,
            row.index,
            &row.d_factor,
            &first[0].pub_attrs,
        ),
        &row.tag,
    ));
}
