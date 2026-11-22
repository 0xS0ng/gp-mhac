use ark_bls12_381::Fr;
use ark_ff::{One, Zero};
use ark_std::rand::{rngs::StdRng, SeedableRng};
use gp_mhac::baselines::mhac::{issuance::*, Error};

#[test]
fn parameter_generation_samples_independent_message_bases() {
    let mut rng = StdRng::seed_from_u64(52);
    let first = setup(3, &mut rng);
    let second = setup(3, &mut rng);
    assert!(!first.g1.is_zero() && !first.g2.is_zero());
    assert!(!second.g1.is_zero() && !second.g2.is_zero());
    assert_ne!(first.g1, second.g1);
    assert_ne!(first.g2, second.g2);
    assert!(first.h.iter().zip(&second.h).all(|(a, b)| a != b));
}

#[test]
fn appendix_h_signature_binds_every_input_and_factor_uses_local_shares() {
    let pp = setup(5, &mut StdRng::seed_from_u64(6));
    let attrs: Vec<_> = (1..=5u64).map(Fr::from).collect();
    let prv = [1, 4];
    let d = issue(&pp, &attrs, &prv, 2, 4, &mut StdRng::seed_from_u64(8)).unwrap();
    for c in &d.credentials {
        let cert = &c.certificate;
        let (factor, signature) = (&cert.d, &cert.signature);
        assert_eq!(signature.to_bytes().len(), 80);
        assert_eq!(
            *factor,
            prv.iter()
                .zip(&c.local.prv_shares)
                .fold(-c.local.a_sig * c.local.e_share, |v, (j, s)| v + pp.h[*j]
                    * s)
        );
        let vk = &d.auth_vk;
        let a = &c.local.a_sig;
        let public = &c.public_attrs;
        assert!(verify_factor(&pp, &d.x2, a, public, factor, signature, vk));
        assert!(!verify_factor(
            &pp,
            &(d.x2 + pp.g2),
            a,
            public,
            factor,
            signature,
            vk
        ));
        assert!(!verify_factor(
            &pp,
            &d.x2,
            &(*a + pp.g1),
            public,
            factor,
            signature,
            vk
        ));
        assert!(!verify_factor(
            &pp,
            &d.x2,
            a,
            public,
            &(*factor + pp.g1),
            signature,
            vk
        ));
        let mut h = pp.h.clone();
        h[0] += pp.g1;
        let p = gp_mhac::issuance::Parameters::from_parts(pp.g1, h, pp.g2);
        assert!(!verify_factor(&p, &d.x2, a, public, factor, signature, vk));
        let mut alt = public.clone();
        alt[0].1 += Fr::one();
        assert!(!verify_factor(&pp, &d.x2, a, &alt, factor, signature, vk));
        alt = public.clone();
        alt[0].0 += 1;
        assert!(!verify_factor(&pp, &d.x2, a, &alt, factor, signature, vk));
    }
}

#[test]
fn reserved_coordinate_is_fresh_not_the_callers_input() {
    let pp = setup(4, &mut StdRng::seed_from_u64(6));
    let mut v = vec![Fr::one(); 4];
    let generate = |values: &[Fr], seed: u64| {
        issue(&pp, values, &[0, 3], 2, 5, &mut StdRng::seed_from_u64(seed)).unwrap()
    };
    let d = generate(&v, 15);
    v[3] += Fr::one();
    let e = generate(&v, 15);
    let reconstruct = |out: &Dealer, slot: usize| {
        out.lsss
            .recon_coeffs(&[1, 4])
            .unwrap()
            .iter()
            .fold(Fr::zero(), |a, (i, k)| {
                a + out.credentials[*i].local.prv_shares[slot] * k
            })
    };
    assert_eq!(
        d.credentials[0].counted_bytes(),
        e.credentials[0].counted_bytes()
    );
    assert_eq!(reconstruct(&d, 0), v[0]);
    assert_ne!(reconstruct(&d, 1), reconstruct(&generate(&v, 16), 1));
    assert_eq!(
        issue(&pp, &v, &[0], 2, 5, &mut StdRng::seed_from_u64(0)).unwrap_err(),
        Error::InvalidPrivateOrRevealedSet
    );
}

#[test]
fn counted_storage_serializes_expected_inventory_for_zero_to_four_business_secrets() {
    let n = 6;
    let pp = setup(8, &mut StdRng::seed_from_u64(6));
    let gp_params = gp_mhac::issuance::setup(8, &mut StdRng::seed_from_u64(6));
    let attrs = vec![Fr::one(); 8];
    for k in 0..=4 {
        // Both schemes share k private business attributes; their private coordinate counts include
        // two reserved coordinates for GP-MHAC and one for MHAC. Serialized sizes exclude public metadata.
        use gp_mhac::{
            access::compile_access,
            issuance::{cred_iss, iss_keygen},
            lsss::threshold,
        };
        let mut grng = StdRng::seed_from_u64(25);
        let gp = cred_iss(
            &gp_params,
            &iss_keygen(&gp_params, &mut grng),
            &attrs,
            &(0..k + 2).collect::<Vec<_>>(),
            &compile_access(threshold(3, n), n),
            &mut grng,
        )
        .unwrap();
        assert!(gp
            .iter()
            .all(|c| c.rows.len() == 1 && c.credential_bytes().len() == 272 + 32 * k));
        let mut prv: Vec<_> = (0..k).collect();
        prv.push(7);
        {
            let d = issue(&pp, &attrs, &prv, 3, n, &mut StdRng::seed_from_u64(24)).unwrap();
            let bytes = 240 + 32 * k;
            for c in d.credentials {
                assert_eq!(c.counted_bytes().len(), bytes);
                assert_eq!(c.public_attrs.len(), 7 - k);
            }
        }
    }
}
