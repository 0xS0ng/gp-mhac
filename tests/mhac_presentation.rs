use ark_bls12_381::Fr;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use gp_mhac::baselines::mhac::issuance::setup;
use gp_mhac::baselines::mhac::issuance::{credential_digest, issue, verify_bound_factor};
use gp_mhac::baselines::mhac::presentation::{Fault, Prepared};
use gp_mhac::baselines::mhac::{mhac_verify, Error};

#[test]
fn issuance_inventory_matches_bytes_and_schnorr_binds_the_credential() {
    let params = setup(8, &mut StdRng::seed_from_u64(132));
    let attrs: Vec<_> = (10u64..18).map(Fr::from).collect();
    for business in 0..=4 {
        let mut prv: Vec<_> = (0..business).collect();
        prv.push(7);
        {
            let mut rng = StdRng::seed_from_u64(100);
            let d = issue(&params, &attrs, &prv, 2, 4, &mut rng).unwrap();
            for c in &d.credentials {
                assert_eq!(c.public_attrs, d.public_attrs);
                assert_eq!(c.local.prv_shares.len(), 1 + business);
                let bytes = {
                    let cert = &c.certificate;
                    let (own, signature) = (&cert.d, &cert.signature);
                    assert_eq!(signature.to_bytes().len(), 80);
                    let h = credential_digest(&params, &d.x2, &c.local.a_sig, &c.public_attrs);
                    assert!(verify_bound_factor(&h, own, signature, &d.auth_vk));
                    let mut h_bad = h;
                    h_bad[0] ^= 1;
                    assert!(!verify_bound_factor(&h_bad, own, signature, &d.auth_vk));
                    2 * 48 + (business + 2) * 32 + 80
                };
                assert_eq!(c.counted_bytes().len(), bytes);
            }
        }
    }
}

#[test]
fn reserved_coordinate_is_issuer_sampled() {
    let params = setup(4, &mut StdRng::seed_from_u64(132));
    let attrs = vec![Fr::from(1); 4];
    let mut other = attrs.clone();
    other[3] = Fr::from(2);
    {
        let issue_with = |values: &[Fr], prv: &[usize]| {
            issue(&params, values, prv, 2, 4, &mut StdRng::seed_from_u64(42))
        };
        assert!(matches!(
            issue_with(&attrs, &[0]),
            Err(Error::InvalidPrivateOrRevealedSet)
        ));
        let a = issue_with(&attrs, &[0, 3]).unwrap();
        let b = issue_with(&other, &[0, 3]).unwrap();
        assert!(a.public_attrs.iter().all(|(j, _)| *j != 3));
        for (x, y) in a.credentials.iter().zip(b.credentials.iter()) {
            assert_eq!(
                x.counted_bytes(),
                y.counted_bytes(),
                "issuer must overwrite caller's mask placeholder"
            );
        }
    }
}

#[test]
fn honest_path_verifies_final_proof_without_factor_or_response_checks() {
    let params = setup(8, &mut StdRng::seed_from_u64(132));
    let attrs = vec![Fr::from(7); 8];
    let rev = [3, 4];
    let revealed = [(3, attrs[3]), (4, attrs[4])];
    let active = [1, 3, 5];
    let nonce = [3; 32];
    let ssid = b"mhac/sparse-committee";
    {
        let mut rng = StdRng::seed_from_u64(1001);
        let d = issue(&params, &attrs, &[0, 7], 3, 6, &mut rng).unwrap();
        let prepared = Prepared::new(&params, &d, &active, &rev).unwrap();
        let o = prepared
            .present(ssid, nonce, Fault::None, &mut rng)
            .unwrap();
        assert!(o.blame.is_empty());
        let p = o.presentation.unwrap();
        assert!(mhac_verify(&params, &d.x2, &p, &revealed, ssid, nonce));
        assert!(!mhac_verify(
            &params,
            &d.x2,
            &p,
            &revealed,
            b"another-session",
            nonce
        ));
        assert!(o.stats.opening_checks > 0);

        assert_eq!(o.stats.signature_checks, 0);
        assert_eq!(o.stats.response_checks, 0);
        assert!(o.stats.final_checks > 0);
    }
}

#[test]
fn diagnostic_matrix_charges_actual_authenticated_sender() {
    let params = setup(5, &mut StdRng::seed_from_u64(132));
    let attrs = vec![Fr::from(4); 5];
    let active = [1, 3];
    let rev = [2, 3];
    {
        let mut rng = StdRng::seed_from_u64(71);
        let d = issue(&params, &attrs, &[0, 4], 2, 4, &mut rng).unwrap();
        let prepared = Prepared::new(&params, &d, &active, &rev).unwrap();
        let mut counter = 0u64;
        let mut show = |fault| {
            counter += 1;
            let mut nonce = [0u8; 32];
            nonce[..8].copy_from_slice(&counter.to_be_bytes());
            prepared.present(&counter.to_be_bytes(), nonce, fault, &mut rng)
        };
        let missing = show(Fault::MissingRandomizer).unwrap();
        assert_eq!(missing.blame, vec![active[0]]);
        for sender in active {
            for fault in [
                Fault::MissingCommitment(sender),
                Fault::MissingOpening(sender),
                Fault::MissingResponse(sender),
                Fault::BadOpening(sender),
                Fault::BadResponse(sender),
                Fault::MalformedResponse(sender),
                Fault::DuplicateResponse(sender),
            ] {
                let o = show(fault).unwrap();
                assert!(o.presentation.is_none());
                assert_eq!(o.blame, vec![sender]);
                if matches!(fault, Fault::BadOpening(_)) {
                    assert_eq!(o.stats.response_checks, 0);
                    assert_eq!(o.stats.final_checks, 0);
                }
            }
            {
                for f in [
                    Fault::BadFactor(sender),
                    Fault::BadSignatureAndResponse(sender),
                ] {
                    let o = show(f).unwrap();
                    assert!(o.presentation.is_none());
                    assert_eq!(o.blame, vec![sender]);
                    assert!(o.stats.signature_checks > 0);
                    assert!(o.stats.final_checks > 0);
                }
                let o = show(Fault::BadSignature(sender)).unwrap();

                assert!(o.presentation.is_some());
                assert!(o.blame.is_empty());
                assert_eq!(o.stats.signature_checks, 0);
            }
        }
    }
}

#[test]
fn two_faults_preserve_evidence_and_the_first_aborting_round() {
    let params = setup(5, &mut StdRng::seed_from_u64(132));
    let attrs = vec![Fr::from(8); 5];
    // Holders 1 and 5 send invalid messages; 3 is an honest receiver.
    let active = [1, 3, 5];
    {
        let mut rng = StdRng::seed_from_u64(887);
        let d = issue(&params, &attrs, &[0, 4], 3, 6, &mut rng).unwrap();
        let prepared = Prepared::new(&params, &d, &active, &[2]).unwrap();
        let pair = prepared
            .present(
                b"two-response-senders",
                [20; 32],
                Fault::BadResponsePair(5, 1),
                &mut rng,
            )
            .unwrap();
        assert!(pair.presentation.is_none());
        assert_eq!(pair.blame, vec![1, 5]);

        let mixed = prepared.present(
            b"two-distinct-stages",
            [21; 32],
            Fault::BadSignatureAndOtherResponse(5, 1),
            &mut rng,
        );

        let o = mixed.unwrap();
        assert!(o.presentation.is_none());
        assert_eq!(o.blame, vec![1, 5]);
        let t = active.len();
        assert_eq!(o.stats.signature_checks, t * (t - 1));
        // All peers including an uncertified sender, plus the Primary
        // checking its own full representation.
        assert_eq!(o.stats.response_checks, t * (t - 1) + 1);
        assert_eq!(o.stats.final_checks, t);
    }
}
