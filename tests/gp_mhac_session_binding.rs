use ark_bls12_381::G1Projective;
use ark_ec::CurveGroup;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use gp_mhac::issuance::iss_setup;
use gp_mhac::presentation::derive_ssid;

#[test]
fn internal_ssid_binds_every_session_component() {
    let (params, keys) = iss_setup(2, &mut StdRng::seed_from_u64(812));
    let hdr = &keys.ipk.header(b"public-context");
    let asid = [1u8; 32];
    let a_sig = params.g1;
    let rows = [0usize, 2];
    let rev = [3usize, 5];
    let nonce = [7u8; 32];
    let baseline = derive_ssid(hdr, &asid, &a_sig, &rows, &rev, &nonce);

    let variants = [
        derive_ssid(
            &keys.ipk.header(b"other-context"),
            &asid,
            &a_sig,
            &rows,
            &rev,
            &nonce,
        ),
        derive_ssid(hdr, &[2u8; 32], &a_sig, &rows, &rev, &nonce),
        derive_ssid(hdr, &asid, &(a_sig + params.g1), &rows, &rev, &nonce),
        derive_ssid(hdr, &asid, &a_sig, &[0, 3], &rev, &nonce),
        derive_ssid(hdr, &asid, &a_sig, &rows, &[3, 6], &nonce),
        derive_ssid(hdr, &asid, &a_sig, &rows, &rev, &[8u8; 32]),
    ];

    assert!(variants.iter().all(|candidate| candidate != &baseline));
    assert_eq!(
        baseline,
        derive_ssid(hdr, &asid, &a_sig, &rows, &rev, &nonce)
    );
}

#[test]
fn ssid_point_encoding_is_canonical() {
    let (params, keys) = iss_setup(1, &mut StdRng::seed_from_u64(815));
    let hdr = &keys.ipk.header(b"application");
    let affine_round_trip = G1Projective::from(params.g1.into_affine());
    assert_eq!(
        derive_ssid(hdr, &[0u8; 32], &params.g1, &[0], &[1], &[0u8; 32]),
        derive_ssid(hdr, &[0u8; 32], &affine_round_trip, &[0], &[1], &[0u8; 32])
    );
}
