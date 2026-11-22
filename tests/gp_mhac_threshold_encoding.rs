use ark_bls12_381::Fr;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use gp_mhac::{
    access::compile_access,
    issuance::{cred_iss, iss_keygen, setup},
    lsss::threshold,
    presentation::cred_pres,
};
use sha2::{Digest, Sha256};

#[test]
fn sparse_threshold_presentation_encoding() {
    let access = compile_access(threshold(3, 8), 8);
    let mut rng = StdRng::seed_from_u64(75613);
    let params = setup(8, &mut rng);
    let keys = iss_keygen(&params, &mut rng);
    let attrs: Vec<_> = (11u64..19).map(Fr::from).collect();
    let cred = cred_iss(&params, &keys, &attrs, &[0, 1, 2], &access, &mut rng).unwrap();
    for (rows, digest) in [
        (
            &[1, 4, 7][..],
            "d360cc48ced73d743ea4c6b592296051cb89aecfbb0d8a10a725427f2b2364ad",
        ),
        (
            &[0, 2, 5, 6][..],
            "911bc04f005d85fa268d224b25e540d9a0fbeb312bd186421ade8d62b676f21b",
        ),
    ] {
        let (proof, transcript) = cred_pres(
            &params,
            &keys.ipk,
            &cred,
            &attrs,
            &[0, 1, 2],
            &access,
            rows,
            &[5, 6, 7],
            b"app",
            [0x3d; 32],
            &mut rng,
        )
        .unwrap();
        let mut h = Sha256::new();
        h.update(access.asid);
        h.update(transcript.ssid);
        for msg in transcript.round1 {
            h.update(msg.commitment);
            h.update(msg.seed_commitment);
        }
        h.update(proof.to_bytes());
        assert_eq!(format!("{:x}", h.finalize()), digest);
    }
}
