use ark_bls12_381::Fr;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use gp_mhac::{
    access::compile_access,
    baselines::mhac::{
        issuance::issue,
        presentation::{Fault, Prepared},
    },
    baselines::tz23,
    issuance::iss_setup,
    lsss::threshold,
    presentation::derive_ssid,
    primitives::hash::commit,
};
use sha2::{Digest, Sha256};

#[test]
fn seeded_session_and_proof_encodings() {
    let mut rng = StdRng::seed_from_u64(31337);
    let (parameters, keys) = iss_setup(4, &mut rng);
    let access = compile_access(threshold(2, 3), 3);
    let header = derive_ssid(
        &keys.ipk.header(b"credential context"),
        &access.asid,
        &parameters.h[0],
        &[0, 1],
        &[2],
        &[7; 32],
    );
    let cm = commit(&header, 1, b"public message", [9; 32]);
    let parameters = gp_mhac::baselines::mhac::issuance::setup(4, &mut rng);
    let attrs = [1, 3, 5, 7].map(Fr::from);
    let dealer = issue(&parameters, &attrs, &[0, 3], 2, 3, &mut rng).unwrap();
    let session = Prepared::new(&parameters, &dealer, &[0, 1], &[2]).unwrap();
    let presentation = session
        .present(&header, [7; 32], Fault::None, &mut rng)
        .unwrap()
        .presentation
        .unwrap();
    let single = tz23::setup(4, &mut rng);
    let (secret, verification_key) = tz23::keygen(&single, &mut rng);
    let signature = tz23::sign(&single, &secret, &attrs, &mut rng).unwrap();
    let proof = tz23::pok_prove(
        &single,
        &verification_key,
        &attrs,
        &signature,
        &[2],
        &mut rng,
    )
    .unwrap();
    let mut h = Sha256::new();
    h.update(header);
    h.update(cm);
    h.update(dealer.credentials[0].counted_bytes());
    h.update(presentation.to_bytes());
    h.update(proof.to_bytes());
    assert_eq!(
        format!("{:x}", h.finalize()),
        "334537e64e6628f66992842059473fd55449319f3d0f30558e314d10c6193874"
    );
}
