use ark_bls12_381::Fr;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use gp_mhac::{
    access::{compile_access, CompiledAccess},
    detect::{
        blame_path, canonicalize, detect, detect_cached, detect_cached_timed, detect_prefix,
        envelopes_from_transcript, AuthenticatedEnvelope, DecodedMessage, DetectOutcome,
    },
    issuance::{cred_iss, iss_setup, IssuerKeys, Parameters, PreCred},
    lsss::threshold,
    presentation::{cred_pres, derive_ssid, Presentation, Transcript},
    primitives::hash::hash_to_g1,
};
use std::collections::BTreeSet;

const CTX: &[u8] = b"committee";
const NONCE: [u8; 32] = [7; 32];
const CANDIDATES: [usize; 3] = [0, 1, 2];
const SUPPORT: [usize; 2] = [0, 1];
const PRV: [usize; 2] = [0, 1];
const REV: [usize; 1] = [3];

struct Session {
    pp: Parameters,
    keys: IssuerKeys,
    access: CompiledAccess,
    shares: Vec<PreCred>,
    proof: Presentation,
    transcript: Transcript,
    envelopes: Vec<AuthenticatedEnvelope>,
}

fn session() -> Session {
    let mut rng = StdRng::seed_from_u64(916);
    let (pp, keys) = iss_setup(4, &mut rng);
    let mut lsss = threshold(2, 4);
    // Row 2 is redundant and is owned by holder 0, the smallest candidate holder.
    lsss.rho = vec![2, 1, 0, 3];
    let access = compile_access(lsss, 4);
    let attrs = [Fr::from(7), Fr::from(11), Fr::from(13), Fr::from(17)];
    let shares = cred_iss(&pp, &keys, &attrs, &PRV, &access, &mut rng).unwrap();
    let (proof, transcript) = cred_pres(
        &pp,
        &keys.ipk,
        &shares,
        &attrs,
        &PRV,
        &access,
        &CANDIDATES,
        &REV,
        CTX,
        NONCE,
        &mut rng,
    )
    .unwrap();
    let envelopes = envelopes_from_transcript(&access, &CANDIDATES, &transcript);
    Session {
        pp,
        keys,
        access,
        shares,
        proof,
        transcript,
        envelopes,
    }
}

fn prefix(s: &Session, envelopes: &[AuthenticatedEnvelope]) -> Option<DetectOutcome> {
    detect_prefix(
        &s.pp,
        &s.keys.ipk,
        &s.shares[1].a_sig,
        &s.access,
        &CANDIDATES,
        envelopes,
        &[(3, Fr::from(17))],
        &s.shares[1].pub_attrs,
        &PRV,
        CTX,
        NONCE,
    )
}

#[test]
fn nonzero_support_determines_slots_primary_session_and_detection() {
    let s = session();
    let t = &s.transcript;
    let w = t.reconstruction().unwrap();
    assert_eq!(w.rows(), SUPPORT);
    assert_eq!(t.active_rows, SUPPORT);
    assert_eq!(t.active_holders, [1, 2]);
    assert_eq!(t.primary, 1);
    assert_eq!(
        t.ssid,
        derive_ssid(
            &s.keys.ipk.header(CTX),
            &s.access.asid,
            &s.shares[1].a_sig,
            &SUPPORT,
            &REV,
            &NONCE
        )
    );
    assert!(s.envelopes.iter().all(|e| e.sender == 1 || e.sender == 2));
    assert!(s.envelopes.iter().any(|e| e.round == 3 && e.sender == 1));
    assert_eq!(prefix(&s, &s.envelopes), None);
    let op = hash_to_g1(b"GP-MHAC-NYM-v1", CTX);
    for rows in [&CANDIDATES[..], &SUPPORT[..]] {
        let outcome = detect_cached(
            &s.pp,
            &s.keys.ipk,
            &s.shares[1].a_sig,
            &op,
            &s.access,
            rows,
            w,
            &s.envelopes,
            t.verified_coin(),
            &[(3, Fr::from(17))],
            &s.shares[1].pub_attrs,
            &PRV,
            0,
            CTX,
            NONCE,
        );
        assert_eq!(outcome, DetectOutcome::Pres(Box::new(s.proof.clone())));
        let uncached = detect(
            &s.pp,
            &s.keys.ipk,
            &s.shares[1].a_sig,
            &op,
            &s.access,
            rows,
            &s.envelopes,
            t.verified_coin(),
            &[(3, Fr::from(17))],
            &s.shares[1].pub_attrs,
            &PRV,
            0,
            CTX,
            NONCE,
        );
        assert_eq!(outcome, uncached);
    }
}

#[test]
fn incorrect_seed_opening_returns_attributed_abort_without_coin() {
    let s = session();
    let mut envs = s.envelopes.clone();
    envs.retain(|e| e.round <= 4);
    let source = envs
        .iter_mut()
        .find(|e| e.sender == 2 && e.round == 4)
        .unwrap();
    let Ok(DecodedMessage::Round4Seed(opening)) = &mut source.payload else {
        panic!("expected seed opening")
    };
    opening.randomness[0] ^= 1;
    assert_eq!(
        prefix(&s, &envs),
        Some(DetectOutcome::Abort(BTreeSet::from([2])))
    );
}

#[test]
fn parameter_mismatch_is_a_caller_error_not_holder_blame() {
    let s = session();
    let t = &s.transcript;
    let pp = Parameters::from_parts(-s.pp.g1, s.pp.h.clone(), s.pp.g2);
    let a_sig = &s.shares[1].a_sig;
    let pub_attrs = &s.shares[1].pub_attrs;
    let revealed = [(3, Fr::from(17))];
    let op = hash_to_g1(b"GP-MHAC-NYM-v1", CTX);
    let (verdict, timing) = detect_cached_timed(
        &pp,
        &s.keys.ipk,
        a_sig,
        &op,
        &s.access,
        &CANDIDATES,
        t.reconstruction().unwrap(),
        &s.envelopes,
        t.verified_coin(),
        &revealed,
        pub_attrs,
        &PRV,
        0,
        CTX,
        NONCE,
    );
    assert_eq!(verdict, DetectOutcome::ParameterMismatch);
    assert_eq!(
        (
            timing.row_auth_ns,
            timing.relations_ns,
            timing.lifting_ns,
            timing.terminal_ns
        ),
        (0, 0, 0, 0)
    );
    // A blocked prefix under the wrong local parameters must not blame any absent sender.
    assert_eq!(
        detect_prefix(
            &pp,
            &s.keys.ipk,
            a_sig,
            &s.access,
            &CANDIDATES,
            &[],
            &revealed,
            pub_attrs,
            &PRV,
            CTX,
            NONCE
        ),
        Some(DetectOutcome::ParameterMismatch)
    );
    let canonical = canonicalize(
        &s.access,
        &SUPPORT,
        &s.envelopes,
        &revealed,
        &PRV,
        s.pp.h.len(),
        &t.ssid,
    )
    .transcript
    .unwrap();
    assert_eq!(
        blame_path(
            &pp,
            &s.keys.ipk,
            a_sig,
            &op,
            &s.access,
            &canonical,
            pub_attrs,
            &PRV,
            0,
            &t.ssid,
            t.verified_coin()
        ),
        DetectOutcome::ParameterMismatch
    );
}

#[test]
fn missing_seed_opening_returns_union_with_completed_prefix_blame() {
    let s = session();
    let mut envs = s.envelopes.clone();
    envs.retain(|e| e.round <= 4 && !(e.round == 4 && e.sender == 2));
    assert_eq!(
        prefix(&s, &envs),
        Some(DetectOutcome::Abort(BTreeSet::from([2])))
    );
    let source = envs
        .iter_mut()
        .find(|e| e.sender == 1 && e.round == 2)
        .unwrap();
    let Ok(DecodedMessage::Round2(opening)) = &mut source.payload else {
        panic!("expected message opening")
    };
    opening.randomness[0] ^= 1;
    assert_eq!(
        prefix(&s, &envs),
        Some(DetectOutcome::Abort(BTreeSet::from([1, 2])))
    );
}
