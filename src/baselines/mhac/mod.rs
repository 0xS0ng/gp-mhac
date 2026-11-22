//! MHAC from *Multi-Holder Anonymous Credentials from BBS Signatures* (CRYPTO 2025).
//! The threshold baseline uses the Appendix H share-size optimization and checks the
//! final presentation before the blame path, in the same order as GP-MHAC.

use crate::issuance::Parameters;
pub mod issuance;
pub mod presentation;
use crate::ops;
use crate::primitives::hash::{commit, hash_to_zp, open};
use ark_bls12_381::{Fr, G1Projective, G2Projective};
use ark_ff::{UniformRand, Zero};
use ark_serialize::CanonicalSerialize;
use ark_std::rand::Rng;
use std::collections::BTreeSet;

const DOMAIN_SIG: &[u8] = b"MHAC-SIG-v1";

/// Signature point and scalar shares held by one threshold credential holder.
#[derive(Clone, Debug)]
pub struct MhacCredential {
    pub holder: usize,
    pub a_sig: G1Projective,
    pub e_share: Fr,
    /// Private-attribute shares in ascending `prv` order.
    pub prv_shares: Vec<Fr>,
}

/// Role-specific randomized bases and any expanded diagnosis terms.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Step2Output {
    pub holder: usize,
    pub a_bar: G1Projective,
    pub b_bar: G1Projective,
    pub c_revealed: G1Projective,
    pub b_tilde: Vec<(usize, G1Projective)>,
}

/// Holder identifier and hash commitment to the announcement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Step3Commitment {
    pub holder: usize,
    pub commitment: [u8; 32],
}

/// Holder identifier and G1 announcement opening.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Step4Opening {
    pub holder: usize,
    pub u: G1Projective,
}

/// Holder's local masks and committed opening for the MHAC presentation.
#[derive(Clone, Debug)]
pub struct RoleState {
    holder: usize,
    gamma_e: Fr,
    gamma_r: Option<Fr>,
    betas: Vec<(usize, Fr)>,
    opening: Step4Opening,
}

impl RoleState {
    /// Returns this holder's opening for its commitment.
    pub fn opening(&self) -> Step4Opening {
        self.opening.clone()
    }
}

/// Step 4: broadcast the committed announcement.
pub fn step4_open(state: &RoleState) -> Step4Opening {
    state.opening()
}

/// Challenge and scalar responses for one active holder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Step6Response {
    pub holder: usize,
    pub ch: Fr,
    pub z_e: Fr,
    pub z_prv: Vec<(usize, Fr)>,
    pub z_r: Option<Fr>,
    pub z_other: Vec<(usize, Fr)>,
}

/// Aggregate MHAC presentation received by the external verifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MhacPresentation {
    pub a_bar: G1Projective,
    pub b_bar: G1Projective,
    pub ch: Fr,
    pub z_r: Fr,
    /// Responses in ascending `Hid = [ell] \ Rev` order.
    pub z_hidden: Vec<Fr>,
    pub z_e: Fr,
}

impl MhacPresentation {
    /// Encodes compressed protocol group elements and scalar fields in order.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(96 + (self.z_hidden.len() + 3) * 32);
        for point in [&self.a_bar, &self.b_bar] {
            point
                .serialize_compressed(&mut bytes)
                .expect("Vec serialization cannot fail");
        }
        self.ch
            .serialize_compressed(&mut bytes)
            .expect("Vec serialization cannot fail");
        self.z_r
            .serialize_compressed(&mut bytes)
            .expect("Vec serialization cannot fail");
        for response in &self.z_hidden {
            response
                .serialize_compressed(&mut bytes)
                .expect("Vec serialization cannot fail");
        }
        self.z_e
            .serialize_compressed(&mut bytes)
            .expect("Vec serialization cannot fail");
        bytes
    }
}

/// Invalid attribute partition, committee, received message or scalar response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    WrongAttributeCount,
    InvalidPrivateOrRevealedSet,
    InvalidActiveSet,
    MissingFactor,
    MissingMessage,
    InvalidResponses,
}

fn is_strictly_ascending(indices: &[usize]) -> bool {
    indices.windows(2).all(|pair| pair[0] < pair[1])
}

fn validate_sets(message_count: usize, prv: &[usize], rev: &[usize]) -> Result<Vec<usize>, Error> {
    if prv.is_empty()
        || !is_strictly_ascending(prv)
        || !is_strictly_ascending(rev)
        || prv.iter().chain(rev).any(|&index| index >= message_count)
        || prv.iter().any(|index| rev.binary_search(index).is_ok())
    {
        return Err(Error::InvalidPrivateOrRevealedSet);
    }
    let hidden: Vec<_> = (0..message_count)
        .filter(|index| rev.binary_search(index).is_err())
        .collect();
    if prv.iter().any(|index| hidden.binary_search(index).is_err()) {
        return Err(Error::InvalidPrivateOrRevealedSet);
    }
    Ok(hidden)
}

fn nonzero_scalar<R: Rng + ?Sized>(rng: &mut R) -> Fr {
    loop {
        let value = Fr::rand(rng);
        if !value.is_zero() {
            return value;
        }
    }
}

impl MhacCredential {
    /// Encodes compressed protocol group elements and scalar fields in order.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.a_sig
            .serialize_compressed(&mut bytes)
            .expect("Vec serialization cannot fail");
        self.e_share
            .serialize_compressed(&mut bytes)
            .expect("Vec serialization cannot fail");
        for share in &self.prv_shares {
            share
                .serialize_compressed(&mut bytes)
                .expect("Vec serialization cannot fail");
        }
        bytes
    }
}

/// Step 1: the Primary samples and broadcasts a nonzero rerandomizer.
pub fn step1_primary<R: Rng + ?Sized>(rng: &mut R) -> Fr {
    nonzero_scalar(rng)
}

fn coefficient_for(holder: usize, coefficients: &[(usize, Fr)]) -> Fr {
    coefficients
        .iter()
        .find(|(index, _)| *index == holder)
        .map(|(_, coefficient)| *coefficient)
        .unwrap_or_else(Fr::zero)
}

fn opening_bytes(u: &G1Projective, nonce: &[u8; 32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(80);
    u.serialize_compressed(&mut bytes)
        .expect("Vec serialization cannot fail");
    bytes.extend_from_slice(nonce);
    bytes
}

/// Step 3: form the role-specific announcement and commit to it.
#[allow(clippy::too_many_arguments)]
pub fn step3_commit<R: Rng + ?Sized>(
    params: &Parameters,
    credential: &MhacCredential,
    step2: &Step2Output,
    prv: &[usize],
    rev: &[usize],
    primary: usize,
    ssid: &[u8],
    nonce: [u8; 32],
    rng: &mut R,
) -> Result<(Step3Commitment, RoleState), Error> {
    let hidden = validate_sets(params.h.len(), prv, rev)?;
    let gamma_e = Fr::rand(rng);
    let mut gamma_r = None;
    let mut betas = Vec::new();
    let mut u = G1Projective::zero();
    if credential.holder == primary {
        let sampled_gamma_r = Fr::rand(rng);
        gamma_r = Some(sampled_gamma_r);
        u += ops::g1_mul(&step2.c_revealed, &sampled_gamma_r);
        for &attribute in &hidden {
            let beta = Fr::rand(rng);
            betas.push((attribute, beta));
            u += ops::g1_mul(&params.h[attribute], &beta);
        }
        u += ops::g1_mul(&step2.a_bar, &gamma_e);
    } else {
        for &attribute in prv {
            let beta = Fr::rand(rng);
            betas.push((attribute, beta));
            u += ops::g1_mul(&params.h[attribute], &beta);
        }
        u += ops::g1_mul(&step2.a_bar, &gamma_e);
    }
    let commitment = commit(
        ssid,
        credential.holder as u64,
        &opening_bytes(&u, &nonce),
        [0u8; 32],
    );
    let opening = Step4Opening {
        holder: credential.holder,
        u,
    };
    Ok((
        Step3Commitment {
            holder: credential.holder,
            commitment,
        },
        RoleState {
            holder: credential.holder,
            gamma_e,
            gamma_r,
            betas,
            opening,
        },
    ))
}

/// Step 5: check the commitment of every other active holder.
pub fn step5_check_commitments(
    checker: usize,
    active: &[usize],
    commitments: &[Step3Commitment],
    openings: &[Step4Opening],
    ssid: &[u8],
    nonce: [u8; 32],
) -> BTreeSet<usize> {
    let mut blame = BTreeSet::new();
    for &holder in active {
        if holder == checker {
            continue;
        }
        let commitment = commitments.iter().find(|item| item.holder == holder);
        let opening = openings.iter().find(|item| item.holder == holder);
        let valid = match (commitment, opening) {
            (Some(commitment), Some(opening)) => open(
                &commitment.commitment,
                ssid,
                holder as u64,
                &opening_bytes(&opening.u, &nonce),
                [0u8; 32],
            ),
            _ => false,
        };
        if !valid {
            blame.insert(holder);
        }
    }
    blame
}

fn signature_challenge(
    ssid: &[u8],
    nonce: &[u8; 32],
    u: &G1Projective,
    a_bar: &G1Projective,
    b_bar: &G1Projective,
    revealed: &[(usize, Fr)],
) -> Fr {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(ssid.len() as u64).to_be_bytes());
    bytes.extend_from_slice(ssid);
    bytes.extend_from_slice(nonce);
    for point in [u, a_bar, b_bar] {
        point
            .serialize_compressed(&mut bytes)
            .expect("Vec serialization cannot fail");
    }
    bytes.extend_from_slice(&(revealed.len() as u64).to_be_bytes());
    for (index, value) in revealed {
        bytes.extend_from_slice(&(*index as u64).to_be_bytes());
        value
            .serialize_compressed(&mut bytes)
            .expect("Vec serialization cannot fail");
    }
    hash_to_zp(DOMAIN_SIG, &bytes)
}

/// Step 6 derives the challenge from the aggregate opening and forms the holder's scalar responses.
#[allow(clippy::too_many_arguments)]
pub fn step6_respond(
    credential: &MhacCredential,
    state: &RoleState,
    step2: &Step2Output,
    attrs: &[Fr],
    prv: &[usize],
    coefficients: &[(usize, Fr)],
    primary: usize,
    r: Fr,
    openings: &[Step4Opening],
    revealed: &[(usize, Fr)],
    ssid: &[u8],
    nonce: [u8; 32],
) -> Result<Step6Response, Error> {
    if state.holder != credential.holder {
        return Err(Error::MissingMessage);
    }
    let u = openings
        .iter()
        .fold(G1Projective::zero(), |sum, opening| sum + opening.u);
    let ch = signature_challenge(ssid, &nonce, &u, &step2.a_bar, &step2.b_bar, revealed);
    let lambda = coefficient_for(credential.holder, coefficients);
    let z_e = state.gamma_e - ch * lambda * credential.e_share;
    let mut z_prv = Vec::with_capacity(prv.len());
    for (position, &attribute) in prv.iter().enumerate() {
        let beta = state
            .betas
            .iter()
            .find(|(index, _)| *index == attribute)
            .map(|(_, beta)| *beta)
            .ok_or(Error::MissingMessage)?;
        z_prv.push((
            attribute,
            beta + ch * r * lambda * credential.prv_shares[position],
        ));
    }
    let (z_r, z_other) = if credential.holder == primary {
        let gamma_r = state.gamma_r.ok_or(Error::MissingMessage)?;
        let z_other = state
            .betas
            .iter()
            .filter(|(attribute, _)| prv.binary_search(attribute).is_err())
            .map(|(attribute, beta)| (*attribute, *beta + ch * r * attrs[*attribute]))
            .collect();
        (Some(gamma_r + ch * r), z_other)
    } else {
        (None, Vec::new())
    };
    Ok(Step6Response {
        holder: credential.holder,
        ch,
        z_e,
        z_prv,
        z_r,
        z_other,
    })
}

fn b_tilde_for(step2: &Step2Output, holder: usize) -> Option<G1Projective> {
    step2
        .b_tilde
        .iter()
        .find(|(index, _)| *index == holder)
        .map(|(_, value)| *value)
}

/// Step 7 detection window for a non-Primary checker.
#[allow(clippy::too_many_arguments)]
pub fn step7_check_responses(
    checker: usize,
    params: &Parameters,
    active: &[usize],
    primary: usize,
    prv: &[usize],
    rev: &[usize],
    step2: &Step2Output,
    openings: &[Step4Opening],
    responses: &[Step6Response],
) -> BTreeSet<usize> {
    let hidden = validate_sets(params.h.len(), prv, rev).unwrap_or_default();
    let mut blame = BTreeSet::new();

    let primary_opening = openings.iter().find(|item| item.holder == primary);
    let primary_response = responses.iter().find(|item| item.holder == primary);
    let primary_b_tilde = b_tilde_for(step2, primary);
    let primary_valid = match (primary_opening, primary_response, primary_b_tilde) {
        (Some(opening), Some(response), Some(b_tilde)) => {
            let lhs = opening.u + ops::g1_mul(&b_tilde, &response.ch);
            let mut complete = true;
            let z_r = response.z_r.unwrap_or_else(|| {
                complete = false;
                Fr::zero()
            });
            let mut rhs = ops::g1_mul(&step2.c_revealed, &z_r);
            for &attribute in &hidden {
                let response_value = if prv.binary_search(&attribute).is_ok() {
                    response
                        .z_prv
                        .iter()
                        .find(|(index, _)| *index == attribute)
                        .map(|(_, value)| *value)
                } else {
                    response
                        .z_other
                        .iter()
                        .find(|(index, _)| *index == attribute)
                        .map(|(_, value)| *value)
                };
                if let Some(value) = response_value {
                    rhs += ops::g1_mul(&params.h[attribute], &value);
                } else {
                    complete = false;
                    rhs += ops::g1_mul(&params.h[attribute], &Fr::zero());
                }
            }
            rhs += ops::g1_mul(&step2.a_bar, &response.z_e);
            complete && lhs == rhs
        }
        _ => false,
    };
    if !primary_valid {
        blame.insert(primary);
    }

    for &holder in active {
        if holder == primary || holder == checker {
            continue;
        }
        let opening = openings.iter().find(|item| item.holder == holder);
        let response = responses.iter().find(|item| item.holder == holder);
        let b_tilde = b_tilde_for(step2, holder);
        let valid = match (opening, response, b_tilde) {
            (Some(opening), Some(response), Some(b_tilde)) => {
                let lhs = opening.u + ops::g1_mul(&b_tilde, &response.ch);
                let mut rhs = G1Projective::zero();
                let mut complete = response.z_prv.len() == prv.len();
                for &attribute in prv {
                    if let Some((_, value)) =
                        response.z_prv.iter().find(|(index, _)| *index == attribute)
                    {
                        rhs += ops::g1_mul(&params.h[attribute], value);
                    } else {
                        complete = false;
                        rhs += ops::g1_mul(&params.h[attribute], &Fr::zero());
                    }
                }
                rhs += ops::g1_mul(&step2.a_bar, &response.z_e);
                complete && lhs == rhs
            }
            _ => false,
        };
        if !valid {
            blame.insert(holder);
        }
    }
    blame
}

/// Step 8 response aggregation.
pub fn assemble(
    step2: &Step2Output,
    responses: &[Step6Response],
    hidden: &[usize],
    prv: &[usize],
    primary: usize,
) -> Result<MhacPresentation, Error> {
    let primary_response = responses
        .iter()
        .find(|response| response.holder == primary)
        .ok_or(Error::MissingMessage)?;
    let ch = primary_response.ch;
    if responses.iter().any(|response| response.ch != ch) {
        return Err(Error::InvalidResponses);
    }
    let z_e = responses
        .iter()
        .fold(Fr::zero(), |sum, response| sum + response.z_e);
    let mut z_hidden = Vec::with_capacity(hidden.len());
    for &attribute in hidden {
        if prv.binary_search(&attribute).is_ok() {
            let mut found = 0;
            let aggregate = responses.iter().fold(Fr::zero(), |sum, response| {
                if let Some((_, value)) =
                    response.z_prv.iter().find(|(index, _)| *index == attribute)
                {
                    found += 1;
                    sum + value
                } else {
                    sum
                }
            });
            if found != responses.len() {
                return Err(Error::InvalidResponses);
            }
            z_hidden.push(aggregate);
        } else {
            let value = primary_response
                .z_other
                .iter()
                .find(|(index, _)| *index == attribute)
                .map(|(_, value)| *value)
                .ok_or(Error::InvalidResponses)?;
            z_hidden.push(value);
        }
    }
    Ok(MhacPresentation {
        a_bar: step2.a_bar,
        b_bar: step2.b_bar,
        ch,
        z_r: primary_response.z_r.ok_or(Error::InvalidResponses)?,
        z_hidden,
        z_e,
    })
}

/// Checks the presentation against the issuer key, disclosed attributes, session identifier and nonce.
pub fn mhac_verify(
    params: &Parameters,
    x2: &G2Projective,
    presentation: &MhacPresentation,
    revealed: &[(usize, Fr)],
    ssid: &[u8],
    nonce: [u8; 32],
) -> bool {
    if presentation.a_bar.is_zero()
        || revealed.windows(2).any(|pair| pair[0].0 >= pair[1].0)
        || revealed.iter().any(|(index, _)| *index >= params.h.len())
    {
        return false;
    }
    let revealed_indices: Vec<_> = revealed.iter().map(|(index, _)| *index).collect();
    let hidden: Vec<_> = (0..params.h.len())
        .filter(|index| revealed_indices.binary_search(index).is_err())
        .collect();
    if hidden.len() != presentation.z_hidden.len() {
        return false;
    }
    let mut c_revealed = params.g1;
    for &(index, value) in revealed {
        c_revealed += ops::g1_mul(&params.h[index], &value);
    }
    let mut u = ops::g1_mul(&presentation.b_bar, &(-presentation.ch))
        + ops::g1_mul(&c_revealed, &presentation.z_r);
    for (&index, response) in hidden.iter().zip(&presentation.z_hidden) {
        u += ops::g1_mul(&params.h[index], response);
    }
    u += ops::g1_mul(&presentation.a_bar, &presentation.z_e);
    if presentation.ch
        != signature_challenge(
            ssid,
            &nonce,
            &u,
            &presentation.a_bar,
            &presentation.b_bar,
            revealed,
        )
    {
        return false;
    }
    ops::pair(&presentation.a_bar, x2) == ops::pair(&presentation.b_bar, &params.g2)
}
