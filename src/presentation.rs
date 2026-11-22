//! GP-MHAC CredPres (Rounds 1–5), Assemble and VfPres for a committee pseudonym.

use super::access::{CompiledAccess, Reconstruction};
use super::issuance::{IssuerPublicKey, Parameters, PreCred, Row};
use super::lsss::Lsss;
use crate::ops;
use crate::primitives::hash::{
    commit, commit_seed, hash_bytes, hash_to_g1, hash_to_zp, open, open_seed,
};
use ark_bls12_381::{Fr, G1Affine, G1Projective};
use ark_ff::{Field, UniformRand, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::rand::Rng;
use std::collections::BTreeMap;

const DOMAIN_NYM: &[u8] = b"GP-MHAC-NYM-v1";
const DOMAIN_SIG: &[u8] = b"GP-MHAC-SIG-v1";
const DOMAIN_DLEQ: &[u8] = b"GP-MHAC-DLEQ-v1";
const DOMAIN_COIN: &[u8] = b"GP-MHAC-COIN-v1";
const DOMAIN_SSID: &[u8] = b"GP-MHAC-SSID-v1";

/// Authenticated row factor with its row index and row tag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RowBroadcast {
    pub index: usize,
    pub d_factor: G1Projective,
    pub tag: crate::primitives::auth::Signature,
}

/// Holder's advertised rows, announcement commitment, and seed commitment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Round1Message {
    pub holder: usize,
    pub rows: Vec<RowBroadcast>,
    pub commitment: [u8; 32],
    pub seed_commitment: [u8; 32],
}

/// A holder's random seed and opening randomness for Round 4.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeedOpening {
    pub holder: usize,
    pub kappa: [u8; 32],
    pub randomness: [u8; 32],
}

/// A holder's committed group elements and their opening randomness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Round1Opening {
    pub holder: usize,
    pub c_hat: G1Projective,
    pub n: G1Projective,
    pub v: G1Projective,
    pub u_hat: G1Projective,
    pub u_prime: G1Projective,
    pub randomness: [u8; 32],
}

impl Round1Opening {
    fn message_bytes(&self) -> Vec<u8> {
        encode_points(&[&self.c_hat, &self.n, &self.v, &self.u_hat, &self.u_prime])
    }

    /// Explicit commitment verification for consumers such as the detector.
    /// This invokes the commitment primitive and therefore counts one H operation.
    pub fn verify_commitment(&self, message: &Round1Message, ssid: &[u8]) -> bool {
        self.holder == message.holder
            && open(
                &message.commitment,
                ssid,
                self.holder as u64,
                &self.message_bytes(),
                self.randomness,
            )
    }
}

/// Private holder witnesses, masks and openings across CredPres rounds.
#[derive(Clone, Debug)]
pub struct HolderState {
    holder: usize,
    gamma: Fr,
    betas: Vec<(usize, Fr)>,
    e_hat: Fr,
    a_hats: Vec<(usize, Fr)>,
    opening: Round1Opening,
    seed_opening: SeedOpening,
}

impl HolderState {
    /// Returns the holder's Round 2 announcement opening.
    pub fn opening(&self) -> Round1Opening {
        self.opening.clone()
    }

    /// Returns the holder's Round 4 seed opening.
    pub fn seed_opening(&self) -> SeedOpening {
        self.seed_opening.clone()
    }
}

/// Committee-wide sums used for the private commitment and the committee pseudonym for this context.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Round2Public {
    pub c_prv: G1Projective,
    pub nym: G1Projective,
}

/// DLEQ challenge and response for the Primary's lifting proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiftProof {
    pub c: Fr,
    pub z: Fr,
}

/// Primary's public randomized points, lifting proof and announcements.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Round3Message {
    pub a_bar: G1Projective,
    pub b_bar: G1Projective,
    pub d: G1Projective,
    pub v_prime: G1Projective,
    pub lift: LiftProof,
    pub u_i: G1Projective,
    pub u_ii: G1Projective,
    pub u_iii: G1Projective,
}

/// Coin and challenge obtained after checking the active holders' seed openings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedCoin {
    eta: [u8; 32],
    ch: Fr,
}

impl VerifiedCoin {
    pub(crate) fn eta(&self) -> [u8; 32] {
        self.eta
    }

    pub(crate) fn ch(&self) -> Fr {
        self.ch
    }
}

/// Local randomizers and masked attributes retained for the Primary's final response.
#[derive(Clone, Debug)]
pub struct PrimaryState {
    gamma_first_randomizer: Fr,
    gamma_r3: Fr,
    first_randomizer: Fr,
    r3: Fr,
    other_betas: Vec<(usize, Fr)>,
    other_attributes: Vec<(usize, Fr)>,
}

/// Holder's scalar responses for its share of the signature exponent and private attributes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HolderResponse {
    pub holder: usize,
    pub z_e: Fr,
    pub z_prv: Vec<(usize, Fr)>,
}

/// Primary's additional randomizer and hidden public attribute responses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrimaryResponse {
    pub z_first_randomizer: Fr,
    pub z_r3: Fr,
    pub z_other: Vec<(usize, Fr)>,
}

/// Verifier-facing proof containing the committee pseudonym and aggregate responses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Presentation {
    pub a_bar: G1Projective,
    pub b_bar: G1Projective,
    pub d: G1Projective,
    pub nym: G1Projective,
    pub eta: [u8; 32],
    pub ch: Fr,
    pub z_first_randomizer: Fr,
    pub z_r3: Fr,
    pub z_e: Fr,
    /// Responses in ascending `Hid = [m] \ Rev` order.
    pub z_hidden: Vec<Fr>,
}

impl Presentation {
    /// Returns the compressed verifier-facing proof in protocol field order.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(352 + 32 * self.z_hidden.len());
        for point in [&self.a_bar, &self.b_bar, &self.d, &self.nym] {
            point
                .serialize_compressed(&mut bytes)
                .expect("Vec serialization cannot fail");
        }
        bytes.extend_from_slice(&self.eta);
        for scalar in [&self.ch, &self.z_first_randomizer, &self.z_r3, &self.z_e] {
            scalar
                .serialize_compressed(&mut bytes)
                .expect("Vec serialization cannot fail");
        }
        for response in &self.z_hidden {
            response
                .serialize_compressed(&mut bytes)
                .expect("Vec serialization cannot fail");
        }
        bytes
    }

    /// Decodes the canonical proof encoding produced by [`Self::to_bytes`].
    /// All four points must be on the curve and in its prime-order subgroup.
    /// Pass a decoded external proof to [`vf_pres`] to check its response count
    /// and protocol equations; successful decoding alone does not verify it.
    pub fn from_bytes_checked(mut bytes: &[u8]) -> Result<Self, SerializationError> {
        const SCALAR_BYTES: usize = 32;
        const FIXED_BYTES: usize = 4 * 48 + 32 + 4 * SCALAR_BYTES;
        let tail_len = bytes
            .len()
            .checked_sub(FIXED_BYTES)
            .ok_or(SerializationError::InvalidData)?;
        if !tail_len.is_multiple_of(SCALAR_BYTES) {
            return Err(SerializationError::InvalidData);
        }

        fn point(input: &mut &[u8]) -> Result<G1Projective, SerializationError> {
            let (encoded, rest) = input
                .split_first_chunk::<48>()
                .ok_or(SerializationError::InvalidData)?;
            let p = G1Affine::deserialize_compressed(&encoded[..])?;
            // The compressed decoder can accept alternate encodings of infinity.
            let mut canonical = [0u8; 48];
            p.serialize_compressed(&mut canonical[..])?;
            if &canonical != encoded {
                return Err(SerializationError::InvalidData);
            }
            *input = rest;
            Ok(p.into())
        }

        let a_bar = point(&mut bytes)?;
        let b_bar = point(&mut bytes)?;
        let d = point(&mut bytes)?;
        let nym = point(&mut bytes)?;
        let (eta, mut scalars) = bytes
            .split_first_chunk::<32>()
            .ok_or(SerializationError::InvalidData)?;
        let ch = Fr::deserialize_compressed(&mut scalars)?;
        let z_first_randomizer = Fr::deserialize_compressed(&mut scalars)?;
        let z_r3 = Fr::deserialize_compressed(&mut scalars)?;
        let z_e = Fr::deserialize_compressed(&mut scalars)?;
        let mut z_hidden = Vec::new();
        z_hidden
            .try_reserve_exact(tail_len / SCALAR_BYTES)
            .map_err(|_| SerializationError::InvalidData)?;
        for response in scalars.chunks_exact(SCALAR_BYTES) {
            z_hidden.push(Fr::deserialize_compressed(response)?);
        }
        Ok(Self {
            a_bar,
            b_bar,
            d,
            nym,
            eta: *eta,
            ch,
            z_first_randomizer,
            z_r3,
            z_e,
            z_hidden,
        })
    }
}

/// Committee messages and verified challenge from the presentation rounds.
#[derive(Clone, Debug)]
pub struct Transcript {
    pub ssid: Vec<u8>,
    pub active_rows: Vec<usize>,
    pub active_holders: Vec<usize>,
    pub primary: usize,
    pub round1: Vec<Round1Message>,
    pub openings: Vec<Round1Opening>,
    pub round2: Round2Public,
    pub round3: Round3Message,
    pub seed_openings: Vec<SeedOpening>,
    pub holder_responses: Vec<HolderResponse>,
    pub primary_response: PrimaryResponse,
    coin: VerifiedCoin,
    reconstruction: Option<Reconstruction>,
}

impl Transcript {
    /// Borrows the local row witness when a compiled access structure was used for presentation.
    pub fn reconstruction(&self) -> Option<&Reconstruction> {
        self.reconstruction.as_ref()
    }

    /// Borrows the verified challenge associated with this transcript.
    pub fn verified_coin(&self) -> &VerifiedCoin {
        &self.coin
    }
}

/// Concrete transmitted bytes for the five presentation rounds.
pub fn transcript_bytes(transcript: &Transcript, p: usize, h_hid: usize) -> usize {
    transcript_round_bytes(transcript, p, h_hid).iter().sum()
}

/// Serialized payload contributed by each of the five broadcast rounds.
pub fn transcript_round_bytes(transcript: &Transcript, p: usize, h_hid: usize) -> [usize; 5] {
    const G1_BYTES: usize = 48;
    const SCALAR_BYTES: usize = 32;
    const TAG_BYTES: usize = 80;
    const COMMITMENT_BYTES: usize = 32;
    const OPENING_RANDOMNESS_BYTES: usize = 32;

    let active_holders = transcript.active_holders.len();
    let active_rows: usize = transcript
        .round1
        .iter()
        .map(|message| message.rows.len())
        .sum();
    debug_assert_eq!(transcript.round1.len(), active_holders);
    debug_assert_eq!(transcript.openings.len(), active_holders);
    debug_assert_eq!(transcript.seed_openings.len(), active_holders);
    debug_assert_eq!(transcript.holder_responses.len(), active_holders);
    debug_assert_eq!(active_rows, transcript.active_rows.len());
    debug_assert!(transcript
        .round1
        .iter()
        .all(|message| message.commitment.len() == COMMITMENT_BYTES));
    debug_assert!(transcript
        .openings
        .iter()
        .all(|opening| opening.randomness.len() == OPENING_RANDOMNESS_BYTES));
    debug_assert!(transcript
        .holder_responses
        .iter()
        .all(|response| response.z_prv.len() == p));
    debug_assert_eq!(transcript.primary_response.z_other.len(), h_hid - p);

    let round1 = transcript
        .round1
        .iter()
        .map(|message| message.rows.len() * (G1_BYTES + TAG_BYTES) + 2 * COMMITMENT_BYTES)
        .sum::<usize>();
    let round2 = active_holders * (5 * G1_BYTES + OPENING_RANDOMNESS_BYTES);
    let round3 = 7 * G1_BYTES + 2 * SCALAR_BYTES;
    let round4 = active_holders * 2 * SCALAR_BYTES;
    let round5 = (active_holders * (p + 1) + h_hid - p + 2) * SCALAR_BYTES;
    [round1, round2, round3, round4, round5]
}

/// Invalid input partition, committee, round evidence or proof responses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidIssuerParameters,
    WrongAttributeCount,
    InvalidPrivateOrRevealedSet,
    InvalidActiveRows,
    MissingActiveRow,
    InvalidRoundMessages,
    InvalidResponses,
}

fn encode_points(points: &[&G1Projective]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(points.len() * 48);
    for point in points {
        point
            .serialize_compressed(&mut bytes)
            .expect("Vec serialization cannot fail");
    }
    bytes
}

/// Canonically encodes the internal session identifier
/// `(hdr, asid, A_sig, R_S, Rev, nonce)`.
pub fn derive_ssid(
    hdr: &[u8],
    asid: &[u8; 32],
    a_sig: &G1Projective,
    active_rows: &[usize],
    rev: &[usize],
    nonce: &[u8; 32],
) -> Vec<u8> {
    assert!(is_strictly_ascending(active_rows));
    assert!(is_strictly_ascending(rev));
    let mut bytes = Vec::new();
    bytes.extend_from_slice(DOMAIN_SSID);
    bytes.extend_from_slice(&(hdr.len() as u64).to_be_bytes());
    bytes.extend_from_slice(hdr);
    bytes.extend_from_slice(asid);
    a_sig
        .serialize_compressed(&mut bytes)
        .expect("Vec serialization cannot fail");
    bytes.extend_from_slice(&(active_rows.len() as u64).to_be_bytes());
    for &row in active_rows {
        bytes.extend_from_slice(&(row as u64).to_be_bytes());
    }
    bytes.extend_from_slice(&(rev.len() as u64).to_be_bytes());
    for &index in rev {
        bytes.extend_from_slice(&(index as u64).to_be_bytes());
    }
    bytes.extend_from_slice(nonce);
    bytes
}

fn is_strictly_ascending(indices: &[usize]) -> bool {
    indices.windows(2).all(|pair| pair[0] < pair[1])
}

fn validate_sets(
    message_count: usize,
    prv: &[usize],
    rev: &[usize],
) -> Result<(Vec<usize>, Vec<usize>), Error> {
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
    let public: Vec<_> = (0..message_count)
        .filter(|index| prv.binary_search(index).is_err())
        .collect();
    Ok((hidden, public))
}

fn coefficient_for(row: usize, coefficients: &[(usize, Fr)]) -> Fr {
    coefficients
        .iter()
        .find(|(index, _)| *index == row)
        .map(|(_, coefficient)| *coefficient)
        .unwrap_or_else(Fr::zero)
}

fn row_in_precredential(precredential: &PreCred, index: usize) -> Option<&Row> {
    precredential.rows.iter().find(|row| row.index == index)
}

/// Creates the holder's commitments and private state from its row credential; rejects invalid rows or indices.
#[allow(clippy::too_many_arguments)]
pub fn round1_holder<R: Rng + ?Sized>(
    params: &Parameters,
    precredential: &PreCred,
    holder: usize,
    active_rows: &[usize],
    coefficients: &[(usize, Fr)],
    prv: &[usize],
    ctx: &[u8],
    ssid: &[u8],
    rng: &mut R,
) -> Result<(Round1Message, HolderState), Error> {
    let op = hash_to_g1(DOMAIN_NYM, ctx);
    round1_holder_with_op(
        &op,
        params,
        precredential,
        holder,
        active_rows,
        coefficients,
        prv,
        ssid,
        rng,
    )
}

/// Round 1 with the pseudonym base H_nym(ctx) from the caller.
#[allow(clippy::too_many_arguments)]
pub fn round1_holder_cached<R: Rng + ?Sized>(
    op: &G1Projective,
    params: &Parameters,
    precredential: &PreCred,
    holder: usize,
    active_rows: &[usize],
    coefficients: &[(usize, Fr)],
    prv: &[usize],
    ssid: &[u8],
    rng: &mut R,
) -> Result<(Round1Message, HolderState), Error> {
    round1_holder_with_op(
        op,
        params,
        precredential,
        holder,
        active_rows,
        coefficients,
        prv,
        ssid,
        rng,
    )
}

#[allow(clippy::too_many_arguments)]
fn round1_holder_with_op<R: Rng + ?Sized>(
    op: &G1Projective,
    params: &Parameters,
    precredential: &PreCred,
    holder: usize,
    active_rows: &[usize],
    coefficients: &[(usize, Fr)],
    prv: &[usize],
    ssid: &[u8],
    rng: &mut R,
) -> Result<(Round1Message, HolderState), Error> {
    if !is_strictly_ascending(active_rows)
        || prv.is_empty()
        || !is_strictly_ascending(prv)
        || prv.iter().any(|&index| index >= params.h.len())
    {
        return Err(Error::InvalidActiveRows);
    }
    let own_rows: Vec<_> = active_rows
        .iter()
        .filter_map(|&index| row_in_precredential(precredential, index))
        .collect();
    if own_rows.is_empty() || own_rows.iter().any(|row| row.prv_shares.len() != prv.len()) {
        return Err(Error::MissingActiveRow);
    }

    let e_hat = own_rows.iter().fold(Fr::zero(), |sum, row| {
        sum + coefficient_for(row.index, coefficients) * row.e_share
    });
    let a_hats: Vec<_> = prv
        .iter()
        .enumerate()
        .map(|(position, &attribute)| {
            let share = own_rows.iter().fold(Fr::zero(), |sum, row| {
                sum + coefficient_for(row.index, coefficients) * row.prv_shares[position]
            });
            (attribute, share)
        })
        .collect();

    let gamma = Fr::rand(rng);
    let betas: Vec<_> = prv
        .iter()
        .map(|&attribute| (attribute, Fr::rand(rng)))
        .collect();
    let v = ops::g1_mul(&precredential.a_sig, &(-gamma));
    let mut u_hat = G1Projective::zero();
    let mut c_hat = G1Projective::zero();
    for (((attribute, beta), (_, share)), expected_attribute) in betas.iter().zip(&a_hats).zip(prv)
    {
        debug_assert_eq!(attribute, expected_attribute);
        u_hat += ops::g1_mul(&params.h[*attribute], &(-*beta));
        c_hat += ops::g1_mul(&params.h[*attribute], share);
    }
    let pid_hat = a_hats[0].1;
    let n = ops::g1_mul(op, &pid_hat);
    let u_prime = ops::g1_mul(op, &betas[0].1);
    let mut randomness = [0u8; 32];
    rng.fill(&mut randomness);
    let mut kappa = [0u8; 32];
    let mut seed_randomness = [0u8; 32];
    rng.fill(&mut kappa);
    rng.fill(&mut seed_randomness);
    let opening = Round1Opening {
        holder,
        c_hat,
        n,
        v,
        u_hat,
        u_prime,
        randomness,
    };
    let commitment = commit(ssid, holder as u64, &opening.message_bytes(), randomness);
    let seed_commitment = commit_seed(ssid, holder as u64, kappa, seed_randomness);
    let seed_opening = SeedOpening {
        holder,
        kappa,
        randomness: seed_randomness,
    };
    let rows = own_rows
        .iter()
        .map(|row| RowBroadcast {
            index: row.index,
            d_factor: row.d_factor,
            tag: row.tag.clone(),
        })
        .collect();
    Ok((
        Round1Message {
            holder,
            rows,
            commitment,
            seed_commitment,
        },
        HolderState {
            holder,
            gamma,
            betas,
            e_hat,
            a_hats,
            opening,
            seed_opening,
        },
    ))
}

/// Publishes the openings and sums their private commitments and pseudonym contributions in Round 2.
pub fn round2_open(states: &[HolderState]) -> (Vec<Round1Opening>, Round2Public) {
    let openings: Vec<_> = states.iter().map(HolderState::opening).collect();
    let c_prv = openings
        .iter()
        .fold(G1Projective::zero(), |sum, opening| sum + opening.c_hat);
    let nym = openings
        .iter()
        .fold(G1Projective::zero(), |sum, opening| sum + opening.n);
    (openings, Round2Public { c_prv, nym })
}

fn nonzero_scalar<R: Rng + ?Sized>(rng: &mut R) -> Fr {
    loop {
        let value = Fr::rand(rng);
        if !value.is_zero() {
            return value;
        }
    }
}

pub(crate) fn dleq_challenge(
    a_sig: &G1Projective,
    v: &G1Projective,
    a_bar: &G1Projective,
    v_prime: &G1Projective,
    t1: &G1Projective,
    t2: &G1Projective,
) -> Fr {
    hash_to_zp(
        DOMAIN_DLEQ,
        &encode_points(&[a_sig, v, a_bar, v_prime, t1, t2]),
    )
}

#[allow(clippy::too_many_arguments)]
fn signature_challenge(
    hdr: &[u8],
    a_bar: &G1Projective,
    b_bar: &G1Projective,
    d: &G1Projective,
    nym: &G1Projective,
    ctx: &[u8],
    u_i: &G1Projective,
    u_ii: &G1Projective,
    u_iii: &G1Projective,
    revealed: &[(usize, Fr)],
    nonce: &[u8; 32],
    eta: &[u8; 32],
) -> Fr {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(hdr.len() as u64).to_be_bytes());
    bytes.extend_from_slice(hdr);
    bytes.extend_from_slice(&encode_points(&[a_bar, b_bar, d, nym]));
    bytes.extend_from_slice(&(ctx.len() as u64).to_be_bytes());
    bytes.extend_from_slice(ctx);
    bytes.extend_from_slice(&encode_points(&[u_i, u_ii, u_iii]));
    bytes.extend_from_slice(&(revealed.len() as u64).to_be_bytes());
    for (index, value) in revealed {
        bytes.extend_from_slice(&(*index as u64).to_be_bytes());
        value
            .serialize_compressed(&mut bytes)
            .expect("Vec serialization cannot fail");
    }
    bytes.extend_from_slice(nonce);
    bytes.extend_from_slice(eta);
    hash_to_zp(DOMAIN_SIG, &bytes)
}

/// Creates the Primary's randomized announcement and lifting proof; rejects inconsistent round inputs.
#[allow(clippy::too_many_arguments)]
pub fn round3_primary<R: Rng + ?Sized>(
    params: &Parameters,
    a_sig: &G1Projective,
    attrs: &[Fr],
    prv: &[usize],
    rev: &[usize],
    active_rows: &[usize],
    coefficients: &[(usize, Fr)],
    round1: &[Round1Message],
    openings: &[Round1Opening],
    ctx: &[u8],
    ssid: &[u8],
    nonce: [u8; 32],
    rng: &mut R,
) -> Result<(Round3Message, PrimaryState), Error> {
    if attrs.len() != params.h.len() {
        return Err(Error::WrongAttributeCount);
    }
    let (_, public) = validate_sets(attrs.len(), prv, rev)?;
    let mut b_pub = params.g1;
    for &index in &public {
        b_pub += ops::g1_mul(&params.h[index], &attrs[index]);
    }
    round3_primary_with_b_pub(
        &b_pub,
        params,
        a_sig,
        attrs,
        prv,
        rev,
        active_rows,
        coefficients,
        round1,
        openings,
        ctx,
        ssid,
        nonce,
        rng,
    )
}

/// Round 3 with the pseudonym base and public-attribute base precomputed.
/// The Primary uses `b_pub` directly and receives the points derived from `op` in the openings.
#[allow(clippy::too_many_arguments)]
pub fn round3_primary_cached<R: Rng + ?Sized>(
    _op: &G1Projective,
    b_pub: &G1Projective,
    params: &Parameters,
    a_sig: &G1Projective,
    attrs: &[Fr],
    prv: &[usize],
    rev: &[usize],
    active_rows: &[usize],
    coefficients: &[(usize, Fr)],
    round1: &[Round1Message],
    openings: &[Round1Opening],
    ctx: &[u8],
    ssid: &[u8],
    nonce: [u8; 32],
    rng: &mut R,
) -> Result<(Round3Message, PrimaryState), Error> {
    round3_primary_with_b_pub(
        b_pub,
        params,
        a_sig,
        attrs,
        prv,
        rev,
        active_rows,
        coefficients,
        round1,
        openings,
        ctx,
        ssid,
        nonce,
        rng,
    )
}

#[allow(clippy::too_many_arguments)]
fn round3_primary_with_b_pub<R: Rng + ?Sized>(
    b_pub: &G1Projective,
    params: &Parameters,
    a_sig: &G1Projective,
    attrs: &[Fr],
    prv: &[usize],
    rev: &[usize],
    active_rows: &[usize],
    coefficients: &[(usize, Fr)],
    round1: &[Round1Message],
    openings: &[Round1Opening],
    _ctx: &[u8],
    _ssid: &[u8],
    _nonce: [u8; 32],
    rng: &mut R,
) -> Result<(Round3Message, PrimaryState), Error> {
    if attrs.len() != params.h.len() {
        return Err(Error::WrongAttributeCount);
    }
    let (hidden, _) = validate_sets(attrs.len(), prv, rev)?;
    if !is_strictly_ascending(active_rows)
        || active_rows.is_empty()
        || round1.len() != openings.len()
    {
        return Err(Error::InvalidRoundMessages);
    }

    let mut row_broadcasts = Vec::with_capacity(active_rows.len());
    for &active_row in active_rows {
        let Some(row) = round1
            .iter()
            .flat_map(|message| &message.rows)
            .find(|row| row.index == active_row)
        else {
            return Err(Error::MissingActiveRow);
        };
        row_broadcasts.push(row);
    }
    if round1
        .windows(2)
        .any(|pair| pair[0].holder >= pair[1].holder)
        || openings
            .windows(2)
            .any(|pair| pair[0].holder >= pair[1].holder)
        || round1
            .iter()
            .zip(openings)
            .any(|(message, opening)| message.holder != opening.holder)
    {
        return Err(Error::InvalidRoundMessages);
    }

    let mut t = G1Projective::zero();
    for row in row_broadcasts {
        t += ops::g1_mul(&row.d_factor, &coefficient_for(row.index, coefficients));
    }
    let c_prv = openings
        .iter()
        .fold(G1Projective::zero(), |sum, opening| sum + opening.c_hat);
    let v = openings
        .iter()
        .fold(G1Projective::zero(), |sum, opening| sum + opening.v);

    let first_randomizer = nonzero_scalar(rng);
    let r2 = nonzero_scalar(rng);
    let r3 = r2.inverse().expect("r2 is nonzero");
    let rerandomizer_product = first_randomizer * r2;
    let a_bar = ops::g1_mul(a_sig, &rerandomizer_product);
    let d = ops::g1_mul(&(*b_pub + c_prv), &r2);
    let b_bar = ops::g1_mul(&(*b_pub + t), &rerandomizer_product);
    let v_prime = ops::g1_mul(&v, &rerandomizer_product);

    let rho = Fr::rand(rng);
    let t1 = ops::g1_mul(a_sig, &rho);
    let t2 = ops::g1_mul(&v, &rho);
    let c_l = dleq_challenge(a_sig, &v, &a_bar, &v_prime, &t1, &t2);
    let lift = LiftProof {
        c: c_l,
        z: rho + c_l * rerandomizer_product,
    };

    let gamma_first_randomizer = Fr::rand(rng);
    let gamma_r3 = Fr::rand(rng);
    let other_hidden: Vec<_> = hidden
        .iter()
        .copied()
        .filter(|index| prv.binary_search(index).is_err())
        .collect();
    let other_betas: Vec<_> = other_hidden
        .iter()
        .map(|&index| (index, Fr::rand(rng)))
        .collect();
    let u_i = ops::g1_mul(&d, &gamma_first_randomizer) + v_prime;
    let u_iii = openings
        .iter()
        .fold(G1Projective::zero(), |sum, opening| sum + opening.u_prime);
    let mut u_ii = ops::g1_mul(&d, &gamma_r3);
    for opening in openings {
        u_ii += opening.u_hat;
    }
    for &(index, beta) in &other_betas {
        u_ii += ops::g1_mul(&params.h[index], &(-beta));
    }
    Ok((
        Round3Message {
            a_bar,
            b_bar,
            d,
            v_prime,
            lift,
            u_i,
            u_ii,
            u_iii,
        },
        PrimaryState {
            gamma_first_randomizer,
            gamma_r3,
            first_randomizer,
            r3,
            other_betas,
            other_attributes: other_hidden
                .iter()
                .map(|&index| (index, attrs[index]))
                .collect(),
        },
    ))
}

/// Collects the seed openings in holder-state order.
pub fn round4_open(states: &[HolderState]) -> Vec<SeedOpening> {
    states.iter().map(HolderState::seed_opening).collect()
}

/// Round 4 checks one seed opening per active holder, derives the coin with H_coin,
/// and binds the verifier header and coin into the challenge with H_sig.
#[allow(clippy::too_many_arguments)]
pub fn verify_round4_coin(
    ipk: &IssuerPublicKey,
    round1: &[Round1Message],
    seed_openings: &[SeedOpening],
    active_rows: &[usize],
    active_holders: &[usize],
    round2: &Round2Public,
    round3: &Round3Message,
    revealed: &[(usize, Fr)],
    ctx: &[u8],
    ssid: &[u8],
    nonce: [u8; 32],
) -> Result<VerifiedCoin, Error> {
    let mut commitments = BTreeMap::new();
    for message in round1 {
        if commitments
            .insert(message.holder, message.seed_commitment)
            .is_some()
        {
            return Err(Error::InvalidRoundMessages);
        }
    }
    let mut openings = BTreeMap::new();
    for opening in seed_openings {
        if openings.insert(opening.holder, opening).is_some() {
            return Err(Error::InvalidRoundMessages);
        }
    }
    if active_holders.is_empty()
        || active_holders.windows(2).any(|pair| pair[0] >= pair[1])
        || commitments
            .keys()
            .copied()
            .ne(active_holders.iter().copied())
        || commitments.len() != openings.len()
        || commitments.keys().ne(openings.keys())
        || commitments.iter().any(|(&holder, commitment)| {
            let opening = openings[&holder];
            !open_seed(
                commitment,
                ssid,
                holder as u64,
                opening.kappa,
                opening.randomness,
            )
        })
    {
        return Err(Error::InvalidRoundMessages);
    }

    let mut coin_input = Vec::new();
    coin_input.extend_from_slice(&(ssid.len() as u64).to_be_bytes());
    coin_input.extend_from_slice(ssid);
    coin_input.extend_from_slice(&(active_rows.len() as u64).to_be_bytes());
    for &row in active_rows {
        coin_input.extend_from_slice(&(row as u64).to_be_bytes());
    }
    for opening in openings.values() {
        coin_input.extend_from_slice(&(opening.holder as u64).to_be_bytes());
        coin_input.extend_from_slice(&opening.kappa);
        coin_input.extend_from_slice(&opening.randomness);
    }
    let eta = hash_bytes(DOMAIN_COIN, &coin_input);
    let ch = signature_challenge(
        &ipk.header(ctx),
        &round3.a_bar,
        &round3.b_bar,
        &round3.d,
        &round2.nym,
        ctx,
        &round3.u_i,
        &round3.u_ii,
        &round3.u_iii,
        revealed,
        &nonce,
        &eta,
    );
    Ok(VerifiedCoin { eta, ch })
}

/// Forms the holder's responses from its private state and a verified common challenge.
pub fn round5_holder(state: &HolderState, coin: &VerifiedCoin) -> HolderResponse {
    let ch = coin.ch();
    HolderResponse {
        holder: state.holder,
        z_e: state.gamma + ch * state.e_hat,
        z_prv: state
            .betas
            .iter()
            .zip(&state.a_hats)
            .map(|((index, beta), (attribute, share))| {
                debug_assert_eq!(index, attribute);
                (*index, *beta + ch * share)
            })
            .collect(),
    }
}

/// Forms both holder and Primary responses from their private states and the verified challenge.
pub fn round5_primary(
    holder_state: &HolderState,
    primary_state: &PrimaryState,
    coin: &VerifiedCoin,
) -> (HolderResponse, PrimaryResponse) {
    let ch = coin.ch();
    let holder_response = round5_holder(holder_state, coin);
    let z_other = primary_state
        .other_betas
        .iter()
        .zip(&primary_state.other_attributes)
        .map(|((index, beta), (attribute, value))| {
            debug_assert_eq!(index, attribute);
            (*index, *beta + ch * value)
        })
        .collect();
    (
        holder_response,
        PrimaryResponse {
            z_first_randomizer: primary_state.gamma_first_randomizer
                + ch * primary_state.first_randomizer,
            z_r3: primary_state.gamma_r3 + ch * primary_state.r3,
            z_other,
        },
    )
}

/// Assemble aggregates the holders' responses into a presentation and checks their attribute indices.
pub fn assemble(
    round2: &Round2Public,
    round3: &Round3Message,
    coin: &VerifiedCoin,
    holder_responses: &[HolderResponse],
    primary_response: &PrimaryResponse,
    hidden: &[usize],
    prv: &[usize],
) -> Result<Presentation, Error> {
    if prv.is_empty() || !is_strictly_ascending(hidden) || !is_strictly_ascending(prv) {
        return Err(Error::InvalidResponses);
    }
    let z_e = holder_responses
        .iter()
        .fold(Fr::zero(), |sum, response| sum + response.z_e);
    let mut z_hidden = Vec::with_capacity(hidden.len());
    for &index in hidden {
        if prv.binary_search(&index).is_ok() {
            let mut found = false;
            let value = holder_responses.iter().fold(Fr::zero(), |sum, response| {
                if let Some((_, value)) = response
                    .z_prv
                    .iter()
                    .find(|(attribute, _)| *attribute == index)
                {
                    found = true;
                    sum + value
                } else {
                    sum
                }
            });
            if !found {
                return Err(Error::InvalidResponses);
            }
            z_hidden.push(value);
        } else {
            let Some((_, value)) = primary_response
                .z_other
                .iter()
                .find(|(attribute, _)| *attribute == index)
            else {
                return Err(Error::InvalidResponses);
            };
            z_hidden.push(*value);
        }
    }
    Ok(Presentation {
        a_bar: round3.a_bar,
        b_bar: round3.b_bar,
        d: round3.d,
        nym: round2.nym,
        eta: coin.eta(),
        ch: coin.ch(),
        z_first_randomizer: primary_response.z_first_randomizer,
        z_r3: primary_response.z_r3,
        z_e,
        z_hidden,
    })
}

/// CredPres with a raw LSSS matrix. The transcript does not retain a compiled reconstruction witness.
#[allow(clippy::too_many_arguments)]
pub fn cred_pres_with_lsss<R: Rng + ?Sized>(
    params: &Parameters,
    ipk: &IssuerPublicKey,
    precredentials: &[PreCred],
    attrs: &[Fr],
    prv: &[usize],
    lsss: &Lsss,
    active_rows: &[usize],
    rev: &[usize],
    ctx: &[u8],
    nonce: [u8; 32],
    rng: &mut R,
) -> Result<(Presentation, Transcript), Error> {
    cred_pres_inner(
        params,
        ipk,
        precredentials,
        attrs,
        prv,
        lsss,
        active_rows,
        rev,
        ctx,
        nonce,
        rng,
        None,
    )
}

/// CredPres under CompileAccess metadata; retains the reconstruction witness for detection.
#[allow(clippy::too_many_arguments)]
pub fn cred_pres<R: Rng + ?Sized>(
    params: &Parameters,
    ipk: &IssuerPublicKey,
    precredentials: &[PreCred],
    attrs: &[Fr],
    prv: &[usize],
    access: &CompiledAccess,
    active_rows: &[usize],
    rev: &[usize],
    ctx: &[u8],
    nonce: [u8; 32],
    rng: &mut R,
) -> Result<(Presentation, Transcript), Error> {
    let reconstruction = access
        .reconstruct(active_rows)
        .ok_or(Error::InvalidActiveRows)?;
    cred_pres_inner(
        params,
        ipk,
        precredentials,
        attrs,
        prv,
        &access.lsss,
        active_rows,
        rev,
        ctx,
        nonce,
        rng,
        Some(reconstruction),
    )
}

#[allow(clippy::too_many_arguments)]
fn cred_pres_inner<R: Rng + ?Sized>(
    params: &Parameters,
    ipk: &IssuerPublicKey,
    precredentials: &[PreCred],
    attrs: &[Fr],
    prv: &[usize],
    lsss: &Lsss,
    active_rows: &[usize],
    rev: &[usize],
    ctx: &[u8],
    nonce: [u8; 32],
    rng: &mut R,
    reconstruction: Option<Reconstruction>,
) -> Result<(Presentation, Transcript), Error> {
    if !ipk.matches_params(params) {
        return Err(Error::InvalidIssuerParameters);
    }
    if !is_strictly_ascending(active_rows) || active_rows.is_empty() {
        return Err(Error::InvalidActiveRows);
    }
    let fresh;
    let sparse = if let Some(witness) = &reconstruction {
        witness.coefficients()
    } else {
        fresh = lsss
            .recon_coeffs(active_rows)
            .ok_or(Error::InvalidActiveRows)?;
        &fresh
    };
    let fresh_rows;
    let active_rows = if let Some(witness) = &reconstruction {
        witness.rows()
    } else {
        fresh_rows = sparse.iter().map(|(row, _)| *row).collect::<Vec<_>>();
        &fresh_rows
    };
    let mut active_holders: Vec<_> = active_rows.iter().map(|&row| lsss.rho[row]).collect();
    active_holders.sort_unstable();
    active_holders.dedup();
    let primary = *active_holders.first().ok_or(Error::InvalidActiveRows)?;
    let primary_credential = precredentials.get(primary).ok_or(Error::MissingActiveRow)?;
    let a_sig = primary_credential.a_sig;
    let ssid = derive_ssid(
        &ipk.header(ctx),
        &primary_credential.asid,
        &a_sig,
        active_rows,
        rev,
        &nonce,
    );

    let mut messages = Vec::new();
    let mut states = Vec::new();
    for &holder in &active_holders {
        let precredential = precredentials.get(holder).ok_or(Error::MissingActiveRow)?;
        let (message, state) = round1_holder(
            params,
            precredential,
            holder,
            active_rows,
            sparse,
            prv,
            ctx,
            &ssid,
            rng,
        )?;
        messages.push(message);
        states.push(state);
    }
    let (openings, round2) = round2_open(&states);
    let (round3, primary_state) = round3_primary(
        params,
        &a_sig,
        attrs,
        prv,
        rev,
        active_rows,
        sparse,
        &messages,
        &openings,
        ctx,
        &ssid,
        nonce,
        rng,
    )?;
    let seed_openings = round4_open(&states);
    let revealed: Vec<_> = rev.iter().map(|&index| (index, attrs[index])).collect();
    let coin = verify_round4_coin(
        ipk,
        &messages,
        &seed_openings,
        active_rows,
        &active_holders,
        &round2,
        &round3,
        &revealed,
        ctx,
        &ssid,
        nonce,
    )?;
    let mut holder_responses = Vec::new();
    let mut primary_response = None;
    for state in &states {
        if state.holder == primary {
            let (holder_response, extra) = round5_primary(state, &primary_state, &coin);
            holder_responses.push(holder_response);
            primary_response = Some(extra);
        } else {
            holder_responses.push(round5_holder(state, &coin));
        }
    }
    let primary_response = primary_response.ok_or(Error::InvalidResponses)?;
    let (hidden, _) = validate_sets(params.h.len(), prv, rev)?;
    let presentation = assemble(
        &round2,
        &round3,
        &coin,
        &holder_responses,
        &primary_response,
        &hidden,
        prv,
    )?;
    Ok((
        presentation,
        Transcript {
            ssid,
            active_rows: active_rows.to_vec(),
            active_holders,
            primary,
            round1: messages,
            openings,
            round2,
            round3,
            seed_openings,
            holder_responses,
            primary_response,
            coin,
            reconstruction,
        },
    ))
}

/// VfPres checks a presentation using the public coordinate index `j_pid`, not the pseudonym secret.
/// For external proof bytes, first use [`Presentation::from_bytes_checked`].
#[allow(clippy::too_many_arguments)]
pub fn vf_pres(
    params: &Parameters,
    ipk: &IssuerPublicKey,
    presentation: &Presentation,
    revealed: &[(usize, Fr)],
    j_pid: usize,
    ctx: &[u8],
    nonce: [u8; 32],
) -> bool {
    if !ipk.matches_params(params)
        || presentation.a_bar.is_zero()
        || revealed.windows(2).any(|pair| pair[0].0 >= pair[1].0)
        || revealed.iter().any(|(index, _)| *index >= params.h.len())
    {
        return false;
    }
    if ops::pair(&presentation.a_bar, &ipk.x2) != ops::pair(&presentation.b_bar, &params.g2) {
        return false;
    }
    let revealed_indices: Vec<_> = revealed.iter().map(|(index, _)| *index).collect();
    let hidden: Vec<_> = (0..params.h.len())
        .filter(|index| revealed_indices.binary_search(index).is_err())
        .collect();
    if presentation.z_hidden.len() != hidden.len() {
        return false;
    }
    let Some(pid_position) = hidden.iter().position(|index| *index == j_pid) else {
        return false;
    };

    let mut b_rev = params.g1;
    for &(index, value) in revealed {
        b_rev += ops::g1_mul(&params.h[index], &value);
    }
    let op = hash_to_g1(DOMAIN_NYM, ctx);
    let u_i = ops::g1_mul(&presentation.d, &presentation.z_first_randomizer)
        + ops::g1_mul(&presentation.a_bar, &(-presentation.z_e))
        + ops::g1_mul(&presentation.b_bar, &(-presentation.ch));
    let u_iii = ops::g1_mul(&op, &presentation.z_hidden[pid_position])
        + ops::g1_mul(&presentation.nym, &(-presentation.ch));
    let mut u_ii = ops::g1_mul(&presentation.d, &presentation.z_r3);
    for (&index, response) in hidden.iter().zip(&presentation.z_hidden) {
        u_ii += ops::g1_mul(&params.h[index], &(-*response));
    }
    u_ii += ops::g1_mul(&b_rev, &(-presentation.ch));
    presentation.ch
        == signature_challenge(
            &ipk.header(ctx),
            &presentation.a_bar,
            &presentation.b_bar,
            &presentation.d,
            &presentation.nym,
            ctx,
            &u_i,
            &u_ii,
            &u_iii,
            revealed,
            &nonce,
            &presentation.eta,
        )
}
