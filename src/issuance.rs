//! GP-MHAC IssSetup and CredIss: issuer keys, issuance and verification of row credentials.

use super::access::CompiledAccess;
use crate::ops;
use crate::primitives::auth::{self, PublicKey, SecretKey};
use crate::primitives::hash::{hash_bytes, hash_to_g1};
use crate::primitives::sample_generator;
use ark_bls12_381::{Fr, G1Projective, G2Projective};
use ark_ff::{Field, UniformRand, Zero};
use ark_serialize::CanonicalSerialize;
use ark_std::rand::Rng;
use std::ops::Deref;
use std::sync::Arc;

const DOMAIN_GENERATOR: &[u8] = b"GP-MHAC-GENERATOR-v1";
const DOMAIN_ROW_TAG: &[u8] = b"GP-MHAC-ROWTAG-v1";
const DOMAIN_HEADER: &[u8] = b"GP-MHAC-HDR-v1";

/// The group elements in pp, in their public order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupParameters {
    pub g1: G1Projective,
    pub h: Vec<G1Projective>,
    pub g2: G2Projective,
}

/// Immutable public parameters shared by an issuer and its presentation and verification calls.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Parameters(Arc<GroupParameters>);

impl Parameters {
    /// Imports the public generators and ordered attribute bases.
    pub fn from_parts(g1: G1Projective, h: Vec<G1Projective>, g2: G2Projective) -> Self {
        Self(Arc::new(GroupParameters { g1, h, g2 }))
    }
}

impl Deref for Parameters {
    type Target = GroupParameters;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// The public BBS verification point and the public row-authentication key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationPoints {
    pub x2: G2Projective,
    pub auth_pk: PublicKey,
}

/// Issuer public key and the precomputed digest of its public parameters and verification points.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuerPublicKey {
    params: Parameters,
    points: VerificationPoints,
    parameter_key_digest: [u8; 32],
}

impl IssuerPublicKey {
    /// Binds the public parameters and issuer key using compressed BLS12-381 encodings.
    /// Rebuild this binding once when importing a parameter/key pair.
    pub fn from_parts(params: &Parameters, x2: G2Projective, auth_pk: PublicKey) -> Self {
        let mut bytes = Vec::new();
        macro_rules! point {
            ($p:expr) => {
                $p.serialize_compressed(&mut bytes)
                    .expect("Vec serialization cannot fail")
            };
        }
        // The suite fixes the groups, pairing, encodings and hash functions.
        bytes.extend_from_slice(b"BLS12-381/SHA-256/v1");
        point!(params.g1);
        point!(params.g2);
        bytes.extend_from_slice(&(params.h.len() as u64).to_be_bytes());
        for h in &params.h {
            point!(h);
        }
        point!(x2);
        point!(auth_pk.0);
        Self {
            params: params.clone(),
            parameter_key_digest: hash_bytes(DOMAIN_HEADER, &bytes),
            points: VerificationPoints { x2, auth_pk },
        }
    }

    /// Checks that the requested pp is the one used to bind the issuer key.
    /// Cloned parameters share storage; independent imports are compared by value.
    pub fn matches_params(&self, params: &Parameters) -> bool {
        Arc::ptr_eq(&self.params.0, &params.0) || self.params == *params
    }

    /// Encodes hdr=(pp, ipk, ctx) without hashing on the presentation or verification path.
    pub fn header(&self, ctx: &[u8]) -> Vec<u8> {
        let mut hdr = Vec::with_capacity(40 + ctx.len());
        hdr.extend_from_slice(&self.parameter_key_digest);
        hdr.extend_from_slice(&(ctx.len() as u64).to_be_bytes());
        hdr.extend_from_slice(ctx);
        hdr
    }
}

impl Deref for IssuerPublicKey {
    type Target = VerificationPoints;

    fn deref(&self) -> &Self::Target {
        &self.points
    }
}

/// Issuer signing and authentication key material.
#[derive(Clone, Debug)]
pub struct IssuerKeys {
    pub x: Fr,
    pub auth_sk: SecretKey,
    pub ipk: IssuerPublicKey,
}

impl Deref for IssuerKeys {
    type Target = IssuerPublicKey;

    fn deref(&self) -> &Self::Target {
        &self.ipk
    }
}

/// Credential shares, row factor and row tag for one access-matrix row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    pub index: usize,
    pub e_share: Fr,
    /// Private-attribute shares in ascending private-attribute index order.
    pub prv_shares: Vec<Fr>,
    pub d_factor: G1Projective,
    pub tag: auth::Signature,
}

/// Holder's credential rows, shared signature point and indexed public attributes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreCred {
    pub asid: [u8; 32],
    pub a_sig: G1Projective,
    pub pub_attrs: Vec<(usize, Fr)>,
    pub rows: Vec<Row>,
}

/// Credential issuance input does not match the parameters or attribute partition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    IssuerParameterMismatch,
    WrongAttributeCount,
    InvalidPrivateSet,
    InvalidDisclosureSet,
    InvalidLsss,
    IdentityMessageBase,
}

/// IssSetup returns the public parameters and issuer keys for the total attribute count,
/// including the two reserved coordinates.
pub fn iss_setup<R: Rng + ?Sized>(attribute_count: usize, rng: &mut R) -> (Parameters, IssuerKeys) {
    let params = setup(attribute_count, rng);
    let keys = iss_keygen(&params, rng);
    (params, keys)
}

/// Issuer-side inputs to CredIss. Only the indices, not the values at the private
/// coordinates, are public.
pub struct CredIssAttributes {
    /// Full attribute vector, including the issuer's private inputs.
    pub attrs: Vec<Fr>,
    pub prv: Vec<usize>,
    pub rev: Vec<usize>,
    /// Public index of the nonzero pseudonym secret.
    pub j_pid: usize,
    /// Public index of the independent mask.
    pub j_mask: usize,
}

/// Prepare CredIss inputs from non-reserved attributes. Private and revealed lists use
/// zero-based indices into `business`; returned indices refer to the full vector.
pub fn cred_iss_attributes<R: Rng + ?Sized>(
    business: &[Fr],
    private: &[usize],
    revealed: &[usize],
    rng: &mut R,
) -> Result<CredIssAttributes, Error> {
    let prv = canonical_private_set(business.len(), private).ok_or(Error::InvalidPrivateSet)?;
    let rev = canonical_private_set(business.len(), revealed).ok_or(Error::InvalidDisclosureSet)?;
    if rev.iter().any(|j| prv.binary_search(j).is_ok()) {
        return Err(Error::InvalidDisclosureSet);
    }
    let pid = loop {
        let value = Fr::rand(rng);
        if !value.is_zero() {
            break value;
        }
    };
    let j_pid = 0;
    let j_mask = 1;
    let mut attrs = Vec::with_capacity(business.len() + 2);
    attrs.extend([pid, Fr::rand(rng)]);
    attrs.extend_from_slice(business);
    Ok(CredIssAttributes {
        attrs,
        prv: [j_pid, j_mask]
            .into_iter()
            .chain(prv.into_iter().map(|j| j + 2))
            .collect(),
        rev: rev.into_iter().map(|j| j + 2).collect(),
        j_pid,
        j_mask,
    })
}

/// Samples both generators independently and derives the indexed attribute bases with H_msg.
pub fn setup<R: Rng + ?Sized>(attribute_count: usize, rng: &mut R) -> Parameters {
    let h = (0..attribute_count)
        .map(|index| hash_to_g1(DOMAIN_GENERATOR, &(index as u64).to_be_bytes()))
        .collect();
    Parameters::from_parts(sample_generator(rng), h, sample_generator(rng))
}

/// Samples the issuer's signing key and Auth key pair for row tags in IssSetup.
pub fn iss_keygen<R: Rng + ?Sized>(params: &Parameters, rng: &mut R) -> IssuerKeys {
    let x = loop {
        let candidate = Fr::rand(rng);
        if !candidate.is_zero() {
            break candidate;
        }
    };
    let x2 = ops::g2_mul(&params.g2, &x);
    let (auth_sk, auth_pk) = auth::keygen(rng);
    IssuerKeys {
        x,
        auth_sk,
        ipk: IssuerPublicKey::from_parts(params, x2, auth_pk),
    }
}

fn canonical_private_set(attribute_count: usize, prv: &[usize]) -> Option<Vec<usize>> {
    let mut canonical = prv.to_vec();
    canonical.sort_unstable();
    if canonical.iter().any(|&index| index >= attribute_count)
        || canonical.windows(2).any(|pair| pair[0] == pair[1])
    {
        None
    } else {
        Some(canonical)
    }
}

/// Encodes the access identifier, signature point, row index, row factor and public attributes for Auth.
pub fn row_tag_message(
    asid: &[u8; 32],
    a_sig: &G1Projective,
    row_index: usize,
    d_factor: &G1Projective,
    pub_attrs: &[(usize, Fr)],
) -> Vec<u8> {
    debug_assert!(pub_attrs.windows(2).all(|pair| pair[0].0 < pair[1].0));
    let mut message = Vec::with_capacity(DOMAIN_ROW_TAG.len() + 136 + 40 * pub_attrs.len());
    message.extend_from_slice(DOMAIN_ROW_TAG);
    message.extend_from_slice(asid);
    a_sig
        .serialize_compressed(&mut message)
        .expect("Vec serialization cannot fail");
    message.extend_from_slice(
        &u64::try_from(row_index)
            .expect("row index fits in u64")
            .to_be_bytes(),
    );
    d_factor
        .serialize_compressed(&mut message)
        .expect("Vec serialization cannot fail");
    message.extend_from_slice(
        &u64::try_from(pub_attrs.len())
            .expect("attribute count fits in u64")
            .to_be_bytes(),
    );
    for (index, value) in pub_attrs {
        message.extend_from_slice(
            &u64::try_from(*index)
                .expect("attribute index fits in u64")
                .to_be_bytes(),
        );
        value
            .serialize_compressed(&mut message)
            .expect("Vec serialization cannot fail");
    }
    message
}

/// CredIss issues holder shares of a single credential for the compiled access structure.
/// Its attribute vector includes both issuer-sampled reserved coordinates.
pub fn cred_iss<R: Rng + ?Sized>(
    params: &Parameters,
    keys: &IssuerKeys,
    attrs: &[Fr],
    prv: &[usize],
    access: &CompiledAccess,
    rng: &mut R,
) -> Result<Vec<PreCred>, Error> {
    if !keys.ipk.matches_params(params) {
        return Err(Error::IssuerParameterMismatch);
    }
    if attrs.len() != params.h.len() {
        return Err(Error::WrongAttributeCount);
    }
    let prv = canonical_private_set(attrs.len(), prv).ok_or(Error::InvalidPrivateSet)?;
    let lsss = &access.lsss;
    if !lsss.is_well_formed() {
        return Err(Error::InvalidLsss);
    }

    let mut commitment = params.g1;
    for (base, attribute) in params.h.iter().zip(attrs) {
        commitment += ops::g1_mul(base, attribute);
    }
    if commitment.is_zero() {
        return Err(Error::IdentityMessageBase);
    }
    let e = loop {
        let candidate = Fr::rand(rng);
        if !(keys.x + candidate).is_zero() {
            break candidate;
        }
    };
    let inverse = (keys.x + e)
        .inverse()
        .expect("nonzero scalar has an inverse");
    let a_sig = ops::g1_mul(&commitment, &inverse);

    let e_shares = lsss.share(e, rng);
    let private_shares: Vec<Vec<Fr>> = prv
        .iter()
        .map(|&index| lsss.share(attrs[index], rng))
        .collect();
    let public_attributes: Vec<_> = attrs
        .iter()
        .copied()
        .enumerate()
        .filter(|(index, _)| prv.binary_search(index).is_err())
        .collect();

    let mut precredentials: Vec<_> = (0..access.n)
        .map(|_| PreCred {
            asid: access.asid,
            a_sig,
            pub_attrs: public_attributes.clone(),
            rows: Vec::new(),
        })
        .collect();

    for (row_index, &holder) in lsss.rho.iter().enumerate() {
        let prv_shares: Vec<_> = private_shares
            .iter()
            .map(|shares| shares[row_index])
            .collect();
        let mut private_commitment = G1Projective::zero();
        for (&attribute_index, share) in prv.iter().zip(&prv_shares) {
            private_commitment += ops::g1_mul(&params.h[attribute_index], share);
        }
        let d_factor = private_commitment + ops::g1_mul(&a_sig, &(-e_shares[row_index]));
        let tag = auth::sign(
            &keys.auth_sk,
            &row_tag_message(
                &access.asid,
                &a_sig,
                row_index,
                &d_factor,
                &public_attributes,
            ),
            rng,
        );
        precredentials[holder].rows.push(Row {
            index: row_index,
            e_share: e_shares[row_index],
            prv_shares,
            d_factor,
            tag,
        });
    }
    Ok(precredentials)
}

/// Accepts exactly the rows assigned to this holder, each with its authentic tag and row factor.
pub fn holder_verify(
    params: &Parameters,
    auth_pk: &PublicKey,
    access: &CompiledAccess,
    holder: usize,
    precred: &PreCred,
    prv: &[usize],
) -> bool {
    if holder >= access.n {
        return false;
    }
    let mut received: Vec<_> = precred.rows.iter().map(|row| row.index).collect();
    received.sort_unstable();
    let expected = access
        .lsss
        .rho
        .iter()
        .enumerate()
        .filter_map(|(row, &owner)| (owner == holder).then_some(row));
    if received.into_iter().ne(expected) {
        return false;
    }
    let Some(prv) = canonical_private_set(params.h.len(), prv) else {
        return false;
    };
    if precred.asid != access.asid || precred.pub_attrs.windows(2).any(|p| p[0].0 >= p[1].0) {
        return false;
    }
    for row in &precred.rows {
        if row.prv_shares.len() != prv.len()
            || !auth::verify(
                auth_pk,
                &row_tag_message(
                    &precred.asid,
                    &precred.a_sig,
                    row.index,
                    &row.d_factor,
                    &precred.pub_attrs,
                ),
                &row.tag,
            )
        {
            return false;
        }
        let mut private_commitment = G1Projective::zero();
        for (&attribute_index, share) in prv.iter().zip(&row.prv_shares) {
            private_commitment += ops::g1_mul(&params.h[attribute_index], share);
        }
        let expected = private_commitment + ops::g1_mul(&precred.a_sig, &(-row.e_share));
        if row.d_factor != expected {
            return false;
        }
    }
    true
}

/// Size of the cryptographic credential payload, excluding ASID and public attributes.
pub fn credential_size_bytes(precred: &PreCred, p: usize) -> usize {
    let row_count = precred.rows.len();
    (1 + row_count) * 48 + row_count * (p + 1) * 32 + row_count * 80
}

impl PreCred {
    /// Serializes exactly the fields included by [`credential_size_bytes`].
    pub fn credential_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.a_sig
            .serialize_compressed(&mut bytes)
            .expect("Vec serialization cannot fail");
        for row in &self.rows {
            row.d_factor
                .serialize_compressed(&mut bytes)
                .expect("Vec serialization cannot fail");
            row.e_share
                .serialize_compressed(&mut bytes)
                .expect("Vec serialization cannot fail");
            for share in &row.prv_shares {
                share
                    .serialize_compressed(&mut bytes)
                    .expect("Vec serialization cannot fail");
            }
            bytes.extend_from_slice(&row.tag.to_bytes());
        }
        bytes
    }
}
