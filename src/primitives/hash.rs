//! Domain-separated hashes: H_msg and H_nym map to G1; H_sig maps to a scalar;
//! H_id, H_coin and the commitment hash H_cmt return byte strings.

use crate::ops;
use ark_bls12_381::{g1, Fr, G1Projective};
use ark_ec::hashing::{
    curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve,
};
use ark_ff::field_hashers::{DefaultFieldHasher, HashToField};
use ark_ff::Zero;
use sha2::{Digest, Sha256};

type G1Hasher =
    MapToCurveBasedHasher<G1Projective, DefaultFieldHasher<Sha256, 128>, WBMap<g1::Config>>;
const G1_RETRY_DOMAIN: &[u8] = b"GP-MHAC-H2G-RETRY-v1";

/// Domain-separated SHA-256 with protocol-operation accounting.
pub fn hash_bytes(domain_tag: &[u8], bytes: &[u8]) -> [u8; 32] {
    ops::count_h();
    let mut hash = Sha256::new();
    hash.update((domain_tag.len() as u64).to_be_bytes());
    hash.update(domain_tag);
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
    hash.finalize().into()
}

/// Hashes bytes to a BLS12-381 scalar using the given domain.
pub fn hash_to_zp(domain_tag: &[u8], bytes: &[u8]) -> Fr {
    ops::count_h();
    let hasher = <DefaultFieldHasher<Sha256, 128> as HashToField<Fr>>::new(domain_tag);
    hasher.hash_to_field(bytes, 1)[0]
}

/// Maps bytes to a nonidentity G1 point under the caller's domain.
pub fn hash_to_g1(domain_tag: &[u8], bytes: &[u8]) -> G1Projective {
    nonidentity_g1_with(domain_tag, bytes, |dst, input| {
        G1Hasher::new(dst)
            .expect("valid hash-to-curve domain tag")
            .hash(input)
            .expect("hash-to-curve must accept arbitrary bytes")
            .into()
    })
}

fn nonidentity_g1_with(
    domain: &[u8],
    msg: &[u8],
    mut map: impl FnMut(&[u8], &[u8]) -> G1Projective,
) -> G1Projective {
    let mut attempt = |dst: &[u8], input: &[u8]| {
        ops::count_h_g();
        map(dst, input)
    };
    let first = attempt(domain, msg);
    if !first.is_zero() {
        return first;
    }

    // Use a separate retry domain. Frame the first-attempt domain and message,
    // then append a positive little-endian counter.
    let mut input = (domain.len() as u64).to_be_bytes().to_vec();
    input.extend_from_slice(domain);
    input.extend_from_slice(&(msg.len() as u64).to_be_bytes());
    input.extend_from_slice(msg);
    let counter_start = input.len();
    input.push(1);
    loop {
        let point = attempt(G1_RETRY_DOMAIN, &input);
        if !point.is_zero() {
            return point;
        }
        let mut i = counter_start;
        while i < input.len() && input[i] == u8::MAX {
            input[i] = 0;
            i += 1;
        }
        if i == input.len() {
            input.push(1);
        } else {
            input[i] += 1;
        }
    }
}

fn commit_with_domain(
    domain: &[u8],
    ssid: &[u8],
    i: u64,
    msg_bytes: &[u8],
    r: [u8; 32],
) -> [u8; 32] {
    ops::count_h();
    let mut hash = Sha256::new();
    hash.update(b"GP-MHAC-COMMIT-v1");
    hash.update((domain.len() as u64).to_be_bytes());
    hash.update(domain);
    hash.update((ssid.len() as u64).to_be_bytes());
    hash.update(ssid);
    hash.update(i.to_be_bytes());
    hash.update((msg_bytes.len() as u64).to_be_bytes());
    hash.update(msg_bytes);
    hash.update(r);
    hash.finalize().into()
}

/// Commits to a message with H_cmt, binding sender, session and opening randomness.
pub fn commit(ssid: &[u8], i: u64, msg_bytes: &[u8], r: [u8; 32]) -> [u8; 32] {
    commit_with_domain(b"msg", ssid, i, msg_bytes, r)
}

/// Commits to a sender's seed using a domain distinct from ordinary message commitments.
pub fn commit_seed(ssid: &[u8], i: u64, seed: [u8; 32], r: [u8; 32]) -> [u8; 32] {
    commit_with_domain(b"seed", ssid, i, &seed, r)
}

/// Returns whether the session, sender, message and randomness open the commitment.
pub fn open(commitment: &[u8; 32], ssid: &[u8], i: u64, msg_bytes: &[u8], r: [u8; 32]) -> bool {
    commit(ssid, i, msg_bytes, r) == *commitment
}

/// Returns whether the sender's seed and randomness open the seed commitment for this session.
pub fn open_seed(commitment: &[u8; 32], ssid: &[u8], i: u64, seed: [u8; 32], r: [u8; 32]) -> bool {
    commit_seed(ssid, i, seed, r) == *commitment
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::{reset, snapshot};
    use ark_ec::{AffineRepr, Group};
    use ark_serialize::CanonicalSerialize;

    #[test]
    fn nonidentity_first_attempt_preserves_compressed_protocol_points() {
        for (dst, msg) in [
            (&b"GP-MHAC-GENERATOR-v1"[..], &0u64.to_be_bytes()[..]),
            (&b"GP-MHAC-NYM-v1"[..], &b"context"[..]),
            (&b"TZ23-GENERATOR-v1"[..], &0u64.to_be_bytes()[..]),
        ] {
            let expected = G1Hasher::new(dst).unwrap().hash(msg).unwrap();
            assert!(!expected.is_zero());
            let mut bytes = Vec::new();
            expected.serialize_compressed(&mut bytes).unwrap();
            reset();
            let mut actual = Vec::new();
            hash_to_g1(dst, msg)
                .serialize_compressed(&mut actual)
                .unwrap();
            assert_eq!(actual, bytes);
            assert_eq!(snapshot().h_g, 1);
        }
    }

    #[test]
    fn identity_retries_are_framed_and_each_attempt_is_counted() {
        let (domain, msg) = (&b"ab"[..], &b"c"[..]);
        let generator = G1Projective::generator();
        for identities in [1u16, 2, 256] {
            reset();
            let mut n = 0u16;
            let out = nonidentity_g1_with(domain, msg, |dst, input| {
                if n == 0 {
                    assert_eq!((dst, input), (domain, msg));
                } else {
                    assert_eq!(dst, G1_RETRY_DOMAIN);
                    let mut expected = b"\0\0\0\0\0\0\0\x02ab\0\0\0\0\0\0\0\x01c".to_vec();
                    let digits = n.to_le_bytes();
                    expected.extend_from_slice(if n < 256 { &digits[..1] } else { &digits });
                    assert_eq!(input, expected);
                }
                n += 1;
                if n <= identities {
                    G1Projective::zero()
                } else {
                    generator
                }
            });
            assert_eq!(out, generator);
            assert_eq!(n, identities + 1);
            assert_eq!(snapshot().h_g, u64::from(n));
        }
    }

    #[test]
    fn hashes_and_commitments_are_counted() {
        reset();
        let digest = hash_bytes(b"test-bytes", b"message");
        let scalar = hash_to_zp(b"test-zp", b"message");
        let point = hash_to_g1(b"test-g1", b"message");
        let randomness = [7u8; 32];
        let commitment = commit(b"session", 3, b"message", randomness);
        assert!(open(&commitment, b"session", 3, b"message", randomness));
        let seed = [9u8; 32];
        let seed_commitment = commit_seed(b"session", 3, seed, randomness);
        assert!(open_seed(&seed_commitment, b"session", 3, seed, randomness));
        assert_ne!(seed_commitment, commit(b"session", 3, &seed, randomness));
        assert_ne!(
            seed_commitment,
            commit_seed(b"session", 4, seed, randomness)
        );
        assert!(!scalar.is_zero());
        assert!(!point.is_zero());
        assert_ne!(digest, [0u8; 32]);
        assert_eq!(snapshot().h, 8);
        assert_eq!(snapshot().h_g, 1);
    }
}
