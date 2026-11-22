//! GP-MHAC CompileAccess and Recon: public access metadata and reconstruction rows.

use super::lsss::{CompiledLsss, Lsss};
use crate::primitives::hash::hash_bytes;
use ark_bls12_381::Fr;
use ark_ff::{One, Zero};
use ark_serialize::CanonicalSerialize;

const DOMAIN_ASID: &[u8] = b"GP-MHAC-ASID-v1";

/// Canonical access identifier, sharing matrix and holder-to-row assignment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompiledAccess {
    pub asid: [u8; 32],
    pub lsss: CompiledLsss,
    pub target: Vec<Fr>,
    pub row_order: Vec<usize>,
    pub n: usize,
}

/// Local reconstruction witness and its nonzero support for an ordered candidate row set.
#[derive(Clone, Debug)]
pub struct Reconstruction {
    asid: [u8; 32],
    policy: CompiledLsss,
    candidates: Vec<usize>,
    rows: Vec<usize>,
    coefficients: Vec<(usize, Fr)>,
}

impl Reconstruction {
    pub fn coefficients(&self) -> &[(usize, Fr)] {
        &self.coefficients
    }

    /// The ordered nonzero support R_S; only these rows participate in CredPres.
    pub fn rows(&self) -> &[usize] {
        &self.rows
    }

    pub(crate) fn covers(&self, rows: &[usize]) -> bool {
        !rows.is_empty() && (rows == self.rows || rows == self.candidates)
    }

    pub(crate) fn matches(&self, access: &CompiledAccess) -> bool {
        self.asid == access.asid && self.policy.same_policy(&access.lsss)
    }
}

impl CompiledAccess {
    /// Recon derives the nonzero support of a canonical, authorized candidate row set.
    pub fn reconstruct(&self, rows: &[usize]) -> Option<Reconstruction> {
        if !rows.windows(2).all(|pair| pair[0] < pair[1]) {
            return None;
        }
        let coefficients = self.lsss.recon_coeffs(rows)?;
        Some(Reconstruction {
            asid: self.asid,
            policy: self.lsss.clone(),
            candidates: if coefficients.len() == rows.len() {
                Vec::new()
            } else {
                rows.to_vec()
            },
            rows: coefficients.iter().map(|(row, _)| *row).collect(),
            coefficients,
        })
    }
}

fn push_u64(bytes: &mut Vec<u8>, value: usize, label: &str) {
    bytes.extend_from_slice(
        &u64::try_from(value)
            .unwrap_or_else(|_| panic!("{label} does not fit in u64"))
            .to_be_bytes(),
    );
}

fn asid_payload(lsss: &Lsss, target: &[Fr], row_order: &[usize], n: usize) -> Vec<u8> {
    let d = lsss.matrix.len();
    let k = lsss.matrix[0].len();
    let mut bytes = Vec::new();
    push_u64(&mut bytes, n, "holder count");
    push_u64(&mut bytes, d, "row count");
    push_u64(&mut bytes, k, "column count");
    for row in &lsss.matrix {
        for value in row {
            value
                .serialize_compressed(&mut bytes)
                .expect("Vec serialization cannot fail");
        }
    }
    for &holder in &lsss.rho {
        push_u64(&mut bytes, holder, "holder index");
    }
    for value in target {
        value
            .serialize_compressed(&mut bytes)
            .expect("Vec serialization cannot fail");
    }
    for &row in row_order {
        push_u64(&mut bytes, row, "row index");
    }
    bytes
}

/// CompileAccess binds the LSSS, target and row order to an access identifier with H_id.
pub fn compile_access(lsss: Lsss, n: usize) -> CompiledAccess {
    assert!(n > 0, "holder count must be positive");
    assert!(lsss.is_well_formed(), "LSSS must be well formed");
    assert!(
        lsss.rho.iter().all(|&holder| holder < n),
        "row owner must be a valid holder"
    );
    let width = lsss.matrix[0].len();
    let mut target = vec![Fr::zero(); width];
    target[0] = Fr::one();
    let row_order: Vec<_> = (0..lsss.matrix.len()).collect();
    let asid = hash_bytes(DOMAIN_ASID, &asid_payload(&lsss, &target, &row_order, n));
    CompiledAccess {
        asid,
        lsss: CompiledLsss::new(lsss),
        target,
        row_order,
        n,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lsss::threshold;
    use crate::ops::{reset, snapshot, OpCounts};

    #[test]
    fn compilation_is_deterministic_and_counts_one_hash() {
        let lsss = threshold(3, 5);
        reset();
        let first = compile_access(lsss.clone(), 5);
        assert_eq!(
            snapshot(),
            OpCounts {
                h: 1,
                ..OpCounts::default()
            }
        );
        reset();
        let second = compile_access(lsss, 5);
        assert_eq!(first, second);
        assert_eq!(snapshot().h, 1);
    }
}
