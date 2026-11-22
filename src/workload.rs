//! Credential attribute partitions for the benchmark workloads.
use ark_bls12_381::Fr;
use ark_ff::{UniformRand, Zero};
use ark_std::rand::{rngs::StdRng, Rng, SeedableRng};

/// Seed for public benchmark committee draws (not for cryptographic secrets).
pub const COMMITTEE_SEED: u64 = 0x4750_4d48_4143_2026;

fn draw_rng(domain: u64, size: u64, round: usize) -> StdRng {
    let mut seed = [0; 32];
    for (dst, word) in seed
        .chunks_exact_mut(8)
        .zip([COMMITTEE_SEED, domain, size, round as u64])
    {
        dst.copy_from_slice(&word.to_le_bytes());
    }
    StdRng::from_seed(seed)
}

/// Draws a uniform subset without replacement, returned in holder order.
pub fn draw_threshold(n: usize, t: usize, round: usize) -> Vec<usize> {
    assert!(t > 0 && t <= n);
    let mut rng = draw_rng(t as u64, n as u64, round);
    let mut ids = ark_std::rand::seq::index::sample(&mut rng, n, t).into_vec();
    ids.sort_unstable();
    ids
}

/// Selects one of the equally eligible alternatives of an access structure.
pub fn draw_index(choices: usize, round: usize, domain: u64) -> usize {
    assert!(choices > 0);
    draw_rng(domain | (1 << 63), choices as u64, round).gen_range(0..choices)
}

/// Business attribute values and disclosure counts shared across schemes.
pub struct Business {
    pub attrs: Vec<Fr>,
    pub private: usize,
    pub revealed: usize,
}
/// Scheme-specific attribute vector, private and revealed indices, and optional pseudonym-secret index.
pub struct Workload {
    pub attrs: Vec<Fr>,
    pub prv: Vec<usize>,
    pub rev: Vec<usize>,
    pub j_pid: Option<usize>,
}
impl Business {
    /// Creates a reproducible business vector; private and revealed counts must fit within its length.
    pub fn fixture(count: usize, private: usize, revealed: usize) -> Self {
        assert!(private + revealed <= count);
        // Independent of the scheme, committee, visibility partition, and run.
        let mut rng = StdRng::seed_from_u64(74_003_094_974_976 + count as u64);
        Self {
            attrs: (0..count).map(|_| Fr::rand(&mut rng)).collect(),
            private,
            revealed,
        }
    }
    fn disclosed(&self, offset: usize) -> Vec<usize> {
        (self.attrs.len() - self.revealed..self.attrs.len())
            .map(|i| i + offset)
            .collect()
    }
    /// Adds the GP-MHAC reserved attributes to the business data and samples a fresh nonzero pseudonym secret.
    pub fn gp<R: Rng + ?Sized>(&self, rng: &mut R) -> Workload {
        let pid = loop {
            let v = Fr::rand(rng);
            if !v.is_zero() {
                break v;
            }
        };
        let mut attrs = vec![pid, Fr::rand(rng)];
        attrs.extend_from_slice(&self.attrs);
        Workload {
            attrs,
            prv: (0..2 + self.private).collect(),
            rev: self.disclosed(2),
            j_pid: Some(0),
        }
    }
    /// Appends the reserved issuer-sampled MHAC coordinate and returns the resulting partition.
    pub fn mhac(&self) -> Workload {
        let mut attrs = self.attrs.clone();
        let mut prv: Vec<_> = (0..self.private).collect();
        prv.push(attrs.len());
        attrs.push(Fr::zero()); // placeholder; the MHAC issuer samples this coordinate
        Workload {
            attrs,
            prv,
            rev: self.disclosed(0),
            j_pid: None,
        }
    }
    /// Returns the same business values and revealed indices for the single-holder TZ23 reference.
    pub fn tz(&self) -> Workload {
        Workload {
            attrs: self.attrs.clone(),
            prv: vec![],
            rev: self.disclosed(0),
            j_pid: None,
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn committee_schedule_is_shared_sorted_and_not_a_prefix() {
        for n in [6, 10, 20, 40, 70, 100] {
            let draws: Vec<_> = (0..110).map(|r| draw_threshold(n, n / 2, r)).collect();
            assert_eq!(
                draws,
                (0..110)
                    .map(|r| draw_threshold(n, n / 2, r))
                    .collect::<Vec<_>>()
            );
            assert!(draws.iter().all(|s| s.len() == n / 2
                && s.iter().all(|&i| i < n)
                && s.windows(2).all(|w| w[0] < w[1])));
            assert!(draws.iter().any(|s| s[0] != 0));
            assert!((0..n).all(|i| draws.iter().any(|s| s.contains(&i))));
        }
    }
    #[test]
    fn same_business_values_and_disclosures_do_not_consume_reserved_slots() {
        for p in [2, 4] {
            let biz = Business::fixture(14, p, 8);
            let g = biz.gp(&mut StdRng::seed_from_u64(9));
            let m = biz.mhac();
            let z = biz.tz();
            assert_eq!(&g.attrs[2..], &m.attrs[..14]);
            assert_eq!(z.attrs, m.attrs[..14]);
            assert!(!g.attrs[g.j_pid.unwrap()].is_zero());
            assert_eq!(m.prv.last(), Some(&14));
            assert_eq!(
                (
                    g.attrs.len(),
                    g.prv.len(),
                    m.attrs.len(),
                    m.prv.len(),
                    z.attrs.len()
                ),
                (16, p + 2, 15, p + 1, 14)
            );
            for w in [&g, &m, &z] {
                assert_eq!(w.rev.len(), 8);
                assert!(w.prv.iter().all(|i| !w.rev.contains(i)));
                assert!(w
                    .rev
                    .iter()
                    .map(|&i| w.attrs[i])
                    .eq(z.attrs[6..].iter().copied()));
            }
        }
    }
}
