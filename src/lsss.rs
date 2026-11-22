//! Linear secret sharing for GP-MHAC CompileAccess and Recon over the BLS12-381 scalar field.
//! Recon uses Lagrange interpolation for threshold policies and elimination for general matrices.

use ark_bls12_381::Fr;
use ark_ff::{Field, One, UniformRand, Zero};
use ark_std::rand::Rng;
use std::{ops::Deref, sync::Arc};

/// Linear secret-sharing matrix and row-to-holder assignment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lsss {
    pub matrix: Vec<Vec<Fr>>,
    /// Maps each matrix row to its holder index.
    pub rho: Vec<usize>,
}

/// An immutable sharing matrix with its reconstruction method selected at compilation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompiledLsss {
    matrix_source: Arc<Lsss>,
    threshold_width: Option<usize>,
}

impl CompiledLsss {
    pub(crate) fn new(lsss: Lsss) -> Self {
        Self {
            threshold_width: lsss.vandermonde_width(),
            matrix_source: Arc::new(lsss),
        }
    }

    pub(crate) fn same_policy(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.matrix_source, &other.matrix_source) || self == other
    }

    /// Reconstructs using the ordered rows and the compiled sharing matrix.
    pub fn recon_coeffs(&self, rows: &[usize]) -> Option<Vec<(usize, Fr)>> {
        match self.threshold_width {
            Some(t) => lagrange(t, self.matrix.len(), rows),
            None => self.matrix_source.recon_general(rows),
        }
    }
}

impl Deref for CompiledLsss {
    type Target = Lsss;

    fn deref(&self) -> &Lsss {
        &self.matrix_source
    }
}

fn valid_rows(rows: &[usize], count: usize) -> bool {
    if rows.is_empty() || rows.iter().any(|&r| r >= count) {
        return false;
    }
    if rows.windows(2).all(|p| p[0] < p[1]) {
        return true;
    }
    let mut sorted = rows.to_vec();
    sorted.sort_unstable();
    sorted.windows(2).all(|p| p[0] != p[1])
}

fn lagrange(t: usize, count: usize, rows: &[usize]) -> Option<Vec<(usize, Fr)>> {
    if rows.len() < t || !valid_rows(rows, count) {
        return None;
    }
    // The first t evaluation points span the target. Later variables are free and set to zero.
    let pivots = &rows[..t];
    let x: Vec<_> = pivots.iter().map(|&r| Fr::from(r as u64 + 1)).collect();
    let numerator: Fr = x.iter().product();
    let mut denominators: Vec<_> = x
        .iter()
        .enumerate()
        .map(|(i, x_i)| {
            x.iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .fold(*x_i, |product, (_, x_j)| product * (*x_j - x_i))
        })
        .collect();
    ark_ff::batch_inversion(&mut denominators);
    Some(
        pivots
            .iter()
            .copied()
            .zip(denominators.into_iter().map(|d| numerator * d))
            .collect(),
    )
}

/// Constructs the `t`-of-`n` Vandermonde sharing matrix.
pub fn threshold(t: usize, n: usize) -> Lsss {
    assert!(t > 0, "threshold must be positive");
    assert!(t <= n, "threshold cannot exceed participant count");
    let matrix = (1..=n)
        .map(|index| {
            let x = Fr::from(index as u64);
            let mut power = Fr::one();
            let mut row = Vec::with_capacity(t);
            for _ in 0..t {
                row.push(power);
                power *= x;
            }
            row
        })
        .collect();
    Lsss {
        matrix,
        rho: (0..n).collect(),
    }
}

/// Policy `(P0 and P1) or (P2 and P3 and P4)`.
pub fn dnf_example() -> Lsss {
    let zero = Fr::zero();
    let one = Fr::one();
    let minus_one = -one;
    Lsss {
        matrix: vec![
            vec![one, one, zero, zero],
            vec![zero, minus_one, zero, zero],
            vec![one, zero, one, one],
            vec![zero, zero, minus_one, zero],
            vec![zero, zero, zero, minus_one],
        ],
        rho: (0..5).collect(),
    }
}

/// Constructs an OR of `k` independent AND clauses over `m` holders each.
///
/// Clause `j` owns columns `1 + (m - 1) * j .. 1 + (m - 1) * (j + 1)`.
/// Its first row carries the secret plus all clause-local masks, and each of
/// the remaining `m - 1` rows cancels one mask. Therefore the all-one
/// coefficient vector over exactly one clause's `m` rows reconstructs the
/// secret.
pub fn disjunction(k: usize, m: usize) -> Lsss {
    assert!(k > 0, "disjunction must contain at least one clause");
    assert!(m > 0, "conjunction width must be positive");
    let mask_count = m - 1;
    let width = 1 + mask_count * k;
    let mut matrix = Vec::with_capacity(k * m);
    for clause in 0..k {
        let mask_start = 1 + mask_count * clause;
        let mut first = vec![Fr::zero(); width];
        first[0] = Fr::one();
        for offset in 0..mask_count {
            first[mask_start + offset] = Fr::one();
        }
        matrix.push(first);
        for offset in 0..mask_count {
            let mut row = vec![Fr::zero(); width];
            row[mask_start + offset] = -Fr::one();
            matrix.push(row);
        }
    }
    Lsss {
        rho: (0..k * m).collect(),
        matrix,
    }
}

/// An OR of `k` three-holder AND clauses.
pub fn dnf_chain(k: usize) -> Lsss {
    disjunction(k, 3)
}

/// A monotone access formula: a holder at a leaf or a threshold gate over subformulas.
///
/// `AND(children)` is `Formula::Thr(children.len(), children)`, and
/// `OR(children)` is `Formula::Thr(1, children)`.
#[derive(Clone, Debug)]
pub enum Formula {
    Leaf(usize),
    Thr(usize, Vec<Formula>),
}

/// Compiles a monotone formula into an LSSS instance by the standard
/// Lewko-Waters labeling.
///
/// The root carries the length-1 label `(1)`. A `Thr(t, children)` gate
/// appends `t - 1` fresh columns and gives child `i` the label
/// `(parent, x_i^1, ..., x_i^{t-1})` with `x_i = i + 1`. A leaf's final label
/// becomes its LSSS row.
pub fn compile_formula(root: &Formula) -> Lsss {
    let mut cols = 1usize;
    let mut rows: Vec<(usize, Vec<Fr>)> = Vec::new();

    fn rec(node: &Formula, label: Vec<Fr>, cols: &mut usize, rows: &mut Vec<(usize, Vec<Fr>)>) {
        match node {
            Formula::Leaf(party) => rows.push((*party, label)),
            Formula::Thr(threshold_value, children) => {
                assert!(
                    *threshold_value >= 1 && *threshold_value <= children.len(),
                    "threshold out of range"
                );
                let base = *cols;
                *cols += threshold_value - 1;
                for (index, child) in children.iter().enumerate() {
                    let x = Fr::from((index + 1) as u64);
                    let mut child_label = label.clone();
                    child_label.resize(*cols, Fr::zero());
                    let mut power = x;
                    for offset in 0..(threshold_value - 1) {
                        child_label[base + offset] = power;
                        power *= x;
                    }
                    rec(child, child_label, cols, rows);
                }
            }
        }
    }

    rec(root, vec![Fr::one()], &mut cols, &mut rows);
    for (_, row) in &mut rows {
        row.resize(cols, Fr::zero());
    }
    Lsss {
        matrix: rows.iter().map(|(_, row)| row.clone()).collect(),
        rho: rows.iter().map(|(party, _)| *party).collect(),
    }
}

impl Lsss {
    fn width(&self) -> Option<usize> {
        let width = self.matrix.first()?.len();
        if width == 0
            || self.rho.len() != self.matrix.len()
            || self.matrix.iter().any(|row| row.len() != width)
        {
            None
        } else {
            Some(width)
        }
    }

    pub(crate) fn is_well_formed(&self) -> bool {
        self.width().is_some()
    }

    /// Shares `secret` using a fresh random vector `(secret, r_1, ..., r_{k-1})`.
    pub fn share<R: Rng + ?Sized>(&self, secret: Fr, rng: &mut R) -> Vec<Fr> {
        let width = self.width().expect("well-formed nonempty LSSS matrix");
        let mut vector = Vec::with_capacity(width);
        vector.push(secret);
        vector.extend((1..width).map(|_| Fr::rand(rng)));
        self.matrix
            .iter()
            .map(|row| {
                row.iter()
                    .zip(&vector)
                    .fold(Fr::zero(), |sum, (coefficient, value)| {
                        sum + *coefficient * value
                    })
            })
            .collect()
    }

    fn vandermonde_width(&self) -> Option<usize> {
        let t = self.width()?;
        if t > self.matrix.len() {
            return None;
        }
        self.matrix
            .iter()
            .enumerate()
            .all(|(i, row)| {
                let x = Fr::from(i as u64 + 1);
                let mut power = Fr::one();
                row.iter().all(|value| {
                    if *value != power {
                        return false;
                    }
                    power *= x;
                    true
                })
            })
            .then_some(t)
    }

    /// Finds the canonical sparse reconstruction vector in the order of the given rows.
    pub fn recon_coeffs(&self, rows: &[usize]) -> Option<Vec<(usize, Fr)>> {
        match self.vandermonde_width() {
            Some(t) => lagrange(t, self.matrix.len(), rows),
            None => self.recon_general(rows),
        }
    }

    /// Solves the reconstruction equations for an arbitrary sharing matrix using RREF.
    ///
    /// Variables follow the caller-provided row order; non-pivot variables are set to
    /// zero, and zero coefficients are omitted from the result.
    pub fn recon_general(&self, rows: &[usize]) -> Option<Vec<(usize, Fr)>> {
        let width = self.width()?;
        if rows.is_empty() || rows.iter().any(|&row| row >= self.matrix.len()) || {
            let mut unique = rows.to_vec();
            unique.sort_unstable();
            unique.windows(2).any(|pair| pair[0] == pair[1])
        } {
            return None;
        }

        // Solve A * omega = target, where A's columns are the selected LSSS rows.
        let variable_count = rows.len();
        let mut augmented = vec![vec![Fr::zero(); variable_count + 1]; width];
        for (equation, augmented_row) in augmented.iter_mut().enumerate() {
            for (variable, &matrix_row) in rows.iter().enumerate() {
                augmented_row[variable] = self.matrix[matrix_row][equation];
            }
            augmented_row[variable_count] = if equation == 0 { Fr::one() } else { Fr::zero() };
        }

        let mut pivot_row = 0;
        let mut pivots = Vec::new();
        for variable in 0..variable_count {
            let Some(found) = (pivot_row..width).find(|&row| !augmented[row][variable].is_zero())
            else {
                continue;
            };
            augmented.swap(pivot_row, found);
            let inverse = augmented[pivot_row][variable]
                .inverse()
                .expect("pivot is nonzero");
            for value in &mut augmented[pivot_row][variable..=variable_count] {
                *value *= inverse;
            }
            let pivot_values = augmented[pivot_row][variable..=variable_count].to_vec();
            for (row, augmented_row) in augmented.iter_mut().enumerate() {
                if row == pivot_row {
                    continue;
                }
                let factor = augmented_row[variable];
                if factor.is_zero() {
                    continue;
                }
                for (value, pivot_value) in augmented_row[variable..=variable_count]
                    .iter_mut()
                    .zip(&pivot_values)
                {
                    *value -= factor * pivot_value;
                }
            }
            pivots.push((variable, pivot_row));
            pivot_row += 1;
            if pivot_row == width {
                break;
            }
        }

        if augmented.iter().any(|equation| {
            equation[..variable_count].iter().all(Zero::is_zero)
                && !equation[variable_count].is_zero()
        }) {
            return None;
        }

        let mut solution = vec![Fr::zero(); variable_count];
        for (variable, equation) in pivots {
            solution[variable] = augmented[equation][variable_count];
        }
        Some(
            rows.iter()
                .copied()
                .zip(solution)
                .filter(|(_, coefficient)| !coefficient.is_zero())
                .collect(),
        )
    }
}
