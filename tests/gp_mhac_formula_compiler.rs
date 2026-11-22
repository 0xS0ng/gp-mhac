use gp_mhac::lsss::{compile_formula, Formula};
use std::collections::BTreeSet;

fn boolean_ok(formula: &Formula, set: &BTreeSet<usize>) -> bool {
    match formula {
        Formula::Leaf(party) => set.contains(party),
        Formula::Thr(threshold, children) => {
            children
                .iter()
                .filter(|child| boolean_ok(child, set))
                .count()
                >= *threshold
        }
    }
}

fn parties(formula: &Formula, out: &mut Vec<usize>) {
    match formula {
        Formula::Leaf(party) => out.push(*party),
        Formula::Thr(_, children) => {
            for child in children {
                parties(child, out);
            }
        }
    }
}

fn gate_col_sum(formula: &Formula) -> usize {
    match formula {
        Formula::Leaf(_) => 0,
        Formula::Thr(threshold, children) => {
            (threshold - 1) + children.iter().map(gate_col_sum).sum::<usize>()
        }
    }
}

#[test]
fn lewko_waters_nested_composite_is_correct() {
    // (3-of-6) AND (2-of-6)
    let left = Formula::Thr(3, (0..6).map(Formula::Leaf).collect());
    let right = Formula::Thr(2, (6..12).map(Formula::Leaf).collect());
    let root = Formula::Thr(2, vec![left, right]);

    let lsss = compile_formula(&root);
    let d = lsss.matrix.len();
    let k = lsss.matrix[0].len();
    assert_eq!(d, 12);
    assert_eq!(k, 1 + gate_col_sum(&root));
    assert_eq!(k, 5);

    let mut parties_vec = Vec::new();
    parties(&root, &mut parties_vec);
    parties_vec.sort_unstable();
    parties_vec.dedup();
    let n = parties_vec.len();
    for mask in 0u32..(1 << n) {
        let set: BTreeSet<_> = (0..n)
            .filter(|index| mask & (1 << index) != 0)
            .map(|index| parties_vec[index])
            .collect();
        let selected_rows: Vec<_> = (0..lsss.matrix.len())
            .filter(|&row| set.contains(&lsss.rho[row]))
            .collect();
        let lsss_authorized = if selected_rows.is_empty() {
            false
        } else {
            lsss.recon_coeffs(&selected_rows).is_some()
        };
        assert_eq!(
            lsss_authorized,
            boolean_ok(&root, &set),
            "subset {set:?} authorization mismatch"
        );
    }
}
