use ark_std::test_rng;
use gp_mhac::access::compile_access;
use gp_mhac::issuance::{iss_keygen, setup};
use gp_mhac::lsss::threshold;
use gp_mhac::ops::{reset, snapshot, OpCounts};

#[test]
fn issuer_setup_has_exact_counts() {
    let mut rng = test_rng();
    for attribute_count in [8usize, 16, 24, 32] {
        reset();
        let params = setup(attribute_count, &mut rng);
        let _ = iss_keygen(&params, &mut rng);
        assert_eq!(
            snapshot(),
            OpCounts {
                e2: 1,
                h: 1,
                h_g: attribute_count as u64,
                ..OpCounts::default()
            },
            "IssSetup count mismatch for l={attribute_count}"
        );
    }
}

#[test]
fn compile_access_counts_exactly_one_hash() {
    for threshold_value in [3usize, 5, 10, 20, 35, 50] {
        reset();
        let lsss = threshold(threshold_value, 2 * threshold_value);
        assert_eq!(snapshot(), OpCounts::default());
        let _ = compile_access(lsss, 2 * threshold_value);
        assert_eq!(
            snapshot(),
            OpCounts {
                h: 1,
                ..OpCounts::default()
            },
            "CompileAccess count mismatch for t={threshold_value}"
        );
    }
}
