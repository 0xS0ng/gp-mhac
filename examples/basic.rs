use ark_bls12_381::Fr;
use ark_std::rand::{rngs::OsRng, RngCore};
use gp_mhac::access::compile_access;
use gp_mhac::issuance::{cred_iss, cred_iss_attributes, iss_setup};
use gp_mhac::lsss::{compile_formula, Formula};
use gp_mhac::presentation::{cred_pres, vf_pres};

fn main() {
    let mut rng = OsRng;
    // IssSetup: two business attributes plus the reserved pseudonym and mask coordinates.
    let (pp, keys) = iss_setup(4, &mut rng);

    // CompileAccess: director 0, finance officers 1–3, legal officers 4–5.
    use Formula::{Leaf, Thr};
    let finance = Thr(2, (1..=3).map(Leaf).collect());
    let legal = Thr(1, (4..=5).map(Leaf).collect());
    let policy = Thr(1, vec![Leaf(0), Thr(2, vec![finance, legal])]);
    let access = compile_access(compile_formula(&policy), 6);

    // CredIss: business attribute 0 is private, and attribute 1 is revealed.
    let (shares, prv, rev, j_pid) = {
        let business = [Fr::from(7u64), Fr::from(42u64)];
        let a = cred_iss_attributes(&business, &[0], &[1], &mut rng).unwrap();
        let shares = cred_iss(&pp, &keys, &a.attrs, &a.prv, &access, &mut rng).unwrap();
        (shares, a.prv, a.rev, a.j_pid)
    };

    let ctx = b"purchase-approval";
    // Only public values come from the credential; CredPres uses row shares for private slots.
    let mut public = vec![Fr::from(0u64); pp.h.len()];
    for &(j, value) in &shares[0].pub_attrs {
        public[j] = value;
    }
    let revealed: Vec<_> = rev.iter().map(|&j| (j, public[j])).collect();
    let mut present = |holders: &[usize]| {
        let rows: Vec<_> = access
            .lsss
            .rho
            .iter()
            .enumerate()
            .filter_map(|(row, holder)| holders.contains(holder).then_some(row))
            .collect();
        let mut nonce = [0; 32];
        rng.fill_bytes(&mut nonce);
        let (proof, _) = cred_pres(
            &pp, &keys.ipk, &shares, &public, &prv, &access, &rows, &rev, ctx, nonce, &mut rng,
        )
        .unwrap();
        // VfPres receives the public coordinate index j_pid, not the pseudonym secret.
        assert!(vf_pres(
            &pp, &keys.ipk, &proof, &revealed, j_pid, ctx, nonce
        ));
        proof.nym
    };

    let director_nym = present(&[0]);
    let officers_nym = present(&[1, 2, 4]);
    assert_eq!(director_nym, officers_nym);
    println!("Both committees verified with the same pseudonym in this context.");
}
