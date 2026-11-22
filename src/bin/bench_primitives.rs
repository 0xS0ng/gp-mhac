//! Seven primitive timings on valid presentation transcripts and randomized group inputs.
use ark_bls12_381::{Fr, G1Projective, G2Projective};
use ark_ec::Group;
use ark_ff::{UniformRand, Zero};
use ark_serialize::CanonicalSerialize;
use ark_std::rand::{rngs::StdRng, seq::SliceRandom, RngCore, SeedableRng};
use gp_mhac::{
    access::compile_access,
    issuance::{self, row_tag_message},
    lsss::threshold,
    ops,
    presentation::{cred_pres, vf_pres},
    primitives::{
        auth,
        hash::{commit, hash_to_g1, hash_to_zp},
    },
};
use std::{
    fs::{self, OpenOptions},
    hint::black_box,
    io::{self, Write},
    path::PathBuf,
    time::Instant,
};

const WARM: usize = 100;
const MEASURED: usize = 1000;
const FIXTURES: usize = 32;
const TAG_NYM: &[u8] = b"GP-MHAC-NYM-v1";
const TAG_SIG: &[u8] = b"GP-MHAC-SIG-v1";
// Use the verifier's application context and request header.
const CTX: &[u8] = b"bench/application";
const SEED_LAYOUT: u64 = 2026112105;
const SEED_FIXTURE: u64 = 289074589749;
const NAMES: [&str; 7] = ["E1", "E2", "P", "H_G", "V_sig", "SHA256", "H_field"];
const CALLS: [usize; 7] = [1, 1, 1, 1, 1, 32, 32];

fn enc(v: &mut Vec<u8>, object: &impl CanonicalSerialize) {
    object.serialize_compressed(v).unwrap();
}
fn u64be(v: &mut Vec<u8>, n: usize) {
    v.extend_from_slice(&(n as u64).to_be_bytes());
}
struct Fixture {
    row: Vec<u8>,
    tag: auth::Signature,
    pk: auth::PublicKey,
    ssid: Vec<u8>,
    sender: u64,
    msg: Vec<u8>,
    salt: [u8; 32],
    header_bytes: usize,
    fs: Vec<u8>,
}

fn build_fixtures(r: &mut StdRng) -> Vec<Fixture> {
    let biz = gp_mhac::workload::Business::fixture(14, 2, 8);
    let w = biz.gp(r);
    let pp = issuance::setup(16, r);
    let keys = issuance::iss_keygen(&pp, r);
    let hdr = keys.ipk.header(CTX);
    let policy = compile_access(threshold(5, 10), 10);
    let active = [0, 1, 2, 3, 4];
    let revealed = w.rev.iter().map(|&j| (j, w.attrs[j])).collect::<Vec<_>>();
    (0..FIXTURES)
        .map(|k| {
            let creds = issuance::cred_iss(&pp, &keys, &w.attrs, &w.prv, &policy, r).unwrap();
            let mut nonce = [0_u8; 32];
            r.fill_bytes(&mut nonce);
            let (pres, tr) = cred_pres(
                &pp, &keys.ipk, &creds, &w.attrs, &w.prv, &policy, &active, &w.rev, CTX, nonce, r,
            )
            .unwrap();
            assert!(vf_pres(&pp, &keys.ipk, &pres, &revealed, 0, CTX, nonce));
            let id = k % active.len();
            let pre = &creds[id];
            let row = &pre.rows[0];
            let tag_bytes = row_tag_message(
                &pre.asid,
                &pre.a_sig,
                row.index,
                &row.d_factor,
                &pre.pub_attrs,
            );
            assert_eq!(row.tag.to_bytes().len(), 80);
            assert!(auth::verify(&keys.auth_pk, &tag_bytes, &row.tag));
            let opening = tr.openings.iter().find(|x| x.holder == id).unwrap();
            let mut msg = Vec::new();
            for x in [
                &opening.c_hat,
                &opening.n,
                &opening.v,
                &opening.u_hat,
                &opening.u_prime,
            ] {
                enc(&mut msg, x);
            }
            let target = tr.round1.iter().find(|x| x.holder == id).unwrap();
            assert_eq!(
                commit(&tr.ssid, id as u64, &msg, opening.randomness),
                target.commitment
            );
            // Rebuild the Fiat–Shamir input and verify it against the proof challenge.
            let mut fs = Vec::new();
            u64be(&mut fs, hdr.len());
            fs.extend_from_slice(&hdr);
            for x in [&pres.a_bar, &pres.b_bar, &pres.d, &pres.nym] {
                enc(&mut fs, x);
            }
            u64be(&mut fs, CTX.len());
            fs.extend_from_slice(CTX);
            for x in [&tr.round3.u_i, &tr.round3.u_ii, &tr.round3.u_iii] {
                enc(&mut fs, x);
            }
            u64be(&mut fs, revealed.len());
            for (idx, a) in &revealed {
                u64be(&mut fs, *idx);
                enc(&mut fs, a);
            }
            fs.extend_from_slice(&nonce);
            fs.extend_from_slice(&pres.eta);
            assert_eq!(hash_to_zp(TAG_SIG, &fs), pres.ch);
            Fixture {
                row: tag_bytes,
                tag: row.tag.clone(),
                pk: keys.auth_pk.clone(),
                ssid: tr.ssid.clone(),
                sender: id as u64,
                msg,
                salt: opening.randomness,
                header_bytes: hdr.len(),
                fs,
            }
        })
        .collect()
}

struct Input {
    a: G1Projective,
    b: G2Projective,
    s: Fr,
}
fn scalar(r: &mut StdRng) -> Fr {
    loop {
        let x = Fr::rand(r);
        if !x.is_zero() {
            return x;
        }
    }
}
fn group_inputs(r: &mut StdRng) -> Vec<Input> {
    (0..WARM + MEASURED)
        .map(|_| Input {
            a: ops::g1_mul(&G1Projective::generator(), &scalar(r)),
            b: ops::g2_mul(&G2Projective::generator(), &scalar(r)),
            s: scalar(r),
        })
        .collect()
}

struct Sample {
    block: usize,
    pos: usize,
    op: usize,
    ns: u128,
}
fn run(path: PathBuf) -> io::Result<()> {
    if path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "output CSV exists",
        ));
    }
    let tmp = path.with_extension("partial");
    let mut csv = OpenOptions::new().create_new(true).write(true).open(&tmp)?;
    let mut rng = StdRng::seed_from_u64(SEED_FIXTURE);
    let fixtures = build_fixtures(&mut rng);
    let input = group_inputs(&mut rng);
    let mut rng = StdRng::seed_from_u64(SEED_LAYOUT);
    let mut schedule = Vec::with_capacity(WARM + MEASURED);
    for _ in 0..WARM + MEASURED {
        let mut ops = [0, 1, 2, 3, 4, 5, 6];
        ops.shuffle(&mut rng);
        schedule.push(ops);
    }
    let f = &fixtures[0];
    // Each SHA-256 update length in commit_with_domain: prefix, lens, domain,
    // ssid, sender, serialized opening, salt. Lengths are byte lengths, not bits.
    let sha_bytes =
        b"GP-MHAC-COMMIT-v1".len() + 8 + b"msg".len() + 8 + f.ssid.len() + 8 + 8 + f.msg.len() + 32;
    for g in &fixtures {
        assert_eq!(
            (g.row.len(), g.ssid.len(), g.msg.len(), g.fs.len()),
            (f.row.len(), f.ssid.len(), f.msg.len(), f.fs.len())
        );
    }
    eprintln!("fixtures={} CTX={} HDR={} V_sig.message={} V_sig.signature=80 round1.ssid={} round1.message={} SHA256.total={} challenge.payload={}",
            fixtures.len(), CTX.len(), f.header_bytes, f.row.len(), f.ssid.len(), f.msg.len(), sha_bytes, f.fs.len());
    let mut results = Vec::with_capacity((WARM + MEASURED) * 7);
    ops::reset();
    for (i, order) in schedule.into_iter().enumerate() {
        let v = &input[i];
        let f = &fixtures[i % FIXTURES];
        for (pos, op) in order.into_iter().enumerate() {
            // Dispatch and validation are outside the measured interval. Keep the
            // compiler barrier on both inputs and output even for repeated CTX.
            let elapsed = match op {
                0 => {
                    let tic = Instant::now();
                    let _ = black_box(ops::g1_mul(black_box(&v.a), black_box(&v.s)));
                    tic.elapsed()
                }
                1 => {
                    let tic = Instant::now();
                    let _ = black_box(ops::g2_mul(black_box(&v.b), black_box(&v.s)));
                    tic.elapsed()
                }
                2 => {
                    let tic = Instant::now();
                    let _ = black_box(ops::pair(black_box(&v.a), black_box(&v.b)));
                    tic.elapsed()
                }
                3 => {
                    let tic = Instant::now();
                    let _ = black_box(hash_to_g1(black_box(TAG_NYM), black_box(CTX)));
                    tic.elapsed()
                }
                4 => {
                    let tic = Instant::now();
                    let ok = black_box(auth::verify(
                        black_box(&f.pk),
                        black_box(&f.row),
                        black_box(&f.tag),
                    ));
                    let elapsed = tic.elapsed();
                    assert!(ok);
                    elapsed
                }
                5 => {
                    let tic = Instant::now();
                    for j in 0..CALLS[op] {
                        let g = &fixtures[(i + j) % FIXTURES];
                        black_box(commit(
                            black_box(&g.ssid),
                            black_box(g.sender),
                            black_box(&g.msg),
                            black_box(g.salt),
                        ));
                    }
                    tic.elapsed()
                }
                6 => {
                    let tic = Instant::now();
                    for j in 0..CALLS[op] {
                        let g = &fixtures[(i + j) % FIXTURES];
                        black_box(hash_to_zp(black_box(TAG_SIG), black_box(&g.fs)));
                    }
                    tic.elapsed()
                }
                _ => unreachable!(),
            };
            results.push(Sample {
                block: i,
                pos,
                op,
                ns: elapsed.as_nanos(),
            });
        }
    }
    let c = ops::snapshot();
    let reps = (WARM + MEASURED) as u64;
    assert_eq!(
        (c.e1, c.e2, c.pairing, c.h_g, c.v_sig, c.h),
        (
            reps,
            reps,
            reps,
            reps,
            reps,
            reps * ((CALLS[5] + CALLS[6]) as u64)
        )
    );
    writeln!(
        csv,
        "phase,block,position,operation,calls,elapsed_ns,us_per_call"
    )?;
    for s in results {
        if s.ns == 0 {
            return Err(io::Error::other("timer returned zero"));
        }
        let phase = if s.block < WARM { "warmup" } else { "measured" };
        writeln!(
            csv,
            "{phase},{},{},{},{},{},{:.12}",
            s.block,
            s.pos,
            NAMES[s.op],
            CALLS[s.op],
            s.ns,
            s.ns as f64 / 1000. / CALLS[s.op] as f64
        )?;
    }
    csv.flush()?;
    csv.sync_all()?;
    drop(csv);
    fs::rename(tmp, path)?;
    Ok(())
}

fn main() -> io::Result<()> {
    let dir = std::env::args_os()
        .nth(1)
        .expect("usage: bench_primitives NEW.csv");
    run(PathBuf::from(dir))
}
