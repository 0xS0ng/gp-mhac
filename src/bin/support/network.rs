//! End-to-end presentation over persistent loopback workers and a delay-injecting broker.
use ark_bls12_381::{Fr, G1Projective, G2Projective};
use ark_ff::Zero;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::{rngs::OsRng, RngCore};
use gp_mhac::workload::Business;
use gp_mhac::{
    access::{compile_access, CompiledAccess},
    baselines::mhac::issuance,
    baselines::mhac::{
        self as f, MhacCredential, Step2Output, Step3Commitment, Step4Opening, Step6Response,
    },
    detect::{detect_cached, AuthenticatedEnvelope, DecodedMessage, DetectOutcome},
    issuance::{cred_iss, iss_keygen, setup, IssuerPublicKey, Parameters, PreCred, Row},
    lsss::threshold,
    ops,
    presentation::{
        self as gp, HolderResponse, LiftProof, PrimaryResponse, Round1Message, Round1Opening,
        Round2Public, Round3Message, RowBroadcast, SeedOpening,
    },
    primitives::{
        auth::{PublicKey, Signature},
        hash::hash_to_g1,
    },
};
use std::{
    env, fs,
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    path::Path,
    process::{Child, Command},
    thread,
    time::{Duration, Instant},
};
#[path = "net/wire.rs"]
mod wire;
use wire::*;
#[path = "net/schedule.rs"]
mod interleaved;
const CONTEXT: &[u8] = b"bench-committee-context";
fn payload(f: impl FnOnce(&mut Writer)) -> Vec<u8> {
    let mut w = Writer::new();
    f(&mut w);
    w.into_bytes()
}
fn invalid(m: impl ToString) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, m.to_string())
}
fn check(v: bool, m: &str) -> io::Result<()> {
    if v {
        Ok(())
    } else {
        Err(invalid(m))
    }
}
struct MhacShare {
    credential: MhacCredential,
    d: G1Projective,
    sig: Signature,
}
#[allow(
    clippy::large_enum_variant,
    reason = "Keep each worker's local credential inline so the timed request does not perform an additional pointer lookup."
)]
enum LocalCredential {
    Gp(PreCred),
    Mhac(MhacShare),
}
struct Config {
    id: usize,
    params: Parameters,
    ipk: IssuerPublicKey,
    pub_attrs: Vec<(usize, Fr)>,
    prv: Vec<usize>,
    rev: Vec<usize>,
    access: CompiledAccess,
    own: LocalCredential,
}
fn configs(scheme: &str, n: usize) -> io::Result<Vec<Vec<u8>>> {
    let b = Business::fixture(14, 2, 8);
    let mut rng = OsRng;
    let t = n / 2;
    let gp = scheme == "gp-mhac";
    let w = if gp { b.gp(&mut rng) } else { b.mhac() };
    let pp = if gp {
        setup(w.attrs.len(), &mut rng)
    } else {
        issuance::setup(w.attrs.len(), &mut rng)
    };
    let pack = |id: usize,
                x: &G2Projective,
                vk: &PublicKey,
                pub_attrs: &[(usize, Fr)],
                cred: &LocalCredential| {
        payload(|o| {
            o.usize(n);
            o.usize(id);
            encode_params(o, &pp);
            o.serializable(x);
            o.serializable(&vk.0);
            encode_indexed_fr_vec(o, pub_attrs);
            encode_usize_vec(o, &w.prv);
            encode_usize_vec(o, &w.rev);
            match cred {
                LocalCredential::Gp(c) => {
                    o.u8(0);
                    encode_precred(o, c);
                }
                LocalCredential::Mhac(MhacShare { credential, d, sig }) => {
                    o.u8(1);
                    encode_mhac_credential(o, credential);
                    o.serializable(d);
                    encode_signature(o, sig);
                }
            }
        })
    };
    if gp {
        assert_eq!(w.j_pid, Some(0));
        let access = compile_access(threshold(t, n), n);
        let keys = iss_keygen(&pp, &mut rng);
        let creds = cred_iss(&pp, &keys, &w.attrs, &w.prv, &access, &mut rng)
            .map_err(|v| invalid(format!("{v:?}")))?;
        Ok(creds
            .iter()
            .enumerate()
            .map(|(i, c)| {
                pack(
                    i,
                    &keys.x2,
                    &keys.auth_pk,
                    &c.pub_attrs,
                    &LocalCredential::Gp(c.clone()),
                )
            })
            .collect())
    } else {
        let d = issuance::issue(&pp, &w.attrs, &w.prv, t, n, &mut rng)
            .map_err(|v| invalid(format!("{v:?}")))?;
        Ok(d.credentials
            .iter()
            .enumerate()
            .map(|(i, c)| {
                let cert = &c.certificate;
                pack(
                    i,
                    &d.x2,
                    &d.auth_vk,
                    &c.public_attrs,
                    &LocalCredential::Mhac(MhacShare {
                        credential: c.local.clone(),
                        d: cert.d,
                        sig: cert.signature.clone(),
                    }),
                )
            })
            .collect())
    }
}
fn read_config(buf: &[u8]) -> io::Result<Config> {
    let mut r = Reader::new(buf);
    let n = r.usize()?;
    let id = r.usize()?;
    check(
        [6, 10, 20, 40, 70, 100].contains(&n) && id < n,
        "bad experiment size or holder",
    )?;
    let params = decode_params(&mut r)?;
    let x2 = r.canonical()?;
    let vk = PublicKey(r.canonical()?);
    let pub_attrs = decode_indexed_fr_vec(&mut r)?;
    let prv = decode_usize_vec(&mut r)?;
    let rev = decode_usize_vec(&mut r)?;
    let mode = r.u8()?;
    let own = match mode {
        0 => LocalCredential::Gp(decode_precred(&mut r)?),
        1 => LocalCredential::Mhac(MhacShare {
            credential: decode_mhac_credential(&mut r)?,
            d: r.canonical()?,
            sig: decode_signature(&mut r)?,
        }),
        _ => return Err(invalid("bad mode")),
    };
    r.end()?;
    let access = compile_access(threshold(n / 2, n), n); // static credential policy, not active request coefficients
    let ipk = IssuerPublicKey::from_parts(&params, x2, vk);
    Ok(Config {
        id,
        params,
        ipk,
        pub_attrs,
        prv,
        rev,
        own,
        access,
    })
}
/// All children contribute a packet only on rounds where they speak. The frame
/// list is authenticated by the broker's dedicated per-sender socket.
fn exchange<T>(
    conn: &mut TcpStream,
    speakers: &[usize],
    msg: Option<Vec<u8>>,
    read: impl Fn(usize, &mut Reader) -> io::Result<T>,
) -> io::Result<Vec<T>> {
    if let Some(m) = msg {
        write_frame(conn, &m)?;
    }
    let frame = read_frame(conn)?;
    let mut r = Reader::new(&frame);
    let count = r.count()?;
    check(count == speakers.len(), "missing or extra broadcaster")?;
    let messages = speakers
        .iter()
        .map(|&expected| {
            let holder = r.usize()?;
            check(holder == expected, "out-of-order or duplicate sender")?;
            let m = r.raw()?;
            let mut body = Reader::new(&m);
            let decoded = read(holder, &mut body)?;
            body.end()?;
            Ok(decoded)
        })
        .collect::<io::Result<Vec<_>>>()?;
    r.end()?;
    Ok(messages)
}
fn envelope(round: u8, sender: usize, m: DecodedMessage) -> AuthenticatedEnvelope {
    AuthenticatedEnvelope {
        round,
        sender,
        payload: Ok(m),
    }
}
fn gp_request(
    stream: &mut TcpStream,
    c: &Config,
    pc: &PreCred,
    active: &[usize],
    nonce: [u8; 32],
) -> io::Result<()> {
    let mut rng = OsRng;
    let reconstruction = c
        .access
        .reconstruct(active)
        .ok_or_else(|| invalid("unauthorized"))?;
    let active = reconstruction.rows();
    let coeff = reconstruction.coefficients();
    let ssid = gp::derive_ssid(
        &c.ipk.header(CONTEXT),
        &c.access.asid,
        &pc.a_sig,
        active,
        &c.rev,
        &nonce,
    );
    let op = hash_to_g1(b"GP-MHAC-NYM-v1", CONTEXT);
    let (m, state) = gp::round1_holder_cached(
        &op, &c.params, pc, c.id, active, coeff, &c.prv, &ssid, &mut rng,
    )
    .expect("honest GP-MHAC first round");
    let commitments = exchange(
        stream,
        active,
        Some(payload(|w| encode_round1_message(w, &m))),
        |id, r| {
            let m = decode_round1_message(r)?;
            check(m.holder == id, "round-one slot")?;
            Ok(m)
        },
    )?;
    let openings = exchange(
        stream,
        active,
        Some(payload(|w| encode_opening(w, &state.opening()))),
        |id, r| {
            let m = decode_opening(r)?;
            check(m.holder == id, "round 2 slot")?;
            Ok(m)
        },
    )?;
    let round2 = round2_public(&openings);
    let primary = active[0];
    let mut primary_state = None;
    let broadcast = if c.id == primary {
        let (m, s) = gp::round3_primary(
            &c.params,
            &pc.a_sig,
            &public_vector(c),
            &c.prv,
            &c.rev,
            active,
            coeff,
            &commitments,
            &openings,
            CONTEXT,
            &ssid,
            nonce,
            &mut rng,
        )
        .expect("honest GP-MHAC round 3");
        primary_state = Some(s);
        Some(payload(|w| encode_r3_msg(w, &m)))
    } else {
        None
    };
    let round3 = exchange(stream, &active[..1], broadcast, |id, r| {
        check(id == primary, "round 3 slot")?;
        decode_r3_msg(r)
    })?
    .pop()
    .ok_or_else(|| invalid("empty round 3"))?;
    let seeds = exchange(
        stream,
        active,
        Some(payload(|w| encode_seed_opening(w, &state.seed_opening()))),
        |id, r| {
            let m = decode_seed_opening(r)?;
            check(m.holder == id, "round 4 slot")?;
            Ok(m)
        },
    )?;
    let rev = revealed(c);
    let coin = gp::verify_round4_coin(
        &c.ipk,
        &commitments,
        &seeds,
        active,
        active,
        &round2,
        &round3,
        &rev,
        CONTEXT,
        &ssid,
        nonce,
    )
    .expect("honest GP-MHAC coin");
    let z = payload(|w| {
        if let Some(ps) = primary_state {
            let (h, p) = gp::round5_primary(&state, &ps, &coin);
            encode_holder_response(w, &h);
            encode_primary_response(w, &p);
        } else {
            encode_holder_response(w, &gp::round5_holder(&state, &coin));
        }
    });
    let r5 = exchange(stream, active, Some(z), |id, r| {
        let h = decode_holder_response(r)?;
        check(h.holder == id, "round 5 slot")?;
        Ok(if id == primary {
            DecodedMessage::Round5Primary {
                holder: h,
                primary: decode_primary_response(r)?,
            }
        } else {
            DecodedMessage::Round5Holder(h)
        })
    })?;
    let mut envs = Vec::new();
    envs.extend(
        commitments
            .into_iter()
            .map(|m| envelope(1, m.holder, DecodedMessage::Round1(m))),
    );
    envs.extend(
        openings
            .into_iter()
            .map(|m| envelope(2, m.holder, DecodedMessage::Round2(m))),
    );
    envs.push(envelope(3, primary, DecodedMessage::Round3(round3)));
    envs.extend(
        seeds
            .into_iter()
            .map(|m| envelope(4, m.holder, DecodedMessage::Round4Seed(m))),
    );
    envs.extend(
        active
            .iter()
            .copied()
            .zip(r5)
            .map(|(id, m)| envelope(5, id, m)),
    );
    match detect_cached(
        &c.params,
        &c.ipk,
        &pc.a_sig,
        &op,
        &c.access,
        active,
        &reconstruction,
        &envs,
        &coin,
        &rev,
        &pc.pub_attrs,
        &c.prv,
        c.prv[0],
        CONTEXT,
        nonce,
    ) {
        DetectOutcome::Pres(_) => Ok(()),
        _ => Err(invalid("honest GP-MHAC detector rejected")),
    }
}
fn public_vector(c: &Config) -> Vec<Fr> {
    let mut attrs = vec![Fr::zero(); c.params.h.len()];
    for &(i, v) in &c.pub_attrs {
        attrs[i] = v
    }
    attrs
}
fn revealed(c: &Config) -> Vec<(usize, Fr)> {
    c.pub_attrs
        .iter()
        .copied()
        .filter(|(i, _)| c.rev.binary_search(i).is_ok())
        .collect()
}

/// Derive the aggregate or per-holder bases from this request's signed factors.
fn mhac_bases(
    mut early: Step2Output,
    base: G1Projective,
    coeff: &[(usize, Fr)],
    factors: &[(G1Projective, Signature)],
    r: Fr,
    individual: bool,
) -> Step2Output {
    let mut b = base;
    for (k, (&(id, l), (d, _))) in coeff.iter().zip(factors).enumerate() {
        if individual {
            let v = if k == 0 {
                ops::g1_mul(&(base + ops::g1_mul(d, &l)), &r)
            } else {
                ops::g1_mul(d, &(r * l))
            };
            early.b_tilde.push((id, v));
        } else {
            b += ops::g1_mul(d, &l);
        }
    }
    early.b_bar = if individual {
        early
            .b_tilde
            .iter()
            .fold(G1Projective::zero(), |a, (_, d)| a + d)
    } else {
        ops::g1_mul(&b, &r)
    };
    early
}
fn mhac_request(
    stream: &mut TcpStream,
    c: &Config,
    share: &MhacShare,
    active: &[usize],
    nonce: [u8; 32],
) -> io::Result<f::MhacPresentation> {
    let credential = &share.credential;
    let coeff = c
        .access
        .lsss
        .recon_coeffs(active)
        .ok_or_else(|| invalid("unauthorized"))?;
    let primary = active[0];
    let mut rng = OsRng;
    let initial = if c.id == primary {
        Some(payload(|w| w.serializable(&f::step1_primary(&mut rng))))
    } else {
        None
    };
    let r: Fr = exchange(stream, &active[..1], initial, |sender, r| {
        check(sender == primary, "Step1 sender")?;
        r.canonical()
    })?
    .pop()
    .ok_or_else(|| invalid("missing r"))?;
    check(!r.is_zero(), "zero randomizer")?;
    // Bind the signed factor to the credential, public bases and selection; one digest per role.
    let digest = issuance::credential_digest(&c.params, &c.ipk.x2, &credential.a_sig, &c.pub_attrs);
    let revealed = revealed(c);
    let attrs = public_vector(c);
    let (mut base, mut cr) = (c.params.g1, c.params.g1);
    for &(i, v) in &c.pub_attrs {
        let h = ops::g1_mul(&c.params.h[i], &v);
        base += h;
        if c.rev.binary_search(&i).is_ok() {
            cr += h;
        }
    }
    let role = Step2Output {
        holder: c.id,
        a_bar: ops::g1_mul(&credential.a_sig, &r),
        b_bar: G1Projective::zero(),
        c_revealed: cr,
        b_tilde: vec![],
    };
    let (cm, state) = f::step3_commit(
        &c.params, credential, &role, &c.prv, &c.rev, primary, CONTEXT, nonce, &mut rng,
    )
    .expect("honest MHAC commitment");
    let packets = exchange(
        stream,
        active,
        Some(payload(|w| {
            encode_mhac_commitment(w, &cm);
            w.serializable(&share.d);
            encode_signature(w, &share.sig)
        })),
        |id, r| {
            let com = decode_mhac_commitment(r)?;
            check(id == com.holder, "com sender")?;
            Ok((com, (r.canonical()?, decode_signature(r)?)))
        },
    )?;
    let (coms, factors): (Vec<_>, Vec<_>) = packets.into_iter().unzip();
    let invalid_certs = || {
        active
            .iter()
            .zip(&factors)
            .filter_map(|(&id, (d, sig))| {
                (id != c.id && !issuance::verify_bound_factor(&digest, d, sig, &c.ipk.auth_pk))
                    .then_some(id)
            })
            .collect::<Vec<_>>()
    };
    let detail_start = role.clone();
    let role = mhac_bases(role, base, &coeff, &factors, r, false);
    let opens = exchange(
        stream,
        active,
        Some(payload(|w| encode_mhac_opening(w, &f::step4_open(&state)))),
        |id, r| {
            let x = decode_mhac_opening(r)?;
            check(x.holder == id, "open sender")?;
            Ok(x)
        },
    )?;
    check(
        f::step5_check_commitments(c.id, active, &coms, &opens, CONTEXT, nonce).is_empty(),
        "bad opening before response",
    )?;
    let z = f::step6_respond(
        credential, &state, &role, &attrs, &c.prv, &coeff, primary, r, &opens, &revealed, CONTEXT,
        nonce,
    )
    .expect("honest MHAC response");
    let hidden: Vec<_> = (0..attrs.len())
        .filter(|i| c.rev.binary_search(i).is_err())
        .collect();
    let other: Vec<_> = hidden
        .iter()
        .copied()
        .filter(|i| c.prv.binary_search(i).is_err())
        .collect();
    // Neither holder index, attribute indices nor challenge is a cryptographic payload.
    // Socket authenticates sender; slot layout and local challenge are implicit.
    let response = payload(|w| {
        w.serializable(&z.z_e);
        for (_, v) in &z.z_prv {
            w.serializable(v)
        }
        if let Some(v) = z.z_r {
            w.serializable(&v)
        }
        for (_, v) in &z.z_other {
            w.serializable(v)
        }
    });
    let responses = exchange(stream, active, Some(response), |id, r| {
        let z_e = r.canonical()?;
        let z_prv = c
            .prv
            .iter()
            .map(|&i| Ok((i, r.canonical()?)))
            .collect::<io::Result<_>>()?;
        let (z_r, z_other) = if id == primary {
            (
                Some(r.canonical()?),
                other
                    .iter()
                    .map(|&i| Ok((i, r.canonical()?)))
                    .collect::<io::Result<_>>()?,
            )
        } else {
            (None, vec![])
        };
        Ok(Step6Response {
            holder: id,
            ch: z.ch,
            z_e,
            z_prv,
            z_r,
            z_other,
        })
    })?;
    let proof =
        f::assemble(&role, &responses, &hidden, &c.prv, primary).expect("honest MHAC assembly");
    if !f::mhac_verify(&c.params, &c.ipk.x2, &proof, &revealed, CONTEXT, nonce) {
        // Reject failed aggregates after checking certificates and individual response equations.
        let certs = invalid_certs();
        let detail = mhac_bases(detail_start, base, &coeff, &factors, r, true);
        let equations = f::step7_check_responses(
            c.id, &c.params, active, primary, &c.prv, &c.rev, &detail, &opens, &responses,
        );
        return Err(invalid(format!(
            "MHAC verification failed; invalid certs={certs:?}, equations={equations:?}"
        )));
    }
    Ok(proof)
}
fn worker(addr: &str, id: usize) -> io::Result<()> {
    let mut s = TcpStream::connect(addr)?;
    s.set_nodelay(true)?;
    s.set_read_timeout(Some(Duration::from_secs(600)))?;
    s.set_write_timeout(Some(Duration::from_secs(600)))?;
    write_frame(
        &mut s,
        &payload(|w| {
            w.usize(id);
            w.u64(u64::from(std::process::id()));
        }),
    )?;
    let c = read_config(&read_frame(&mut s)?)?;
    check(id == c.id, "wrong credential routing")?;
    write_frame(&mut s, b"READY")?;
    loop {
        let request = read_frame(&mut s)?;
        if request == b"STOP" {
            return Ok(());
        }
        let mut reader = Reader::new(&request);
        let nonce = reader.fixed32()?;
        let active = decode_usize_vec(&mut reader)?;
        reader.end()?;
        check(
            valid_committee(&active, c.access.lsss.rho.len()) && active.binary_search(&id).is_ok(),
            "incorrect threshold request",
        )?;
        match &c.own {
            LocalCredential::Gp(pc) => {
                gp_request(&mut s, &c, pc, &active, nonce)?;
            }
            LocalCredential::Mhac(share) => {
                mhac_request(&mut s, &c, share, &active, nonce)?;
            }
        }
        write_frame(&mut s, b"RELEASED")?;
        check(
            read_frame(&mut s)? == b"AUDIT",
            "missing synchronization fence",
        )?;
        write_frame(&mut s, b"READY")?;
    }
}
#[derive(Clone, Copy)]
struct Model {
    rtt_ms: f64,
    mbps: f64,
}
impl Model {
    fn wait(&self, bytes: usize) {
        if self.mbps == 0.0 {
            return;
        }
        let delay =
            Duration::from_secs_f64(self.rtt_ms * 1e-3 + bytes as f64 * 8.0 / (self.mbps * 1e6));
        let start = Instant::now();
        let guard = Duration::from_millis(5);
        if delay > guard {
            thread::sleep(delay - guard);
        }
        while start.elapsed() < delay {
            std::hint::spin_loop();
        }
    }
}
struct Peer {
    id: usize,
    s: TcpStream,
    child: WorkerProcess,
}

struct WorkerProcess(Child);

impl Drop for WorkerProcess {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

fn valid_committee(active: &[usize], n: usize) -> bool {
    !active.is_empty()
        && active.len() == n / 2
        && active.windows(2).all(|a| a[0] < a[1])
        && active[active.len() - 1] < n
}

/// Select authenticated connections without renumbering their holders.
fn active_workers<'a, T>(
    pool: &'a mut [T],
    active: &[usize],
    id: impl Fn(&T) -> usize,
) -> io::Result<Vec<&'a mut T>> {
    check(valid_committee(active, pool.len()), "bad active set")?;
    let selected: Vec<_> = pool
        .iter_mut()
        .filter(|p| active.binary_search(&id(p)).is_ok())
        .collect();
    check(
        selected.iter().map(|p| id(p)).eq(active.iter().copied()),
        "missing or misrouted holder",
    )?;
    Ok(selected)
}

fn start(scheme: &str, n: usize) -> io::Result<Vec<Peer>> {
    let mut packets = configs(scheme, n)?;
    let l = TcpListener::bind("127.0.0.1:0")?;
    l.set_nonblocking(true)?;
    let addr = l.local_addr()?.to_string();
    let mut children = Vec::new();
    for id in 0..n {
        children.push(Some(WorkerProcess(
            Command::new(env::current_exe()?)
                .args(["child", &addr, &id.to_string()])
                .spawn()?,
        )));
    }
    let mut peers = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(600);
    for _ in 0..n {
        let (mut s, _) = loop {
            match l.accept() {
                Ok(pair) => break pair,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    for child in children.iter_mut().flatten() {
                        if let Some(status) = child.0.try_wait()? {
                            return Err(invalid(format!(
                                "holder {} exited before init: {status}",
                                child.0.id()
                            )));
                        }
                    }
                    if Instant::now() >= deadline {
                        return Err(invalid("holder initialization timed out"));
                    }
                    thread::sleep(Duration::from_millis(5));
                }
                Err(e) => return Err(e),
            }
        };
        s.set_nonblocking(false)?;
        s.set_nodelay(true)?;
        s.set_read_timeout(Some(Duration::from_secs(600)))?;
        s.set_write_timeout(Some(Duration::from_secs(600)))?;
        let hello = read_frame(&mut s)?;
        let mut r = Reader::new(&hello);
        let id = r.usize()?;
        let pid = r.u64()?;
        r.end()?;
        let child = children
            .get_mut(id)
            .and_then(Option::take)
            .ok_or_else(|| invalid("bad child identifier"))?;
        check(u64::from(child.0.id()) == pid, "bad child PID")?;
        write_frame(&mut s, &std::mem::take(&mut packets[id]))?;
        check(read_frame(&mut s)? == b"READY", "init rejected")?;
        peers.push(Peer { id, s, child });
    }
    peers.sort_by_key(|p| p.id);
    Ok(peers)
}
fn all_send(peers: &mut [&mut Peer], message: &[u8]) -> io::Result<()> {
    for p in peers {
        write_frame(&mut p.s, message)?;
    }
    Ok(())
}
fn all_recv(peers: &mut [&mut Peer], message: &[u8]) -> io::Result<()> {
    for p in peers {
        check(read_frame(&mut p.s)? == message, "missing holder ACK")?;
    }
    Ok(())
}
fn round_bytes(gp: bool, t: usize) -> Vec<usize> {
    if gp {
        vec![
            t * (48 + 80 + 64),
            t * (5 * 48 + 32),
            7 * 48 + 2 * 32,
            t * 64,
            32 * (t * (4 + 1) + (8 - 4) + 2),
        ]
    } else {
        vec![
            32,
            t * (32 + 48 + 80),
            t * 48,
            32 * (t * (3 + 1) + (7 - 3) + 1),
        ]
    }
}
/// Time one authenticated presentation with emulated barrier delays.
fn timed_sample(
    pool: &mut [Peer],
    active: &[usize],
    gp: bool,
    model: Model,
    bytes: &[usize],
) -> io::Result<(f64, [f64; 5])> {
    let mut peers = active_workers(pool, active, |p| p.id)?;
    let t = peers.len();
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    let request = payload(|w| {
        w.fixed32(&nonce);
        encode_usize_vec(w, active)
    });
    let mut wait_ms = [0.; 5];
    let start = Instant::now();
    all_send(&mut peers, &request)?;
    for (k, &cost) in bytes.iter().enumerate() {
        let primary_only = (gp && k == 2) || (!gp && k == 0);
        let mut w = Writer::new();
        w.usize(if primary_only { 1 } else { t });
        for peer in peers.iter_mut().take(if primary_only { 1 } else { t }) {
            let m = read_frame(&mut peer.s)?;
            w.usize(peer.id);
            w.raw(&m);
        }
        if model.mbps != 0.0 {
            let barrier = Instant::now();
            model.wait(cost);
            wait_ms[k] = barrier.elapsed().as_secs_f64() * 1e3;
        } else {
            model.wait(cost);
        }
        all_send(&mut peers, &w.into_bytes())?;
    }
    all_recv(&mut peers, b"RELEASED")?;
    let ms = start.elapsed().as_secs_f64() * 1e3;
    all_send(&mut peers, b"AUDIT")?;
    all_recv(&mut peers, b"READY")?;
    Ok((ms, wait_ms))
}
/// Run all randomized, paired conditions; child mode serves one credential holder.
pub fn run() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.get(1).map(String::as_str) == Some("child") && args.len() == 4 {
        worker(&args[2], args[3].parse().map_err(invalid)?)
    } else {
        interleaved::campaign(&args[1..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_connections_retain_sparse_holder_ids_and_order() {
        let mut slots: Vec<_> = (0..6).map(|id| (id, 0)).collect();
        let mut recipients = active_workers(&mut slots, &[1, 3, 5], |s| s.0).unwrap();
        assert_eq!(recipients[0].0, 1);
        assert_eq!(recipients[1].0, 3);
        for p in &mut recipients {
            p.1 += 1;
        }
        assert_eq!(slots, vec![(0, 0), (1, 1), (2, 0), (3, 1), (4, 0), (5, 1)]);
        for bad in [&[0, 0, 1][..], &[5, 3, 1], &[1, 2, 6], &[1, 2]] {
            assert!(active_workers(&mut slots, bad, |s| s.0).is_err());
        }
        slots[5].0 = 3;
        assert!(active_workers(&mut slots, &[1, 3, 5], |s| s.0).is_err());
    }

    #[test]
    fn every_worker_receives_its_own_credential() {
        for scheme in ["gp-mhac", "mhac"] {
            let packets = configs(scheme, 6).unwrap();
            assert_eq!(packets.len(), 6);
            for (id, packet) in packets.iter().enumerate() {
                let c = read_config(packet).unwrap();
                assert_eq!(c.id, id);
                assert_eq!(c.access.lsss.rho.len(), 6);
                match c.own {
                    LocalCredential::Gp(share) => {
                        assert_eq!(share.rows.len(), 1);
                        assert_eq!(share.rows[0].index, id);
                    }
                    LocalCredential::Mhac(share) => assert_eq!(share.credential.holder, id),
                }
            }
        }
    }
}
