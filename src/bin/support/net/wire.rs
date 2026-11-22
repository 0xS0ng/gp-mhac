//! Length-framed loopback transport and canonical peer packet codecs.
use super::*;
pub(super) struct Writer {
    bytes: Vec<u8>,
}

impl Writer {
    pub(super) fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    pub(super) fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    pub(super) fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    pub(super) fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    pub(super) fn usize(&mut self, value: usize) {
        self.u64(value as u64);
    }

    pub(super) fn raw(&mut self, value: &[u8]) {
        self.usize(value.len());
        self.bytes.extend_from_slice(value);
    }

    pub(super) fn fixed32(&mut self, value: &[u8; 32]) {
        self.bytes.extend_from_slice(value);
    }

    pub(super) fn serializable<T: CanonicalSerialize>(&mut self, value: &T) {
        value
            .serialize_compressed(&mut self.bytes)
            .expect("Vec serialization cannot fail");
    }
}

pub(super) struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub(super) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    pub(super) fn take(&mut self, len: usize) -> io::Result<&'a [u8]> {
        if len > self.bytes.len().saturating_sub(self.pos) {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "short frame payload",
            ));
        }
        let out = &self.bytes[self.pos..self.pos + len];
        self.pos += len;
        Ok(out)
    }

    pub(super) fn u8(&mut self) -> io::Result<u8> {
        Ok(self.take(1)?[0])
    }

    pub(super) fn u64(&mut self) -> io::Result<u64> {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(self.take(8)?);
        Ok(u64::from_be_bytes(bytes))
    }

    pub(super) fn usize(&mut self) -> io::Result<usize> {
        usize::try_from(self.u64()?).map_err(|_| invalid("oversized integer"))
    }

    pub(super) fn count(&mut self) -> io::Result<usize> {
        let n = self.usize()?;
        check(
            n <= 1024 && n <= self.bytes.len() - self.pos,
            "oversized item count",
        )?;
        Ok(n)
    }

    pub(super) fn end(&self) -> io::Result<()> {
        check(self.pos == self.bytes.len(), "unexpected trailing fields")
    }

    pub(super) fn raw(&mut self) -> io::Result<Vec<u8>> {
        let len = self.usize()?;
        Ok(self.take(len)?.to_vec())
    }

    pub(super) fn fixed32(&mut self) -> io::Result<[u8; 32]> {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(self.take(32)?);
        Ok(bytes)
    }

    pub(super) fn canonical<T: CanonicalDeserialize>(&mut self) -> io::Result<T> {
        let mut slice = &self.bytes[self.pos..];
        let before = slice.len();
        let value = T::deserialize_compressed(&mut slice)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
        self.pos += before - slice.len();
        Ok(value)
    }
}

pub(super) fn write_frame(stream: &mut TcpStream, payload: &[u8]) -> io::Result<()> {
    stream.write_all(&(payload.len() as u64).to_be_bytes())?;
    stream.write_all(payload)?;
    stream.flush()
}

pub(super) fn read_frame(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut len_bytes = [0u8; 8];
    stream.read_exact(&mut len_bytes)?;
    let len =
        usize::try_from(u64::from_be_bytes(len_bytes)).map_err(|_| invalid("oversized frame"))?;
    check(len <= 2 * 1024 * 1024, "oversized frame")?;
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload)?;
    Ok(payload)
}

pub(super) fn encode_signature(writer: &mut Writer, signature: &Signature) {
    writer.serializable(&signature.commitment);
    writer.serializable(&signature.response);
}

pub(super) fn decode_signature(reader: &mut Reader<'_>) -> io::Result<Signature> {
    Ok(Signature {
        commitment: reader.canonical()?,
        response: reader.canonical()?,
    })
}

pub(super) fn encode_row(writer: &mut Writer, row: &Row) {
    writer.usize(row.index);
    writer.serializable(&row.e_share);
    writer.usize(row.prv_shares.len());
    for share in &row.prv_shares {
        writer.serializable(share);
    }
    writer.serializable(&row.d_factor);
    encode_signature(writer, &row.tag);
}

pub(super) fn decode_row(reader: &mut Reader<'_>) -> io::Result<Row> {
    let index = reader.usize()?;
    let e_share = reader.canonical()?;
    let share_count = reader.count()?;
    let mut prv_shares = Vec::with_capacity(share_count);
    for _ in 0..share_count {
        prv_shares.push(reader.canonical()?);
    }
    let d_factor = reader.canonical()?;
    let tag = decode_signature(reader)?;
    Ok(Row {
        index,
        e_share,
        prv_shares,
        d_factor,
        tag,
    })
}

pub(super) fn encode_precred(writer: &mut Writer, precredential: &PreCred) {
    writer.fixed32(&precredential.asid);
    writer.serializable(&precredential.a_sig);
    writer.usize(precredential.pub_attrs.len());
    for (index, value) in &precredential.pub_attrs {
        writer.usize(*index);
        writer.serializable(value);
    }
    writer.usize(precredential.rows.len());
    for row in &precredential.rows {
        encode_row(writer, row);
    }
}

pub(super) fn decode_precred(reader: &mut Reader<'_>) -> io::Result<PreCred> {
    let asid = reader.fixed32()?;
    let a_sig = reader.canonical()?;
    let pub_count = reader.count()?;
    let mut pub_attrs = Vec::with_capacity(pub_count);
    for _ in 0..pub_count {
        pub_attrs.push((reader.usize()?, reader.canonical()?));
    }
    let row_count = reader.count()?;
    let mut rows = Vec::with_capacity(row_count);
    for _ in 0..row_count {
        rows.push(decode_row(reader)?);
    }
    Ok(PreCred {
        asid,
        a_sig,
        pub_attrs,
        rows,
    })
}

pub(super) fn encode_mhac_credential(writer: &mut Writer, credential: &MhacCredential) {
    writer.usize(credential.holder);
    writer.serializable(&credential.a_sig);
    writer.serializable(&credential.e_share);
    encode_fr_vec(writer, &credential.prv_shares);
}

pub(super) fn decode_mhac_credential(reader: &mut Reader<'_>) -> io::Result<MhacCredential> {
    Ok(MhacCredential {
        holder: reader.usize()?,
        a_sig: reader.canonical()?,
        e_share: reader.canonical()?,
        prv_shares: decode_fr_vec(reader)?,
    })
}

pub(super) fn encode_mhac_commitment(writer: &mut Writer, commitment: &Step3Commitment) {
    writer.usize(commitment.holder);
    writer.fixed32(&commitment.commitment);
}

pub(super) fn decode_mhac_commitment(reader: &mut Reader<'_>) -> io::Result<Step3Commitment> {
    Ok(Step3Commitment {
        holder: reader.usize()?,
        commitment: reader.fixed32()?,
    })
}

pub(super) fn encode_mhac_opening(writer: &mut Writer, opening: &Step4Opening) {
    writer.usize(opening.holder);
    writer.serializable(&opening.u);
}

pub(super) fn decode_mhac_opening(reader: &mut Reader<'_>) -> io::Result<Step4Opening> {
    Ok(Step4Opening {
        holder: reader.usize()?,
        u: reader.canonical()?,
    })
}

pub(super) fn encode_params(writer: &mut Writer, params: &Parameters) {
    writer.serializable(&params.g1);
    writer.usize(params.h.len());
    for point in &params.h {
        writer.serializable(point);
    }
    writer.serializable(&params.g2);
}

pub(super) fn decode_params(reader: &mut Reader<'_>) -> io::Result<Parameters> {
    let g1 = reader.canonical()?;
    let count = reader.count()?;
    let mut h = Vec::with_capacity(count);
    for _ in 0..count {
        h.push(reader.canonical()?);
    }
    let g2 = reader.canonical()?;
    Ok(Parameters::from_parts(g1, h, g2))
}

pub(super) fn encode_usize_vec(writer: &mut Writer, values: &[usize]) {
    writer.usize(values.len());
    for value in values {
        writer.usize(*value);
    }
}

pub(super) fn decode_usize_vec(reader: &mut Reader<'_>) -> io::Result<Vec<usize>> {
    let count = reader.count()?;
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        values.push(reader.usize()?);
    }
    Ok(values)
}

pub(super) fn encode_fr_vec(writer: &mut Writer, values: &[Fr]) {
    writer.usize(values.len());
    for value in values {
        writer.serializable(value);
    }
}

pub(super) fn decode_fr_vec(reader: &mut Reader<'_>) -> io::Result<Vec<Fr>> {
    let count = reader.count()?;
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        values.push(reader.canonical()?);
    }
    Ok(values)
}

pub(super) fn encode_indexed_fr_vec(writer: &mut Writer, values: &[(usize, Fr)]) {
    writer.usize(values.len());
    for (index, value) in values {
        writer.usize(*index);
        writer.serializable(value);
    }
}

pub(super) fn decode_indexed_fr_vec(reader: &mut Reader<'_>) -> io::Result<Vec<(usize, Fr)>> {
    let count = reader.count()?;
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        values.push((reader.usize()?, reader.canonical()?));
    }
    Ok(values)
}

pub(super) fn encode_row_broadcast(writer: &mut Writer, row: &RowBroadcast) {
    writer.usize(row.index);
    writer.serializable(&row.d_factor);
    encode_signature(writer, &row.tag);
}

pub(super) fn decode_row_broadcast(reader: &mut Reader<'_>) -> io::Result<RowBroadcast> {
    Ok(RowBroadcast {
        index: reader.usize()?,
        d_factor: reader.canonical()?,
        tag: decode_signature(reader)?,
    })
}

pub(super) fn encode_round1_message(writer: &mut Writer, message: &Round1Message) {
    writer.usize(message.holder);
    writer.usize(message.rows.len());
    for row in &message.rows {
        encode_row_broadcast(writer, row);
    }
    writer.fixed32(&message.commitment);
    writer.fixed32(&message.seed_commitment);
}

pub(super) fn decode_round1_message(reader: &mut Reader<'_>) -> io::Result<Round1Message> {
    let holder = reader.usize()?;
    let row_count = reader.count()?;
    let mut rows = Vec::with_capacity(row_count);
    for _ in 0..row_count {
        rows.push(decode_row_broadcast(reader)?);
    }
    let commitment = reader.fixed32()?;
    let seed_commitment = reader.fixed32()?;
    Ok(Round1Message {
        holder,
        rows,
        commitment,
        seed_commitment,
    })
}

pub(super) fn encode_opening(writer: &mut Writer, opening: &Round1Opening) {
    writer.usize(opening.holder);
    writer.serializable(&opening.c_hat);
    writer.serializable(&opening.n);
    writer.serializable(&opening.v);
    writer.serializable(&opening.u_hat);
    writer.serializable(&opening.u_prime);
    writer.fixed32(&opening.randomness);
}

pub(super) fn decode_opening(reader: &mut Reader<'_>) -> io::Result<Round1Opening> {
    Ok(Round1Opening {
        holder: reader.usize()?,
        c_hat: reader.canonical()?,
        n: reader.canonical()?,
        v: reader.canonical()?,
        u_hat: reader.canonical()?,
        u_prime: reader.canonical()?,
        randomness: reader.fixed32()?,
    })
}

pub(super) fn encode_r3_msg(writer: &mut Writer, message: &Round3Message) {
    writer.serializable(&message.a_bar);
    writer.serializable(&message.b_bar);
    writer.serializable(&message.d);
    writer.serializable(&message.v_prime);
    writer.serializable(&message.lift.c);
    writer.serializable(&message.lift.z);
    writer.serializable(&message.u_i);
    writer.serializable(&message.u_ii);
    writer.serializable(&message.u_iii);
}

pub(super) fn decode_r3_msg(reader: &mut Reader<'_>) -> io::Result<Round3Message> {
    Ok(Round3Message {
        a_bar: reader.canonical()?,
        b_bar: reader.canonical()?,
        d: reader.canonical()?,
        v_prime: reader.canonical()?,
        lift: LiftProof {
            c: reader.canonical()?,
            z: reader.canonical()?,
        },
        u_i: reader.canonical()?,
        u_ii: reader.canonical()?,
        u_iii: reader.canonical()?,
    })
}

pub(super) fn encode_seed_opening(writer: &mut Writer, opening: &SeedOpening) {
    writer.usize(opening.holder);
    writer.fixed32(&opening.kappa);
    writer.fixed32(&opening.randomness);
}

pub(super) fn decode_seed_opening(reader: &mut Reader<'_>) -> io::Result<SeedOpening> {
    Ok(SeedOpening {
        holder: reader.usize()?,
        kappa: reader.fixed32()?,
        randomness: reader.fixed32()?,
    })
}

pub(super) fn round2_public(openings: &[Round1Opening]) -> Round2Public {
    Round2Public {
        c_prv: openings
            .iter()
            .fold(G1Projective::zero(), |sum, opening| sum + opening.c_hat),
        nym: openings
            .iter()
            .fold(G1Projective::zero(), |sum, opening| sum + opening.n),
    }
}

pub(super) fn encode_holder_response(writer: &mut Writer, response: &HolderResponse) {
    writer.usize(response.holder);
    writer.serializable(&response.z_e);
    encode_indexed_fr_vec(writer, &response.z_prv);
}

pub(super) fn decode_holder_response(reader: &mut Reader<'_>) -> io::Result<HolderResponse> {
    Ok(HolderResponse {
        holder: reader.usize()?,
        z_e: reader.canonical()?,
        z_prv: decode_indexed_fr_vec(reader)?,
    })
}

pub(super) fn encode_primary_response(writer: &mut Writer, response: &PrimaryResponse) {
    writer.serializable(&response.z_first_randomizer);
    writer.serializable(&response.z_r3);
    encode_indexed_fr_vec(writer, &response.z_other);
}

pub(super) fn decode_primary_response(reader: &mut Reader<'_>) -> io::Result<PrimaryResponse> {
    Ok(PrimaryResponse {
        z_first_randomizer: reader.canonical()?,
        z_r3: reader.canonical()?,
        z_other: decode_indexed_fr_vec(reader)?,
    })
}
