//! Obfuscation layer: wraps an already-encrypted wire packet in a header
//! that looks like a DTLS 1.2 record, so passive DPI heuristics that
//! classify traffic by leading bytes see something that looks like
//! ordinary DTLS application data rather than an unrecognized protocol.
//!
//! This is deliberately cheap disguise, not protocol emulation -- our
//! payload is already uniformly random-looking ciphertext (which is
//! itself consistent with a DTLS record body), so the only thing left to
//! fake is the record header. A determined active prober (one that
//! actually speaks DTLS back at us) would unmask this immediately; the
//! goal here is defeating byte-pattern/heuristic classifiers, which is
//! what most DPI-based VPN blocking in practice relies on.
//!
//! DTLS 1.2 record header (RFC 6347 §4.1): `ContentType(1) |
//! ProtocolVersion(2) | Epoch(2) | SequenceNumber(6) | Length(2)`.

const DTLS_CONTENT_TYPE_APPLICATION_DATA: u8 = 23;
const DTLS_1_2_VERSION: [u8; 2] = [0xfe, 0xfd];
const HEADER_LEN: usize = 1 + 2 + 2 + 6 + 2;

pub struct Obfuscator {
    enabled: bool,
    epoch: u16,
}

impl Obfuscator {
    pub fn new(enabled: bool) -> Self {
        Obfuscator { enabled, epoch: 0 }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Wrap `wire` (an already-encrypted session packet) in a fake DTLS
    /// record header, or pass it through unchanged if obfuscation is
    /// disabled. `record_seq` is the DTLS-record-layer sequence number
    /// (distinct from our own transport sequence number, which is
    /// already carried inside `wire`) -- it only needs to look plausible.
    pub fn wrap(&self, wire: &[u8], record_seq: u64) -> Vec<u8> {
        if !self.enabled {
            return wire.to_vec();
        }
        let mut out = Vec::with_capacity(HEADER_LEN + wire.len());
        out.push(DTLS_CONTENT_TYPE_APPLICATION_DATA);
        out.extend_from_slice(&DTLS_1_2_VERSION);
        out.extend_from_slice(&self.epoch.to_be_bytes());
        // 48-bit big-endian record sequence number.
        out.extend_from_slice(&record_seq.to_be_bytes()[2..]);
        out.extend_from_slice(&(wire.len() as u16).to_be_bytes());
        out.extend_from_slice(wire);
        out
    }

    /// Strip the fake DTLS header, or pass through unchanged if
    /// obfuscation is disabled.
    pub fn unwrap<'a>(&self, framed: &'a [u8]) -> anyhow::Result<&'a [u8]> {
        if !self.enabled {
            return Ok(framed);
        }
        if framed.len() < HEADER_LEN {
            anyhow::bail!("framed packet too short to contain a DTLS-shaped header");
        }
        if framed[0] != DTLS_CONTENT_TYPE_APPLICATION_DATA {
            anyhow::bail!("unexpected content type in obfuscated packet");
        }
        let length = u16::from_be_bytes([framed[11], framed[12]]) as usize;
        let body = &framed[HEADER_LEN..];
        if length != body.len() {
            anyhow::bail!("length field in obfuscated header doesn't match packet size");
        }
        Ok(body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_when_enabled() {
        let obf = Obfuscator::new(true);
        let wire = b"pretend-this-is-ciphertext";
        let framed = obf.wrap(wire, 42);
        assert_eq!(obf.unwrap(&framed).unwrap(), wire);
    }

    #[test]
    fn wrapped_packet_starts_with_dtls_looking_header() {
        let obf = Obfuscator::new(true);
        let framed = obf.wrap(b"payload", 1);
        assert_eq!(framed[0], DTLS_CONTENT_TYPE_APPLICATION_DATA);
        assert_eq!(&framed[1..3], &DTLS_1_2_VERSION);
    }

    #[test]
    fn passthrough_when_disabled() {
        let obf = Obfuscator::new(false);
        let wire = b"raw session packet";
        let framed = obf.wrap(wire, 0);
        assert_eq!(framed, wire);
        assert_eq!(obf.unwrap(&framed).unwrap(), wire);
    }

    #[test]
    fn rejects_tampered_length_field() {
        let obf = Obfuscator::new(true);
        let mut framed = obf.wrap(b"payload", 5);
        framed[11] = 0xff;
        framed[12] = 0xff;
        assert!(obf.unwrap(&framed).is_err());
    }
}
