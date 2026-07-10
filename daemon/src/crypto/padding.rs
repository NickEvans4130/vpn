//! Constant-size packet padding, applied before encryption so ciphertext
//! length doesn't leak the size of the underlying IP packet to a network
//! observer. Wire format is `[u16 LE actual length][payload][zero pad]`.

pub const DEFAULT_PAD_TARGET: usize = 1400;

/// Pad `plaintext` up to `target` bytes. If `plaintext` (plus the 2-byte
/// length prefix) is already larger than `target`, no padding is added --
/// the packet is sent at its natural size rather than truncated or
/// rejected outright.
pub fn pad(plaintext: &[u8], target: usize) -> Vec<u8> {
    let prefixed_len = plaintext.len() + 2;
    let total = prefixed_len.max(target);
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&(plaintext.len() as u16).to_le_bytes());
    out.extend_from_slice(plaintext);
    out.resize(total, 0);
    out
}

pub fn unpad(padded: &[u8]) -> anyhow::Result<&[u8]> {
    if padded.len() < 2 {
        anyhow::bail!("padded packet too short to contain a length prefix");
    }
    let len = u16::from_le_bytes([padded[0], padded[1]]) as usize;
    let body = &padded[2..];
    if len > body.len() {
        anyhow::bail!("padded packet length prefix exceeds packet size");
    }
    Ok(&body[..len])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pads_small_packets_to_target_size() {
        let padded = pad(b"hello", DEFAULT_PAD_TARGET);
        assert_eq!(padded.len(), DEFAULT_PAD_TARGET);
        assert_eq!(unpad(&padded).unwrap(), b"hello");
    }

    #[test]
    fn constant_size_regardless_of_payload_length() {
        let a = pad(b"x", DEFAULT_PAD_TARGET);
        let b = pad(&vec![7u8; 900], DEFAULT_PAD_TARGET);
        assert_eq!(a.len(), b.len());
    }

    #[test]
    fn oversized_payload_is_not_truncated() {
        let big = vec![9u8; DEFAULT_PAD_TARGET + 100];
        let padded = pad(&big, DEFAULT_PAD_TARGET);
        assert_eq!(unpad(&padded).unwrap(), big.as_slice());
    }

    #[test]
    fn empty_payload_round_trips() {
        let padded = pad(b"", DEFAULT_PAD_TARGET);
        assert_eq!(unpad(&padded).unwrap(), b"");
    }
}
