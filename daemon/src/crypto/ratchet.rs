//! Symmetric per-packet ratchet: each packet gets its own AEAD key derived
//! from a chain key via HKDF, and the old chain key is zeroed immediately
//! after the next one is derived -- there is no retained key history, so a
//! captured packet key can't be used to derive any other packet's key in
//! either direction.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

pub struct Ratchet {
    chain_key: [u8; 32],
}

impl Ratchet {
    pub fn new(initial_chain_key: [u8; 32]) -> Self {
        Ratchet {
            chain_key: initial_chain_key,
        }
    }

    /// Advance the chain by one step: `chain_key_n+1, packet_key_n =
    /// HKDF(chain_key_n)`. The two outputs are domain-separated via HKDF
    /// info strings so neither can be derived from the other.
    pub fn advance(&mut self) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(Some(&self.chain_key), &[]);

        let mut next_chain_key = [0u8; 32];
        hk.expand(b"pqvpn-ratchet-chain-key", &mut next_chain_key)
            .expect("hkdf expand within limit");

        let mut packet_key = [0u8; 32];
        hk.expand(b"pqvpn-ratchet-packet-key", &mut packet_key)
            .expect("hkdf expand within limit");

        self.chain_key.zeroize();
        self.chain_key = next_chain_key;
        packet_key
    }
}

impl Drop for Ratchet {
    fn drop(&mut self) {
        self.chain_key.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn successive_packet_keys_are_distinct() {
        let mut r = Ratchet::new([7u8; 32]);
        let k1 = r.advance();
        let k2 = r.advance();
        let k3 = r.advance();
        assert_ne!(k1, k2);
        assert_ne!(k2, k3);
        assert_ne!(k1, k3);
    }

    #[test]
    fn two_ratchets_from_same_seed_stay_in_lockstep() {
        let mut a = Ratchet::new([42u8; 32]);
        let mut b = Ratchet::new([42u8; 32]);
        for _ in 0..1000 {
            assert_eq!(a.advance(), b.advance());
        }
    }
}
