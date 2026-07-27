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

    /// Expose the raw chain key so a fresh receiving-side ratchet can be
    /// bootstrapped from a `Ratchet` produced elsewhere (e.g. the DH
    /// ratchet's rekey output), without duplicating chain-key derivation
    /// logic. Crate-internal only -- callers outside `crypto` should never
    /// need the raw bytes.
    pub(crate) fn chain_key(&self) -> [u8; 32] {
        self.chain_key
    }
}

impl Drop for Ratchet {
    fn drop(&mut self) {
        self.chain_key.zeroize();
    }
}

/// Wraps a receiving-side `Ratchet` with a bounded cache of "skipped"
/// packet keys, so packets can be decrypted slightly out of order (up to
/// `max_skip` positions ahead of the last consumed sequence number)
/// without losing the single-use-key property. Keys are removed from the
/// cache (and zeroized) the moment they're consumed or evicted, so at
/// most `max_skip` keys are ever retained -- there is still no long-term
/// key history.
pub struct ReceivingChain {
    ratchet: Ratchet,
    next_seq: u64,
    skipped: std::collections::BTreeMap<u64, [u8; 32]>,
    max_skip: u64,
}

impl ReceivingChain {
    pub fn new(chain_key: [u8; 32], max_skip: u64) -> Self {
        ReceivingChain {
            ratchet: Ratchet::new(chain_key),
            next_seq: 0,
            skipped: std::collections::BTreeMap::new(),
            max_skip,
        }
    }

    /// Return the packet key for `seq`, deriving forward and caching any
    /// intermediate keys as needed. Returns `None` if `seq` has already
    /// been consumed and evicted, or is further ahead than `max_skip`
    /// (a cheap guard against an attacker forcing unbounded key caching).
    pub fn key_for_seq(&mut self, seq: u64) -> Option<[u8; 32]> {
        if seq < self.next_seq {
            return self.skipped.remove(&seq);
        }
        if seq - self.next_seq > self.max_skip {
            return None;
        }
        while self.next_seq < seq {
            let key = self.ratchet.advance();
            self.skipped.insert(self.next_seq, key);
            self.next_seq += 1;
            while self.skipped.len() as u64 > self.max_skip {
                if let Some((&oldest, _)) = self.skipped.iter().next() {
                    if let Some(mut evicted) = self.skipped.remove(&oldest) {
                        evicted.zeroize();
                    }
                }
            }
        }
        let key = self.ratchet.advance();
        self.next_seq += 1;
        Some(key)
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

    #[test]
    fn receiving_chain_matches_sending_chain_in_order() {
        let mut send = Ratchet::new([1u8; 32]);
        let mut recv = ReceivingChain::new([1u8; 32], 64);
        for seq in 0..20u64 {
            let sent = send.advance();
            let got = recv.key_for_seq(seq).unwrap();
            assert_eq!(sent, got);
        }
    }

    #[test]
    fn receiving_chain_handles_reordering_within_skip_window() {
        let mut send = Ratchet::new([2u8; 32]);
        let expected: Vec<[u8; 32]> = (0..5).map(|_| send.advance()).collect();

        let mut recv = ReceivingChain::new([2u8; 32], 64);
        // Arrive out of order: 2, 0, 1, 4, 3.
        assert_eq!(recv.key_for_seq(2).unwrap(), expected[2]);
        assert_eq!(recv.key_for_seq(0).unwrap(), expected[0]);
        assert_eq!(recv.key_for_seq(1).unwrap(), expected[1]);
        assert_eq!(recv.key_for_seq(4).unwrap(), expected[4]);
        assert_eq!(recv.key_for_seq(3).unwrap(), expected[3]);
    }

    #[test]
    fn receiving_chain_rejects_key_reuse_after_consumption() {
        let mut recv = ReceivingChain::new([3u8; 32], 64);
        recv.key_for_seq(0).unwrap();
        assert!(recv.key_for_seq(0).is_none());
    }

    #[test]
    fn receiving_chain_rejects_jump_beyond_max_skip() {
        let mut recv = ReceivingChain::new([4u8; 32], 8);
        assert!(recv.key_for_seq(100).is_none());
    }
}
