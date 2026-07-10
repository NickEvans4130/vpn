//! Periodic DH ratchet: re-runs a fresh ephemeral X25519 exchange on a
//! schedule (60s elapsed or 2^16 packets sent, whichever comes first) and
//! mixes the result into a persistent root key. This gives
//! post-compromise security -- an attacker who steals the current
//! symmetric ratchet chain loses that advantage at the next rekey, without
//! needing a full handshake. ML-KEM-768 gets folded into the same
//! `finish_rekey` mix once the hybrid PQ milestone lands; the wire
//! protocol and root-key mixing are already shaped for that so the swap
//! doesn't require restructuring this module.

use std::time::{Duration, Instant};

use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, ReusableSecret};
use zeroize::Zeroize;

use super::ratchet::Ratchet;

pub const DEFAULT_REKEY_INTERVAL: Duration = Duration::from_secs(60);
pub const DEFAULT_REKEY_PACKET_THRESHOLD: u32 = 1 << 16;

/// Which side of the original handshake this peer played -- determines
/// how the two ratchet outputs (k1, k2) are assigned to send/recv, same
/// convention as the initial Noise split().
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Initiator,
    Responder,
}

pub struct RatchetPolicy {
    pub interval: Duration,
    pub packet_threshold: u32,
}

impl Default for RatchetPolicy {
    fn default() -> Self {
        RatchetPolicy {
            interval: DEFAULT_REKEY_INTERVAL,
            packet_threshold: DEFAULT_REKEY_PACKET_THRESHOLD,
        }
    }
}

pub struct DhRatchetState {
    root_key: [u8; 32],
    role: Role,
    policy: RatchetPolicy,
    epoch: u64,
    packets_since_rekey: u32,
    last_rekey: Instant,
}

/// A rekey exchange in progress: our fresh ephemeral has been generated
/// and its public half sent to the peer; waiting on theirs.
pub struct PendingRekey {
    local_eph: ReusableSecret,
}

impl DhRatchetState {
    pub fn new(root_key: [u8; 32], role: Role, policy: RatchetPolicy) -> Self {
        DhRatchetState {
            root_key,
            role,
            policy,
            epoch: 0,
            packets_since_rekey: 0,
            last_rekey: Instant::now(),
        }
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn packets_since_rekey(&self) -> u32 {
        self.packets_since_rekey
    }

    pub fn record_packet_sent(&mut self) {
        self.packets_since_rekey += 1;
    }

    pub fn should_rekey(&self) -> bool {
        self.packets_since_rekey >= self.policy.packet_threshold
            || self.last_rekey.elapsed() >= self.policy.interval
    }

    /// Start a rekey: generate a fresh ephemeral keypair, return the
    /// public half to send to the peer alongside a handle to finish once
    /// the peer's ephemeral arrives.
    pub fn begin_rekey(&self) -> (PublicKey, PendingRekey) {
        let local_eph = ReusableSecret::random();
        let local_pub = PublicKey::from(&local_eph);
        (local_pub, PendingRekey { local_eph })
    }

    /// Complete a rekey once the peer's ephemeral public key is known.
    /// Mixes the fresh DH output into the root key and derives new
    /// send/recv ratchet chains, zeroing the old root key immediately.
    pub fn finish_rekey(
        &mut self,
        pending: PendingRekey,
        peer_eph_pub: PublicKey,
    ) -> (Ratchet, Ratchet) {
        let dh = pending.local_eph.diffie_hellman(&peer_eph_pub);

        let hk = Hkdf::<Sha256>::new(Some(&self.root_key), dh.as_bytes());
        let mut okm = [0u8; 96];
        hk.expand(&[], &mut okm).expect("hkdf expand within limit");

        let mut new_root = [0u8; 32];
        let mut k1 = [0u8; 32];
        let mut k2 = [0u8; 32];
        new_root.copy_from_slice(&okm[..32]);
        k1.copy_from_slice(&okm[32..64]);
        k2.copy_from_slice(&okm[64..]);
        okm.zeroize();

        self.root_key.zeroize();
        self.root_key = new_root;
        self.epoch += 1;
        self.packets_since_rekey = 0;
        self.last_rekey = Instant::now();

        match self.role {
            Role::Initiator => (Ratchet::new(k1), Ratchet::new(k2)),
            Role::Responder => (Ratchet::new(k2), Ratchet::new(k1)),
        }
    }
}

impl Drop for DhRatchetState {
    fn drop(&mut self) {
        self.root_key.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_sides_derive_matching_crossed_chains() {
        let seed = [3u8; 32];
        let mut initiator = DhRatchetState::new(seed, Role::Initiator, RatchetPolicy::default());
        let mut responder = DhRatchetState::new(seed, Role::Responder, RatchetPolicy::default());

        let (init_pub, init_pending) = initiator.begin_rekey();
        let (resp_pub, resp_pending) = responder.begin_rekey();

        let (mut init_send, mut init_recv) = initiator.finish_rekey(init_pending, resp_pub);
        let (mut resp_send, mut resp_recv) = responder.finish_rekey(resp_pending, init_pub);

        assert_eq!(init_send.advance(), resp_recv.advance());
        assert_eq!(resp_send.advance(), init_recv.advance());
        assert_eq!(initiator.epoch(), 1);
        assert_eq!(responder.epoch(), 1);
    }

    #[test]
    fn rekey_resets_packet_counter_and_clears_threshold_trigger() {
        let mut state = DhRatchetState::new(
            [9u8; 32],
            Role::Initiator,
            RatchetPolicy {
                interval: Duration::from_secs(3600),
                packet_threshold: 10,
            },
        );
        for _ in 0..10 {
            state.record_packet_sent();
        }
        assert!(state.should_rekey());

        let (pub_key, pending) = state.begin_rekey();
        state.finish_rekey(pending, pub_key);

        assert_eq!(state.packets_since_rekey(), 0);
        assert!(!state.should_rekey());
    }

    #[test]
    fn time_threshold_triggers_independent_of_packet_count() {
        let state = DhRatchetState::new(
            [1u8; 32],
            Role::Initiator,
            RatchetPolicy {
                interval: Duration::from_millis(0),
                packet_threshold: DEFAULT_REKEY_PACKET_THRESHOLD,
            },
        );
        assert!(state.should_rekey());
    }
}
