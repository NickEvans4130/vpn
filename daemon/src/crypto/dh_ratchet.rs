//! Periodic DH+KEM ratchet: re-runs a fresh hybrid X25519 + ML-KEM-768
//! exchange on a schedule (60s elapsed or 2^16 packets sent, whichever
//! comes first) and mixes the result into a persistent root key. This
//! gives post-compromise security -- an attacker who steals the current
//! symmetric ratchet chain loses that advantage at the next rekey,
//! without needing a full handshake.
//!
//! Unlike the initial Noise_IK handshake (where the responder's static
//! KEM key is known ahead of time), a periodic rekey has no pre-shared
//! KEM public key to encapsulate against -- so the exchange is
//! necessarily one asymmetric round trip: the initiator generates a
//! fresh ephemeral KEM keypair and offers its public half; the responder
//! encapsulates against it and answers with the ciphertext. Both sides
//! also exchange fresh X25519 ephemerals in the same messages, and the
//! root key is re-derived from `HKDF(root_key, dh || kem_secret)`.

use std::time::{Duration, Instant};

use hkdf::Hkdf;
use ml_kem::kem::{Decapsulate, Encapsulate, KeyExport};
use ml_kem::{Ciphertext, DecapsulationKey768, EncapsulationKey, Kem, MlKem768};
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

/// Sent initiator -> responder to start a rekey: a fresh X25519 ephemeral
/// and a fresh, single-use ML-KEM-768 encapsulation key.
pub struct RekeyOffer {
    pub x_pub: PublicKey,
    pub kem_ek_bytes: Vec<u8>,
}

/// Sent responder -> initiator to complete a rekey: the responder's own
/// fresh X25519 ephemeral, plus the ML-KEM-768 ciphertext encapsulated
/// against the initiator's offered key.
pub struct RekeyResponse {
    pub x_pub: PublicKey,
    pub kem_ciphertext: Vec<u8>,
}

/// Initiator-side state held between offering a rekey and receiving the
/// responder's answer.
pub struct PendingRekey {
    local_eph: ReusableSecret,
    kem_decap: DecapsulationKey768,
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

    /// Initiator side: start a rekey by generating a fresh X25519
    /// ephemeral and a fresh ML-KEM-768 keypair, offering the public
    /// halves of both to the peer.
    pub fn begin_rekey_as_initiator(&self) -> (RekeyOffer, PendingRekey) {
        let local_eph = ReusableSecret::random();
        let x_pub = PublicKey::from(&local_eph);
        let (kem_decap, kem_encap) = MlKem768::generate_keypair();
        let offer = RekeyOffer {
            x_pub,
            kem_ek_bytes: kem_encap.to_bytes().to_vec(),
        };
        (offer, PendingRekey { local_eph, kem_decap })
    }

    /// Initiator side: complete the rekey once the responder has replied.
    pub fn finish_rekey_as_initiator(
        &mut self,
        pending: PendingRekey,
        response: RekeyResponse,
    ) -> anyhow::Result<(Ratchet, Ratchet)> {
        let dh = pending.local_eph.diffie_hellman(&response.x_pub);
        let kem_ct = Ciphertext::<MlKem768>::try_from(response.kem_ciphertext.as_slice())
            .map_err(|_| anyhow::anyhow!("malformed ML-KEM-768 ciphertext in rekey response"))?;
        let kem_secret = pending.kem_decap.decapsulate(&kem_ct);

        Ok(self.mix_and_derive(dh.as_bytes(), &kem_secret))
    }

    /// Responder side: answer a rekey offer in one step -- generate a
    /// fresh X25519 ephemeral, encapsulate against the initiator's
    /// offered KEM key, mix both into the root key, and return the reply
    /// to send back alongside the freshly derived ratchet chains.
    pub fn respond_to_rekey(
        &mut self,
        offer: RekeyOffer,
    ) -> anyhow::Result<(RekeyResponse, Ratchet, Ratchet)> {
        let local_eph = ReusableSecret::random();
        let x_pub = PublicKey::from(&local_eph);
        let dh = local_eph.diffie_hellman(&offer.x_pub);

        let peer_kem_ek = EncapsulationKey::<MlKem768>::new(
            offer
                .kem_ek_bytes
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("malformed ML-KEM-768 encapsulation key in rekey offer"))?,
        )
        .map_err(|_| anyhow::anyhow!("invalid ML-KEM-768 encapsulation key in rekey offer"))?;
        let (kem_ciphertext, kem_secret) = peer_kem_ek.encapsulate();

        let (send, recv) = self.mix_and_derive(dh.as_bytes(), &kem_secret);
        let response = RekeyResponse {
            x_pub,
            kem_ciphertext: kem_ciphertext.to_vec(),
        };
        Ok((response, send, recv))
    }

    fn mix_and_derive(&mut self, dh: &[u8], kem_secret: &[u8]) -> (Ratchet, Ratchet) {
        let mut ikm = Vec::with_capacity(dh.len() + kem_secret.len());
        ikm.extend_from_slice(dh);
        ikm.extend_from_slice(kem_secret);

        let hk = Hkdf::<Sha256>::new(Some(&self.root_key), &ikm);
        ikm.zeroize();
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

        let (offer, pending) = initiator.begin_rekey_as_initiator();
        let (response, mut resp_send, mut resp_recv) =
            responder.respond_to_rekey(offer).expect("responder answers offer");
        let (mut init_send, mut init_recv) = initiator
            .finish_rekey_as_initiator(pending, response)
            .expect("initiator finishes rekey");

        assert_eq!(init_send.advance(), resp_recv.advance());
        assert_eq!(resp_send.advance(), init_recv.advance());
        assert_eq!(initiator.epoch(), 1);
        assert_eq!(responder.epoch(), 1);
    }

    #[test]
    fn rekey_resets_packet_counter_and_clears_threshold_trigger() {
        let seed = [9u8; 32];
        let mut initiator = DhRatchetState::new(
            seed,
            Role::Initiator,
            RatchetPolicy {
                interval: Duration::from_secs(3600),
                packet_threshold: 10,
            },
        );
        let mut responder = DhRatchetState::new(
            seed,
            Role::Responder,
            RatchetPolicy {
                interval: Duration::from_secs(3600),
                packet_threshold: 10,
            },
        );
        for _ in 0..10 {
            initiator.record_packet_sent();
        }
        assert!(initiator.should_rekey());

        let (offer, pending) = initiator.begin_rekey_as_initiator();
        let (response, _, _) = responder.respond_to_rekey(offer).unwrap();
        initiator.finish_rekey_as_initiator(pending, response).unwrap();

        assert_eq!(initiator.packets_since_rekey(), 0);
        assert!(!initiator.should_rekey());
    }

    /// Proves zeroization actually happens, not just that the key value
    /// changes. Constructs the state inside a `MaybeUninit` (storage that
    /// stays allocated and valid even after the value inside it is
    /// dropped), captures a raw pointer at the `root_key` field, calls
    /// `drop_in_place` (running `Drop`, which per its impl calls
    /// `.zeroize()` on `root_key`), and then reads that same location
    /// back and asserts every byte is zero. Unlike asserting "new key !=
    /// old key", which would pass even with no zeroization at all, this
    /// directly inspects the memory contents post-drop -- without ever
    /// reading through freed/deallocated memory, since `MaybeUninit`'s
    /// storage is never deallocated here.
    #[test]
    fn root_key_memory_is_actually_zeroized_on_drop() {
        let seed = [0x77u8; 32];
        let mut storage = std::mem::MaybeUninit::new(DhRatchetState::new(
            seed,
            Role::Initiator,
            RatchetPolicy::default(),
        ));
        // SAFETY: `storage` was just initialized via `MaybeUninit::new`.
        let ptr: *const u8 = unsafe { storage.assume_init_ref() }.root_key.as_ptr();
        unsafe {
            std::ptr::drop_in_place(storage.as_mut_ptr());
        }
        // SAFETY: `ptr` points into `storage`, which is still allocated
        // (it's a local `MaybeUninit`, not a `Box` that got freed). Only
        // the value inside was dropped via `drop_in_place`, so the bytes
        // `Drop::drop` last wrote there are still readable.
        let after = unsafe { std::slice::from_raw_parts(ptr, 32) };
        assert_eq!(after, &[0u8; 32], "root_key bytes were not zeroized on drop");
        assert_ne!(after, &seed[..], "sanity check: zeroized value differs from original seed");
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
