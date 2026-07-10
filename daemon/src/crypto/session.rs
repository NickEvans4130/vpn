//! Transport session: wraps a send/recv pair of symmetric ratchets and
//! encrypts each packet under its own single-use key. Adds constant-size
//! padding (before encryption) and sliding-window replay protection (on
//! decryption) on top of the ratchet's structural replay rejection.
//!
//! Wire format: `pkt_type(1) || seq(8, LE) || nonce(24) || ciphertext`.
//! `pkt_type` and `seq` are AEAD-associated data, not encrypted -- they
//! have to be readable before the packet key (which depends on `seq`)
//! can even be derived.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key as AeadKey, XChaCha20Poly1305, XNonce};

use super::noise::TransportKeys;
use super::padding::{self, DEFAULT_PAD_TARGET};
use super::ratchet::{Ratchet, ReceivingChain};
use super::replay::ReplayWindow;

/// How far ahead of the last-consumed sequence number the receiving
/// chain will derive and cache keys for, to tolerate reordering. Matches
/// the replay window's own size so the two limits agree.
const MAX_SKIP: u64 = super::replay::WINDOW_SIZE;

pub struct Session {
    send_chain: Ratchet,
    recv_chain: ReceivingChain,
    replay_window: ReplayWindow,
    send_seq: u64,
    pad_target: usize,
}

impl Session {
    pub fn new(keys: TransportKeys) -> Self {
        Self::with_pad_target(keys, DEFAULT_PAD_TARGET)
    }

    pub fn with_pad_target(keys: TransportKeys, pad_target: usize) -> Self {
        Session {
            send_chain: Ratchet::new(keys.send_key),
            recv_chain: ReceivingChain::new(keys.recv_key, MAX_SKIP),
            replay_window: ReplayWindow::new(),
            send_seq: 0,
            pad_target,
        }
    }

    /// Encrypt one packet of type `pkt_type`, padding the plaintext to a
    /// constant size first. Advances the send chain and the sequence
    /// counter.
    pub fn encrypt(&mut self, pkt_type: u8, plaintext: &[u8]) -> Vec<u8> {
        let seq = self.send_seq;
        self.send_seq += 1;

        let padded = padding::pad(plaintext, self.pad_target);
        let packet_key = self.send_chain.advance();
        let cipher = XChaCha20Poly1305::new(
            &AeadKey::try_from(packet_key.as_slice()).expect("32-byte key"),
        );

        let mut nonce_bytes = [0u8; 24];
        getrandom::fill(&mut nonce_bytes).expect("getrandom failure");
        let nonce = XNonce::try_from(nonce_bytes.as_slice()).expect("24-byte nonce");

        let aad = aad_bytes(pkt_type, seq);
        let ciphertext = cipher
            .encrypt(&nonce, Payload { msg: &padded, aad: &aad })
            .expect("session encryption");

        let mut out = Vec::with_capacity(1 + 8 + 24 + ciphertext.len());
        out.push(pkt_type);
        out.extend_from_slice(&seq.to_le_bytes());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        out
    }

    /// Decrypt one packet. Rejects replays via the sliding window before
    /// spending a ratchet key derivation on them, and rejects sequence
    /// numbers too far ahead of the last consumed one (bounded skip).
    pub fn decrypt(&mut self, wire: &[u8]) -> anyhow::Result<Vec<u8>> {
        if wire.len() < 1 + 8 + 24 {
            anyhow::bail!("packet too short to contain a header");
        }
        let pkt_type = wire[0];
        let seq = u64::from_le_bytes(wire[1..9].try_into().unwrap());
        let nonce_bytes = &wire[9..33];
        let ciphertext = &wire[33..];

        if !self.replay_window.check(seq) {
            anyhow::bail!("replayed or too-old sequence number: {seq}");
        }

        let packet_key = self
            .recv_chain
            .key_for_seq(seq)
            .ok_or_else(|| anyhow::anyhow!("sequence number {seq} out of range (too far ahead or already consumed)"))?;

        let cipher = XChaCha20Poly1305::new(
            &AeadKey::try_from(packet_key.as_slice()).expect("32-byte key"),
        );
        let nonce = XNonce::try_from(nonce_bytes).expect("24-byte nonce");
        let aad = aad_bytes(pkt_type, seq);

        let padded = cipher
            .decrypt(&nonce, Payload { msg: ciphertext, aad: &aad })
            .map_err(|_| anyhow::anyhow!("session decryption failed (auth tag mismatch)"))?;

        // Only commit to the replay window after authentication succeeds,
        // so a forged packet can't be used to probe window state.
        self.replay_window.commit(seq);

        Ok(padding::unpad(&padded)?.to_vec())
    }
}

fn aad_bytes(pkt_type: u8, seq: u64) -> [u8; 9] {
    let mut aad = [0u8; 9];
    aad[0] = pkt_type;
    aad[1..].copy_from_slice(&seq.to_le_bytes());
    aad
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::noise::{InitiatorHandshake, ResponderHandshake, StaticIdentity};

    fn handshake_pair() -> (Session, Session) {
        let initiator_id = StaticIdentity::generate();
        let responder_id = StaticIdentity::generate();

        let (init_hs, msg1) =
            InitiatorHandshake::start(&initiator_id, responder_id.public, &responder_id.kem_encap);
        let mut resp_hs = ResponderHandshake::new(&responder_id);
        resp_hs.read_message1(&msg1).unwrap();
        let (msg2, responder_keys) = resp_hs.write_message2().unwrap();
        let initiator_keys = init_hs.finish(msg2).unwrap();

        (Session::new(initiator_keys), Session::new(responder_keys))
    }

    #[test]
    fn round_trip_through_full_handshake() {
        let (mut init_session, mut resp_session) = handshake_pair();

        let plaintext = b"hello over the wire";
        let wire = init_session.encrypt(0x01, plaintext);
        let decrypted = resp_session.decrypt(&wire).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn packets_are_padded_to_constant_size() {
        let (mut init_session, _resp_session) = handshake_pair();
        let short = init_session.encrypt(0x01, b"x");
        let long = init_session.encrypt(0x01, &vec![7u8; 900]);
        assert_eq!(short.len(), long.len());
    }

    #[test]
    fn replayed_packet_is_rejected() {
        let (mut init_session, mut resp_session) = handshake_pair();

        let wire1 = init_session.encrypt(0x01, b"first");
        resp_session.decrypt(&wire1).unwrap();

        let replay_result = resp_session.decrypt(&wire1);
        assert!(replay_result.is_err());
    }

    #[test]
    fn reordered_packets_within_window_still_decrypt() {
        let (mut init_session, mut resp_session) = handshake_pair();

        let w0 = init_session.encrypt(0x01, b"zero");
        let w1 = init_session.encrypt(0x01, b"one");
        let w2 = init_session.encrypt(0x01, b"two");

        // Arrive out of order.
        assert_eq!(resp_session.decrypt(&w2).unwrap(), b"two");
        assert_eq!(resp_session.decrypt(&w0).unwrap(), b"zero");
        assert_eq!(resp_session.decrypt(&w1).unwrap(), b"one");

        // Any of them replayed again now fails.
        assert!(resp_session.decrypt(&w0).is_err());
    }

    #[test]
    fn many_packets_round_trip_in_order() {
        let (mut init_session, mut resp_session) = handshake_pair();
        for i in 0..500u32 {
            let plaintext = format!("packet {i}");
            let wire = init_session.encrypt(0x01, plaintext.as_bytes());
            let decrypted = resp_session.decrypt(&wire).unwrap();
            assert_eq!(decrypted, plaintext.as_bytes());
        }
    }
}
