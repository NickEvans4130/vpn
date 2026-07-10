//! Transport session: wraps a send/recv pair of symmetric ratchets and
//! encrypts each packet under its own single-use key. The 192-bit nonce
//! is still randomized per packet (not a counter) as defense-in-depth --
//! even though packet keys are already unique, a nonce collision under
//! key reuse would be catastrophic for Poly1305, so we don't rely on the
//! ratchet alone to guarantee nonce uniqueness.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key as AeadKey, XChaCha20Poly1305, XNonce};

use super::noise::TransportKeys;
use super::ratchet::Ratchet;

pub struct Session {
    send_chain: Ratchet,
    recv_chain: Ratchet,
    send_seq: u64,
}

impl Session {
    pub fn new(keys: TransportKeys) -> Self {
        Session {
            send_chain: Ratchet::new(keys.send_key),
            recv_chain: Ratchet::new(keys.recv_key),
            send_seq: 0,
        }
    }

    /// Encrypt one packet. Advances the send chain, so this must be
    /// called at most once per packet and packets must be delivered (or
    /// at least the ratchet advanced) in the same order on both ends --
    /// out-of-order delivery is handled by the replay window added in a
    /// later milestone.
    pub fn encrypt(&mut self, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let packet_key = self.send_chain.advance();
        let cipher = XChaCha20Poly1305::new(
            &AeadKey::try_from(packet_key.as_slice()).expect("32-byte key"),
        );

        let mut nonce_bytes = [0u8; 24];
        getrandom::fill(&mut nonce_bytes).expect("getrandom failure");
        let nonce = XNonce::try_from(nonce_bytes.as_slice()).expect("24-byte nonce");

        let ciphertext = cipher
            .encrypt(&nonce, Payload { msg: plaintext, aad })
            .expect("session encryption");

        self.send_seq += 1;

        let mut out = Vec::with_capacity(24 + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        out
    }

    /// Decrypt one packet. Advances the recv chain.
    pub fn decrypt(&mut self, aad: &[u8], wire: &[u8]) -> anyhow::Result<Vec<u8>> {
        if wire.len() < 24 {
            anyhow::bail!("packet too short to contain a nonce");
        }
        let (nonce_bytes, ciphertext) = wire.split_at(24);
        let packet_key = self.recv_chain.advance();
        let cipher = XChaCha20Poly1305::new(
            &AeadKey::try_from(packet_key.as_slice()).expect("32-byte key"),
        );
        let nonce = XNonce::try_from(nonce_bytes).expect("24-byte nonce");
        cipher
            .decrypt(&nonce, Payload { msg: ciphertext, aad })
            .map_err(|_| anyhow::anyhow!("session decryption failed (auth tag mismatch)"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::noise::{InitiatorHandshake, ResponderHandshake, StaticIdentity};

    fn handshake_pair() -> (Session, Session) {
        let initiator_id = StaticIdentity::generate();
        let responder_id = StaticIdentity::generate();

        let (init_hs, msg1) = InitiatorHandshake::start(&initiator_id, responder_id.public);
        let mut resp_hs = ResponderHandshake::new(&responder_id);
        resp_hs.read_message1(&msg1).unwrap();
        let (msg2, responder_keys) = resp_hs.write_message2().unwrap();
        let initiator_keys = init_hs.finish(msg2).unwrap();

        (Session::new(initiator_keys), Session::new(responder_keys))
    }

    #[test]
    fn round_trip_through_full_handshake() {
        let (mut init_session, mut resp_session) = handshake_pair();

        let aad = b"pkt-type=data,seq=0";
        let plaintext = b"hello over the wire";
        let wire = init_session.encrypt(aad, plaintext);
        let decrypted = resp_session.decrypt(aad, &wire).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn each_packet_uses_a_distinct_key_so_replay_fails_auth() {
        let (mut init_session, mut resp_session) = handshake_pair();

        let aad = b"pkt";
        let wire1 = init_session.encrypt(aad, b"first");
        let decrypted1 = resp_session.decrypt(aad, &wire1).unwrap();
        assert_eq!(decrypted1, b"first");

        // Replaying the same ciphertext again fails: the recv chain has
        // already advanced past the key that produced wire1.
        let replay_result = resp_session.decrypt(aad, &wire1);
        assert!(replay_result.is_err());
    }

    #[test]
    fn many_packets_round_trip_in_order() {
        let (mut init_session, mut resp_session) = handshake_pair();
        for i in 0..500u32 {
            let aad = i.to_le_bytes();
            let plaintext = format!("packet {i}");
            let wire = init_session.encrypt(&aad, plaintext.as_bytes());
            let decrypted = resp_session.decrypt(&aad, &wire).unwrap();
            assert_eq!(decrypted, plaintext.as_bytes());
        }
    }
}
