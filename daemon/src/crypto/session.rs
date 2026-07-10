//! Single-session AEAD transport, built on the transport keys produced by
//! the Noise_IK handshake. This is a placeholder for the full symmetric
//! ratchet (per-packet keys) that replaces it in the next build step --
//! for now, one fixed key is used for the whole session with a counter
//! nonce, purely to prove the handshake -> transport path end to end.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key as AeadKey, XChaCha20Poly1305, XNonce};
use zeroize::Zeroize;

use super::noise::TransportKeys;

pub struct Session {
    send_key: [u8; 32],
    recv_key: [u8; 32],
    send_counter: u64,
}

impl Session {
    pub fn new(keys: TransportKeys) -> Self {
        let session = Session {
            send_key: keys.send_key,
            recv_key: keys.recv_key,
            send_counter: 0,
        };
        session
    }

    /// Encrypt one packet. Returns `nonce || ciphertext`; the nonce is
    /// carried alongside the ciphertext since XChaCha20's 192-bit nonce
    /// is too large to reconstruct purely from a wire sequence number.
    pub fn encrypt(&mut self, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let cipher = XChaCha20Poly1305::new(&AeadKey::try_from(self.send_key.as_slice()).expect("32-byte key"));
        let mut nonce_bytes = [0u8; 24];
        nonce_bytes[..8].copy_from_slice(&self.send_counter.to_le_bytes());
        self.send_counter += 1;
        let nonce = XNonce::try_from(nonce_bytes.as_slice()).expect("24-byte nonce");
        let ciphertext = cipher
            .encrypt(&nonce, Payload { msg: plaintext, aad })
            .expect("session encryption");
        let mut out = Vec::with_capacity(24 + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        out
    }

    pub fn decrypt(&self, aad: &[u8], wire: &[u8]) -> anyhow::Result<Vec<u8>> {
        if wire.len() < 24 {
            anyhow::bail!("packet too short to contain a nonce");
        }
        let (nonce_bytes, ciphertext) = wire.split_at(24);
        let cipher = XChaCha20Poly1305::new(&AeadKey::try_from(self.recv_key.as_slice()).expect("32-byte key"));
        let nonce = XNonce::try_from(nonce_bytes).expect("24-byte nonce");
        cipher
            .decrypt(&nonce, Payload { msg: ciphertext, aad })
            .map_err(|_| anyhow::anyhow!("session decryption failed (auth tag mismatch)"))
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.send_key.zeroize();
        self.recv_key.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::noise::{InitiatorHandshake, ResponderHandshake, StaticIdentity};

    #[test]
    fn round_trip_through_full_handshake() {
        let initiator_id = StaticIdentity::generate();
        let responder_id = StaticIdentity::generate();

        let (init_hs, msg1) = InitiatorHandshake::start(&initiator_id, responder_id.public);
        let mut resp_hs = ResponderHandshake::new(&responder_id);
        resp_hs.read_message1(&msg1).unwrap();
        let (msg2, responder_keys) = resp_hs.write_message2().unwrap();
        let initiator_keys = init_hs.finish(msg2).unwrap();

        let mut init_session = Session::new(initiator_keys);
        let resp_session = Session::new(responder_keys);

        let aad = b"pkt-type=data,seq=0";
        let plaintext = b"hello over the wire";
        let wire = init_session.encrypt(aad, plaintext);
        let decrypted = resp_session.decrypt(aad, &wire).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
