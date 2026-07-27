//! Classical (X25519-only) Noise_IK-style handshake.
//!
//! This is a hand-rolled implementation of the Noise "IK" pattern
//! (`Noise_IK_25519_ChaChaPoly_SHA256`), following the Noise Protocol
//! Framework's symmetric-state construction rather than reusing an
//! existing Noise library. ML-KEM-768 is layered in on top of this once
//! the classical path is verified (see the project build order).
//!
//! IK pattern (responder's static key is known to the initiator ahead of
//! time, e.g. from peer configuration):
//! ```text
//! <- s
//! ...
//! -> e, es, s, ss
//! <- e, ee, se
//! ```
//!
//! Ephemeral keys use `ReusableSecret` rather than `EphemeralSecret`
//! because each side's ephemeral is used in two DH operations within the
//! same handshake (es/ss for the initiator's static-key encryption, then
//! ee/se for the final key material) — `EphemeralSecret` is consumed on
//! first use and can't express that.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key as AeadKey, Nonce as AeadNonce};
use hkdf::Hkdf;
use ml_kem::kem::{Decapsulate, Encapsulate, KeyExport};
use ml_kem::{Ciphertext, EncapsulationKey, Kem, MlKem768};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, ReusableSecret, StaticSecret};
use zeroize::Zeroize;

const PROTOCOL_NAME: &[u8] = b"Noise_IK_25519_MLKEM768_ChaChaPoly_SHA256";

/// A completed handshake, producing two independent transport keys — one
/// for each direction — so a compromise of one direction's key doesn't
/// leak the other.
pub struct TransportKeys {
    pub send_key: [u8; 32],
    pub recv_key: [u8; 32],
    /// The handshake's final chaining key, kept around as the seed for
    /// the periodic DH(+KEM) ratchet -- separate from send/recv so a
    /// leaked transport key doesn't also leak the ratchet's root.
    pub root_key: [u8; 32],
}

impl Drop for TransportKeys {
    fn drop(&mut self) {
        self.send_key.zeroize();
        self.recv_key.zeroize();
        self.root_key.zeroize();
    }
}

#[derive(Clone)]
struct SymmetricState {
    ck: [u8; 32],
    h: [u8; 32],
}

impl Drop for SymmetricState {
    fn drop(&mut self) {
        self.ck.zeroize();
        self.h.zeroize();
    }
}

impl SymmetricState {
    fn new() -> Self {
        // Noise spec: if protocol name <= HASHLEN, pad with zeros, else hash it.
        let h: [u8; 32] = if PROTOCOL_NAME.len() <= 32 {
            let mut h = [0u8; 32];
            h[..PROTOCOL_NAME.len()].copy_from_slice(PROTOCOL_NAME);
            h
        } else {
            Sha256::digest(PROTOCOL_NAME).into()
        };
        SymmetricState { ck: h, h }
    }

    fn mix_hash(&mut self, data: &[u8]) {
        let mut hasher = Sha256::new();
        hasher.update(self.h);
        hasher.update(data);
        self.h = hasher.finalize().into();
    }

    /// HKDF(ck, input_key_material) -> (new ck, output key), per Noise's MixKey.
    fn mix_key(&mut self, ikm: &[u8]) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(Some(&self.ck), ikm);
        let mut okm = [0u8; 64];
        hk.expand(&[], &mut okm).expect("hkdf expand within limit");
        self.ck.copy_from_slice(&okm[..32]);
        let mut key = [0u8; 32];
        key.copy_from_slice(&okm[32..]);
        okm.zeroize();
        key
    }

    fn encrypt_and_hash(&mut self, key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
        let cipher = ChaCha20Poly1305::new(&AeadKey::try_from(key.as_slice()).expect("32-byte key"));
        let nonce = AeadNonce::default(); // zero nonce: key is single-use per Noise message
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: &self.h,
                },
            )
            .expect("chacha20poly1305 encryption");
        self.mix_hash(&ciphertext);
        ciphertext
    }

    fn decrypt_and_hash(&mut self, key: &[u8; 32], ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new(&AeadKey::try_from(key.as_slice()).expect("32-byte key"));
        let nonce = AeadNonce::default();
        let plaintext = cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad: &self.h,
                },
            )
            .map_err(|_| anyhow::anyhow!("handshake decryption failed (auth tag mismatch)"))?;
        self.mix_hash(ciphertext);
        Ok(plaintext)
    }

    /// Final key derivation: split the chaining key into two raw output
    /// keys (k1, k2). Both sides compute identical (k1, k2) since ck is
    /// identical -- callers must assign send/recv per their handshake
    /// role (initiator sends with k1/recvs with k2, responder is mirrored),
    /// same as Noise's `Split()`.
    fn root_key(&self) -> [u8; 32] {
        self.ck
    }

    fn split(&self) -> ([u8; 32], [u8; 32]) {
        let hk = Hkdf::<Sha256>::new(Some(&self.ck), &[]);
        let mut okm = [0u8; 64];
        hk.expand(&[], &mut okm).expect("hkdf expand within limit");
        let mut k1 = [0u8; 32];
        let mut k2 = [0u8; 32];
        k1.copy_from_slice(&okm[..32]);
        k2.copy_from_slice(&okm[32..]);
        okm.zeroize();
        (k1, k2)
    }
}

/// Long-term identity for a peer: X25519 static keypair plus an ML-KEM-768
/// static keypair. Both are treated as "static keys" in the IK sense --
/// the initiator must know the responder's public halves of each ahead of
/// time (e.g. from peer configuration).
pub struct StaticIdentity {
    pub secret: StaticSecret,
    pub public: PublicKey,
    pub kem_decap: ml_kem::DecapsulationKey768,
    pub kem_encap: EncapsulationKey<MlKem768>,
}

impl StaticIdentity {
    pub fn generate() -> Self {
        let secret = StaticSecret::random();
        let public = PublicKey::from(&secret);
        let (kem_decap, kem_encap) = MlKem768::generate_keypair();
        StaticIdentity {
            secret,
            public,
            kem_decap,
            kem_encap,
        }
    }
}

pub struct InitiatorHandshake {
    state: SymmetricState,
    e_priv: ReusableSecret,
    s_priv: StaticSecret,
}

pub struct ResponderHandshake {
    state: SymmetricState,
    s_priv_bytes: [u8; 32],
    kem_decap: ml_kem::DecapsulationKey768,
    pending_ie: Option<PublicKey>,
    pending_is: Option<PublicKey>,
}

/// Message 1: e, es, s, ss, plus an ML-KEM-768 ciphertext encapsulated to
/// the responder's known KEM public key — sent initiator -> responder.
pub struct Message1 {
    pub e_pub: [u8; 32],
    pub kem_ciphertext: Vec<u8>,
    pub encrypted_static: Vec<u8>,
    pub encrypted_payload: Vec<u8>,
}

/// Message 2: e, ee, se — sent responder -> initiator.
pub struct Message2 {
    pub e_pub: [u8; 32],
    pub encrypted_payload: Vec<u8>,
}

impl InitiatorHandshake {
    /// Start a handshake as the initiator, given our own static identity
    /// and the responder's known static X25519 and ML-KEM-768 public keys.
    pub fn start(
        local: &StaticIdentity,
        remote_static: PublicKey,
        remote_kem_encap: &EncapsulationKey<MlKem768>,
    ) -> (Self, Message1) {
        let mut state = SymmetricState::new();
        // Pre-message: mix in the responder's known static public keys.
        state.mix_hash(remote_static.as_bytes());
        state.mix_hash(&remote_kem_encap.to_bytes());

        let e_priv = ReusableSecret::random();
        let e_pub = PublicKey::from(&e_priv);
        state.mix_hash(e_pub.as_bytes());

        // es = DH(e, rs)
        let es = e_priv.diffie_hellman(&remote_static);
        let key1 = state.mix_key(es.as_bytes());
        let encrypted_static = state.encrypt_and_hash(&key1, local.public.as_bytes());

        // ss = DH(s, rs)
        let ss = local.secret.diffie_hellman(&remote_static);
        let key2 = state.mix_key(ss.as_bytes());
        let encrypted_payload = state.encrypt_and_hash(&key2, b"");

        // kem = Encapsulate(remote's known static ML-KEM-768 key). Mixed
        // in as a fourth root-key input alongside es/ss/(ee+se later),
        // matching the design doc's HKDF(dh1||dh2||dh3||kem_secret).
        let (kem_ciphertext, kem_secret) = remote_kem_encap.encapsulate();
        state.mix_key(&kem_secret);

        let msg1 = Message1 {
            e_pub: *e_pub.as_bytes(),
            kem_ciphertext: kem_ciphertext.to_vec(),
            encrypted_static,
            encrypted_payload,
        };

        (
            InitiatorHandshake {
                state,
                e_priv,
                s_priv: local.secret.clone(),
            },
            msg1,
        )
    }

    /// Borrows rather than consumes `self` so a failed attempt (e.g. a
    /// tampered/mismatched message2) can be retried without re-deriving
    /// or copying the long-lived secret material (`e_priv`, `s_priv`) --
    /// only a transient clone of the transcript state is taken per
    /// attempt, and that clone is zeroized on drop regardless of whether
    /// this call succeeds or fails. `e_priv`/`s_priv` themselves are
    /// zeroized on drop by `x25519-dalek`'s `zeroize` feature once this
    /// handshake is retired (either via `finish` returning or the whole
    /// `InitiatorHandshake` being dropped).
    pub fn finish(&self, msg2: Message2) -> anyhow::Result<TransportKeys> {
        let mut state = self.state.clone();

        let re = PublicKey::from(msg2.e_pub);
        state.mix_hash(re.as_bytes());

        // ee = DH(e, re)
        let ee = self.e_priv.diffie_hellman(&re);
        state.mix_key(ee.as_bytes());

        // se = DH(s, re)
        let se = self.s_priv.diffie_hellman(&re);
        let key2 = state.mix_key(se.as_bytes());

        let _payload = state.decrypt_and_hash(&key2, &msg2.encrypted_payload)?;

        // Initiator: send with k1, receive with k2.
        let root_key = state.root_key();
        let (k1, k2) = state.split();
        Ok(TransportKeys {
            send_key: k1,
            recv_key: k2,
            root_key,
        })
    }
}

impl ResponderHandshake {
    pub fn new(local: &StaticIdentity) -> Self {
        let mut state = SymmetricState::new();
        state.mix_hash(local.public.as_bytes());
        state.mix_hash(&local.kem_encap.to_bytes());
        ResponderHandshake {
            state,
            s_priv_bytes: local.secret.to_bytes(),
            kem_decap: local.kem_decap.clone(),
            pending_ie: None,
            pending_is: None,
        }
    }

    /// Process message 1, returning the initiator's static public key
    /// (now authenticated) so the caller can verify it's a known peer.
    pub fn read_message1(&mut self, msg1: &Message1) -> anyhow::Result<PublicKey> {
        let ie = PublicKey::from(msg1.e_pub);
        self.state.mix_hash(ie.as_bytes());

        let s_priv = StaticSecret::from(self.s_priv_bytes);
        // es = DH(s_r, e_i) == DH(e_i, s_r)
        let es = s_priv.diffie_hellman(&ie);
        let key1 = self.state.mix_key(es.as_bytes());
        let is_bytes = self
            .state
            .decrypt_and_hash(&key1, &msg1.encrypted_static)?;
        let mut is_arr = [0u8; 32];
        is_arr.copy_from_slice(&is_bytes);
        let initiator_static = PublicKey::from(is_arr);

        let ss = s_priv.diffie_hellman(&initiator_static);
        let key2 = self.state.mix_key(ss.as_bytes());

        let kem_ct = Ciphertext::<MlKem768>::try_from(msg1.kem_ciphertext.as_slice())
            .map_err(|_| anyhow::anyhow!("malformed ML-KEM-768 ciphertext"))?;
        let kem_secret = self.kem_decap.decapsulate(&kem_ct);
        self.state.mix_key(&kem_secret);

        let _payload = self
            .state
            .decrypt_and_hash(&key2, &msg1.encrypted_payload)?;

        self.pending_ie = Some(ie);
        self.pending_is = Some(initiator_static);
        Ok(initiator_static)
    }

    pub fn write_message2(mut self) -> anyhow::Result<(Message2, TransportKeys)> {
        let ie = self
            .pending_ie
            .take()
            .ok_or_else(|| anyhow::anyhow!("read_message1 must be called first"))?;
        let is = self
            .pending_is
            .take()
            .ok_or_else(|| anyhow::anyhow!("read_message1 must be called first"))?;

        let e_priv = ReusableSecret::random();
        let e_pub = PublicKey::from(&e_priv);
        self.state.mix_hash(e_pub.as_bytes());

        // ee = DH(e_r, e_i)
        let ee = e_priv.diffie_hellman(&ie);
        self.state.mix_key(ee.as_bytes());

        // se = DH(e_r, s_i) == DH(s_i, e_r)
        let se = e_priv.diffie_hellman(&is);
        let key2 = self.state.mix_key(se.as_bytes());
        let encrypted_payload = self.state.encrypt_and_hash(&key2, b"");

        // Responder is the mirror of the initiator: send with k2, receive with k1.
        let root_key = self.state.root_key();
        let (k1, k2) = self.state.split();
        let keys = TransportKeys {
            send_key: k2,
            recv_key: k1,
            root_key,
        };
        Ok((
            Message2 {
                e_pub: *e_pub.as_bytes(),
                encrypted_payload,
            },
            keys,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_produces_matching_crossed_transport_keys() {
        let initiator_id = StaticIdentity::generate();
        let responder_id = StaticIdentity::generate();

        let (init_hs, msg1) = InitiatorHandshake::start(&initiator_id, responder_id.public, &responder_id.kem_encap);

        let mut resp_hs = ResponderHandshake::new(&responder_id);
        let learned_initiator_static = resp_hs.read_message1(&msg1).expect("msg1 decrypts");
        assert_eq!(learned_initiator_static.as_bytes(), initiator_id.public.as_bytes());

        let (msg2, responder_keys) = resp_hs.write_message2().expect("write msg2");
        let initiator_keys = init_hs.finish(msg2).expect("msg2 decrypts");

        // Each side's send key must equal the other side's recv key.
        assert_eq!(initiator_keys.send_key, responder_keys.recv_key);
        assert_eq!(initiator_keys.recv_key, responder_keys.send_key);
    }

    #[test]
    fn tampered_message1_fails_auth() {
        let initiator_id = StaticIdentity::generate();
        let responder_id = StaticIdentity::generate();

        let (_init_hs, mut msg1) = InitiatorHandshake::start(&initiator_id, responder_id.public, &responder_id.kem_encap);
        // Flip a bit in the encrypted static key ciphertext.
        msg1.encrypted_static[0] ^= 0x01;

        let mut resp_hs = ResponderHandshake::new(&responder_id);
        assert!(resp_hs.read_message1(&msg1).is_err());
    }
}


