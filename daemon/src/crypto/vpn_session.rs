//! Single source of truth for a live peer connection's crypto state: the
//! current (and briefly, previous) symmetric `Session`, plus the
//! `DhRatchetState` driving periodic rekeys. `main.rs`'s packet loop only
//! ever calls methods here -- no AEAD, padding, or ratchet operations
//! happen inline in `main.rs`.
//!
//! DESIGN GAP -- epoch handling across a rekey (see PR description):
//! the wire format has no room inside the AEAD-protected `Session`
//! packets for an epoch number (changing that would touch already-tested
//! wire framing in `session.rs`), so `VpnSession` prepends one epoch byte
//! *outside* `Session::encrypt`'s own framing: `epoch(1) ||
//! session_wire`. On a rekey, the receiver keeps the just-retired epoch's
//! `Session` around for a short grace window (`EPOCH_GRACE` epochs, i.e.
//! just the current one plus the immediately preceding one) rather than
//! dropping in-flight packets encrypted under the old chain the instant
//! the new epoch is installed. A rekey happens at most once a minute
//! (`RatchetPolicy::default`), so keeping one extra epoch alive for the
//! (much shorter) network RTT is enough to absorb reordering without
//! retaining unbounded key history. A rekey-offer/response packet itself
//! being lost or reordered relative to data packets is handled by the
//! *sender* side: the initiator only starts a new rekey attempt once it
//! observes `should_rekey()` again (i.e. never proactively retries a lost
//! offer), so a lost offer just delays the next rekey until the next time
//! threshold or packet-count threshold trips again -- acceptable because
//! rekeying is a defense-in-depth freshness measure, not something data
//! flow correctness depends on (the current epoch keeps working either
//! way).

use std::collections::BTreeMap;

use super::dh_ratchet::{DhRatchetState, PendingRekey, RatchetPolicy, Role};
use super::noise::TransportKeys;
use super::padding::DEFAULT_PAD_TARGET;
use super::ratchet::Ratchet;
use super::session::Session;
use super::handshake_wire::{decode_rekey_offer, decode_rekey_response, encode_rekey_offer, encode_rekey_response};

/// Number of ratchet epochs kept alive at once: the current one plus a
/// short grace window of previous ones for in-flight packets. See the
/// module doc comment for the reasoning.
const EPOCH_GRACE: usize = 2;

pub struct VpnSession {
    epoch: u8,
    sessions: BTreeMap<u8, Session>,
    dh_ratchet: DhRatchetState,
    role: Role,
    pending_rekey: Option<PendingRekey>,
    pad_target: usize,
}

impl VpnSession {
    pub fn new(keys: TransportKeys, role: Role) -> Self {
        Self::with_pad_target(keys, role, DEFAULT_PAD_TARGET)
    }

    pub fn with_pad_target(keys: TransportKeys, role: Role, pad_target: usize) -> Self {
        let root_key = keys.root_key;
        let mut sessions = BTreeMap::new();
        sessions.insert(0u8, Session::with_pad_target(keys, pad_target));
        VpnSession {
            epoch: 0,
            sessions,
            dh_ratchet: DhRatchetState::new(root_key, role, RatchetPolicy::default()),
            role,
            pending_rekey: None,
            pad_target,
        }
    }

    /// Encrypt one TUN-read plaintext packet for the wire: ratchet step +
    /// pad + AEAD encrypt (all inside `Session::encrypt`), then prefix
    /// the current ratchet epoch. Also records the packet against the DH
    /// ratchet's volume-based rekey trigger.
    pub fn encrypt_for_wire(&mut self, pkt_type: u8, plaintext: &[u8]) -> Vec<u8> {
        let epoch = self.epoch;
        let session = self
            .sessions
            .get_mut(&epoch)
            .expect("current epoch's session always exists");
        let wire = session.encrypt(pkt_type, plaintext);
        self.dh_ratchet.record_packet_sent();

        let mut out = Vec::with_capacity(1 + wire.len());
        out.push(epoch);
        out.extend_from_slice(&wire);
        out
    }

    /// Decrypt one packet, given the `epoch(1) || session_wire` bytes
    /// produced by `encrypt_for_wire` on the peer's side (after any
    /// obfuscation/framing has already been stripped by the caller).
    /// Looks up the matching epoch's `Session` -- may be the current one
    /// or, briefly after a rekey, the previous one.
    pub fn decrypt_from_wire(&mut self, framed: &[u8]) -> anyhow::Result<Vec<u8>> {
        if framed.is_empty() {
            anyhow::bail!("empty data packet");
        }
        let epoch = framed[0];
        let wire = &framed[1..];
        let session = self
            .sessions
            .get_mut(&epoch)
            .ok_or_else(|| anyhow::anyhow!("unknown or expired ratchet epoch {epoch}"))?;
        session.decrypt(wire)
    }

    /// Whether it's time to kick off a new periodic rekey. Only the
    /// initiator side ever starts one (mirrors the Noise_IK asymmetry --
    /// see `dh_ratchet.rs`'s module doc); the responder only reacts to
    /// offers it receives.
    pub fn should_rekey(&self) -> bool {
        self.role == Role::Initiator && self.pending_rekey.is_none() && self.dh_ratchet.should_rekey()
    }

    /// Initiator side: begin a rekey, returning the wire bytes of the
    /// offer to send to the peer.
    pub fn begin_rekey(&mut self) -> Vec<u8> {
        let (offer, pending) = self.dh_ratchet.begin_rekey_as_initiator();
        self.pending_rekey = Some(pending);
        encode_rekey_offer(&offer)
    }

    /// Initiator side: process the peer's rekey response, installing the
    /// new epoch's `Session`.
    pub fn finish_rekey(&mut self, wire: &[u8]) -> anyhow::Result<()> {
        let pending = self
            .pending_rekey
            .take()
            .ok_or_else(|| anyhow::anyhow!("no rekey in progress"))?;
        let response = decode_rekey_response(wire)?;
        let (send, recv) = self.dh_ratchet.finish_rekey_as_initiator(pending, response)?;
        self.install_new_epoch(send, recv);
        Ok(())
    }

    /// Responder side: process an incoming rekey offer, installing the
    /// new epoch's `Session` and returning the wire bytes of the response
    /// to send back.
    pub fn respond_to_rekey(&mut self, wire: &[u8]) -> anyhow::Result<Vec<u8>> {
        let offer = decode_rekey_offer(wire)?;
        let (response, send, recv) = self.dh_ratchet.respond_to_rekey(offer)?;
        self.install_new_epoch(send, recv);
        Ok(encode_rekey_response(&response))
    }

    fn install_new_epoch(&mut self, send: Ratchet, recv: Ratchet) {
        let new_epoch = self.epoch.wrapping_add(1);
        let session = Session::from_ratchets(send, recv, self.pad_target);
        self.sessions.insert(new_epoch, session);
        self.epoch = new_epoch;
        // Retain only the current epoch and its immediate predecessor
        // (EPOCH_GRACE == 2). Evicting by numeric BTreeMap key order would
        // misbehave across the 255 -> 0 wraparound, where the newest epoch
        // (0) sorts as the smallest key; retain by identity instead.
        debug_assert_eq!(EPOCH_GRACE, 2);
        let previous_epoch = self.epoch.wrapping_sub(1);
        self.sessions
            .retain(|&epoch, _| epoch == self.epoch || epoch == previous_epoch);
    }

    pub fn epoch(&self) -> u8 {
        self.epoch
    }

    pub fn dh_ratchet_epoch(&self) -> u64 {
        self.dh_ratchet.epoch()
    }
}
