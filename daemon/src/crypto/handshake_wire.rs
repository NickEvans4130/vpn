//! Minimal UDP wire protocol carrying the Noise_IK handshake and the
//! periodic DH+KEM rekey exchange, plus a stopgap "hello" used to
//! bootstrap knowledge of the peer's static public keys (see the
//! `exchange_hello` doc comment for the caveat).
//!
//! Every message starts with a one-byte type tag so a receiver can demux
//! control-plane traffic (handshake/rekey/hello) from data-plane traffic
//! (see `MSG_DATA`, handled by the packet-forwarding loop in `main.rs`,
//! not here) sharing the same UDP socket.

use std::net::SocketAddr;
use std::time::Duration;

use ml_kem::kem::KeyExport;
use ml_kem::{EncapsulationKey, MlKem768};
use tokio::net::UdpSocket;
use x25519_dalek::PublicKey;

use super::dh_ratchet::{RekeyOffer, RekeyResponse};
use super::noise::{InitiatorHandshake, Message1, Message2, ResponderHandshake, StaticIdentity, TransportKeys};

pub const MSG_HELLO: u8 = 0;
pub const MSG_HANDSHAKE1: u8 = 1;
pub const MSG_HANDSHAKE2: u8 = 2;
pub const MSG_REKEY_OFFER: u8 = 3;
pub const MSG_REKEY_RESPONSE: u8 = 4;
pub const MSG_DATA: u8 = 5;

fn write_lp(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u16).to_le_bytes());
    buf.extend_from_slice(data);
}

fn read_lp<'a>(buf: &'a [u8], pos: &mut usize) -> anyhow::Result<&'a [u8]> {
    if buf.len() < *pos + 2 {
        anyhow::bail!("truncated length prefix");
    }
    let len = u16::from_le_bytes(buf[*pos..*pos + 2].try_into().unwrap()) as usize;
    *pos += 2;
    if buf.len() < *pos + len {
        anyhow::bail!("truncated field");
    }
    let out = &buf[*pos..*pos + len];
    *pos += len;
    Ok(out)
}

fn read_fixed32(buf: &[u8], msg_type: u8, label: &str) -> anyhow::Result<[u8; 32]> {
    if buf.is_empty() || buf[0] != msg_type {
        anyhow::bail!("not a {label} message");
    }
    if buf.len() < 33 {
        anyhow::bail!("truncated {label}");
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&buf[1..33]);
    Ok(out)
}

pub fn encode_hello(id: &StaticIdentity) -> Vec<u8> {
    let mut out = vec![MSG_HELLO];
    out.extend_from_slice(id.public.as_bytes());
    write_lp(&mut out, &id.kem_encap.to_bytes());
    out
}

pub fn decode_hello(buf: &[u8]) -> anyhow::Result<(PublicKey, EncapsulationKey<MlKem768>)> {
    let xb = read_fixed32(buf, MSG_HELLO, "hello")?;
    let mut pos = 33;
    let kem_bytes = read_lp(buf, &mut pos)?;
    let kem = EncapsulationKey::<MlKem768>::new(
        kem_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("bad ML-KEM-768 encapsulation key length in hello"))?,
    )
    .map_err(|_| anyhow::anyhow!("invalid ML-KEM-768 encapsulation key in hello"))?;
    Ok((PublicKey::from(xb), kem))
}

pub fn encode_message1(msg: &Message1) -> Vec<u8> {
    let mut out = vec![MSG_HANDSHAKE1];
    out.extend_from_slice(&msg.e_pub);
    write_lp(&mut out, &msg.kem_ciphertext);
    write_lp(&mut out, &msg.encrypted_static);
    write_lp(&mut out, &msg.encrypted_payload);
    out
}

pub fn decode_message1(buf: &[u8]) -> anyhow::Result<Message1> {
    let e_pub = read_fixed32(buf, MSG_HANDSHAKE1, "handshake message1")?;
    let mut pos = 33;
    let kem_ciphertext = read_lp(buf, &mut pos)?.to_vec();
    let encrypted_static = read_lp(buf, &mut pos)?.to_vec();
    let encrypted_payload = read_lp(buf, &mut pos)?.to_vec();
    Ok(Message1 {
        e_pub,
        kem_ciphertext,
        encrypted_static,
        encrypted_payload,
    })
}

pub fn encode_message2(msg: &Message2) -> Vec<u8> {
    let mut out = vec![MSG_HANDSHAKE2];
    out.extend_from_slice(&msg.e_pub);
    write_lp(&mut out, &msg.encrypted_payload);
    out
}

pub fn decode_message2(buf: &[u8]) -> anyhow::Result<Message2> {
    let e_pub = read_fixed32(buf, MSG_HANDSHAKE2, "handshake message2")?;
    let mut pos = 33;
    let encrypted_payload = read_lp(buf, &mut pos)?.to_vec();
    Ok(Message2 { e_pub, encrypted_payload })
}

pub fn encode_rekey_offer(offer: &RekeyOffer) -> Vec<u8> {
    let mut out = vec![MSG_REKEY_OFFER];
    out.extend_from_slice(offer.x_pub.as_bytes());
    write_lp(&mut out, &offer.kem_ek_bytes);
    out
}

pub fn decode_rekey_offer(buf: &[u8]) -> anyhow::Result<RekeyOffer> {
    let xb = read_fixed32(buf, MSG_REKEY_OFFER, "rekey offer")?;
    let mut pos = 33;
    let kem_ek_bytes = read_lp(buf, &mut pos)?.to_vec();
    Ok(RekeyOffer {
        x_pub: PublicKey::from(xb),
        kem_ek_bytes,
    })
}

pub fn encode_rekey_response(resp: &RekeyResponse) -> Vec<u8> {
    let mut out = vec![MSG_REKEY_RESPONSE];
    out.extend_from_slice(resp.x_pub.as_bytes());
    write_lp(&mut out, &resp.kem_ciphertext);
    out
}

pub fn decode_rekey_response(buf: &[u8]) -> anyhow::Result<RekeyResponse> {
    let xb = read_fixed32(buf, MSG_REKEY_RESPONSE, "rekey response")?;
    let mut pos = 33;
    let kem_ciphertext = read_lp(buf, &mut pos)?.to_vec();
    Ok(RekeyResponse {
        x_pub: PublicKey::from(xb),
        kem_ciphertext,
    })
}

/// DESIGN GAP (see PR description): there is no peer-key provisioning
/// system in this codebase yet (out of scope per the milestone -- no QR
/// flow, no config file of pinned peer keys). This exchanges each side's
/// static X25519 + ML-KEM-768 *public* keys in the clear so the real
/// Noise_IK handshake below has something to authenticate against.
/// That means the very first connection between two fresh instances is
/// trust-on-first-use with **no** MITM protection -- an attacker who can
/// intercept this initial exchange can substitute their own keys. A real
/// deployment needs these pinned out-of-band before this call. This is a
/// stopgap to unblock exercising the rest of the crypto pipeline
/// end-to-end, not a security feature.
pub async fn exchange_hello(
    socket: &UdpSocket,
    peer: SocketAddr,
    local: &StaticIdentity,
) -> anyhow::Result<(PublicKey, EncapsulationKey<MlKem768>)> {
    let hello = encode_hello(local);
    let mut buf = [0u8; 4096];
    for attempt in 0..100u32 {
        socket.send_to(&hello, peer).await?;
        let wait = Duration::from_millis(100 + 50 * attempt as u64).min(Duration::from_secs(1));
        match tokio::time::timeout(wait, socket.recv_from(&mut buf)).await {
            Ok(Ok((n, from))) if from == peer => {
                if let Ok(pair) = decode_hello(&buf[..n]) {
                    return Ok(pair);
                }
            }
            _ => continue,
        }
    }
    anyhow::bail!("static-key bootstrap ('hello') exchange timed out with {peer}")
}

/// Run the real Noise_IK handshake over `socket` as the initiator.
/// Retries sending message1 with linear backoff until message2 arrives
/// or attempts are exhausted.
pub async fn handshake_as_initiator(
    socket: &UdpSocket,
    peer: SocketAddr,
    local: &StaticIdentity,
    remote_static: PublicKey,
    remote_kem_encap: &EncapsulationKey<MlKem768>,
) -> anyhow::Result<TransportKeys> {
    let (hs, msg1) = InitiatorHandshake::start(local, remote_static, remote_kem_encap);
    let wire1 = encode_message1(&msg1);

    let mut buf = [0u8; 4096];
    for attempt in 0..30u32 {
        socket.send_to(&wire1, peer).await?;
        let wait = Duration::from_millis(150 + 100 * attempt as u64).min(Duration::from_secs(2));
        match tokio::time::timeout(wait, socket.recv_from(&mut buf)).await {
            Ok(Ok((n, from))) if from == peer => {
                if let Ok(msg2) = decode_message2(&buf[..n]) {
                    // `finish` borrows `hs` and only clones its transient
                    // transcript state internally, so a failed attempt
                    // doesn't consume or corrupt `hs` -- safe to retry.
                    match hs.finish(msg2) {
                        Ok(keys) => return Ok(keys),
                        Err(_) => continue, // auth failure; keep retrying
                    }
                }
                // Not a message2 (e.g. a stray retransmitted hello); keep retrying.
            }
            _ => continue,
        }
    }
    anyhow::bail!("handshake timed out waiting for message2 from {peer}")
}

/// Run the real Noise_IK handshake over `socket` as the responder: wait
/// for message1 (ignoring anything else, e.g. leftover hello retransmits
/// racing on the same socket), then reply with message2.
pub async fn handshake_as_responder(
    socket: &UdpSocket,
    local: &StaticIdentity,
) -> anyhow::Result<(TransportKeys, SocketAddr)> {
    let mut buf = [0u8; 4096];
    loop {
        let (n, from) = socket.recv_from(&mut buf).await?;
        let msg1 = match decode_message1(&buf[..n]) {
            Ok(m) => m,
            Err(_) => continue,
        };
        let mut resp_hs = ResponderHandshake::new(local);
        if resp_hs.read_message1(&msg1).is_err() {
            continue;
        }
        let (msg2, keys) = resp_hs.write_message2()?;
        let wire2 = encode_message2(&msg2);
        socket.send_to(&wire2, from).await?;
        return Ok((keys, from));
    }
}
