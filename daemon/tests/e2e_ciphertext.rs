//! End-to-end proof that real bytes captured off a real loopback UDP
//! socket are opaque ciphertext, not the plaintext TUN payload -- the
//! acceptance criterion for milestone 12 (replacing the plaintext
//! passthrough in `main.rs` with the real crypto pipeline).
//!
//! Deliberately does NOT create a real TUN device (needs CAP_NET_ADMIN,
//! won't run in CI/sandboxes) -- instead drives the same `VpnSession` +
//! `handshake_wire` + `Obfuscator` code that `main.rs`'s packet loop
//! calls, over two real `UdpSocket`s bound to 127.0.0.1:0, so the
//! "no plaintext on the wire" assertion is exercised against actual
//! bytes that went through a real socket, not an in-memory shortcut.

use pqvpn::crypto::dh_ratchet::Role;
use pqvpn::crypto::handshake_wire::{self, MSG_DATA};
use pqvpn::crypto::noise::StaticIdentity;
use pqvpn::crypto::obfuscation::Obfuscator;
use pqvpn::crypto::vpn_session::VpnSession;
use tokio::net::UdpSocket;

const MARKER: &[u8] = b"PING-INTEGRATION-TEST-PAYLOAD-MARKER";

/// Mirrors the "encrypt, frame, obfuscate, send" half of main.rs's
/// tun_to_udp loop, and the "receive, deobfuscate, decrypt" half of
/// udp_to_tun -- factored out here so both this test and main.rs exercise
/// the identical code path (main.rs just adds the TUN read/write around
/// it).
async fn send_data_packet(
    socket: &UdpSocket,
    peer: std::net::SocketAddr,
    session: &mut VpnSession,
    obfuscator: &Obfuscator,
    record_seq: u64,
    plaintext: &[u8],
) -> anyhow::Result<()> {
    let data_wire = session.encrypt_for_wire(0x01, plaintext);
    let mut outer = Vec::with_capacity(1 + data_wire.len());
    outer.push(MSG_DATA);
    outer.extend_from_slice(&data_wire);
    let framed = obfuscator.wrap(&outer, record_seq);
    socket.send_to(&framed, peer).await?;
    Ok(())
}

fn decrypt_captured(
    session: &mut VpnSession,
    obfuscator: &Obfuscator,
    captured: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let unwrapped = obfuscator.unwrap(captured)?;
    anyhow::ensure!(!unwrapped.is_empty(), "empty captured packet");
    anyhow::ensure!(unwrapped[0] == MSG_DATA, "expected a data packet");
    session.decrypt_from_wire(&unwrapped[1..])
}

/// Real handshake between two `VpnSession`s over a real loopback UDP
/// socket pair, driven concurrently (the responder blocks in `recv_from`
/// until the initiator's message1 arrives).
async fn handshake_pair() -> (UdpSocket, std::net::SocketAddr, VpnSession, UdpSocket, std::net::SocketAddr, VpnSession)
{
    let initiator_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let responder_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let initiator_addr = initiator_socket.local_addr().unwrap();
    let responder_addr = responder_socket.local_addr().unwrap();

    let initiator_id = StaticIdentity::generate();
    let responder_id = StaticIdentity::generate();
    let responder_static = responder_id.public;
    let responder_kem_encap = responder_id.kem_encap.clone();

    let responder_task = tokio::spawn(async move {
        handshake_wire::handshake_as_responder(&responder_socket, &responder_id)
            .await
            .map(|(keys, _from)| (keys, responder_socket))
    });

    let initiator_keys = handshake_wire::handshake_as_initiator(
        &initiator_socket,
        responder_addr,
        &initiator_id,
        responder_static,
        &responder_kem_encap,
    )
    .await
    .expect("initiator handshake succeeds");

    let (responder_keys, responder_socket) = responder_task
        .await
        .expect("responder task didn't panic")
        .expect("responder handshake succeeds");

    let initiator_session = VpnSession::new(initiator_keys, Role::Initiator);
    let responder_session = VpnSession::new(responder_keys, Role::Responder);

    (
        initiator_socket,
        responder_addr,
        initiator_session,
        responder_socket,
        initiator_addr,
        responder_session,
    )
}

#[tokio::test]
async fn wire_bytes_are_opaque_and_round_trip_without_obfuscation() {
    let (initiator_socket, responder_addr, mut initiator_session, responder_socket, _initiator_addr, mut responder_session) =
        handshake_pair().await;

    let obfuscator = Obfuscator::new(false);

    send_data_packet(&initiator_socket, responder_addr, &mut initiator_session, &obfuscator, 0, MARKER)
        .await
        .expect("send succeeds");

    let mut buf = [0u8; 4096];
    let (n, _from) = tokio::time::timeout(std::time::Duration::from_secs(2), responder_socket.recv_from(&mut buf))
        .await
        .expect("recv within timeout")
        .expect("recv succeeds");
    let captured = &buf[..n];

    // The actual acceptance criterion: raw bytes captured off the real
    // socket must not contain the plaintext marker anywhere.
    assert!(
        !captured.windows(MARKER.len()).any(|w| w == MARKER),
        "plaintext marker leaked onto the wire uncrypted"
    );

    // Without obfuscation, the wire format is the raw VpnSession framing:
    // MSG_DATA(1) || epoch(1) || pkt_type(1) || seq(8) || nonce(24) || ciphertext.
    assert_eq!(captured[0], MSG_DATA);

    let decrypted = decrypt_captured(&mut responder_session, &obfuscator, captured).expect("decrypts cleanly");
    assert_eq!(decrypted, MARKER);
}

#[tokio::test]
async fn obfuscated_wire_bytes_look_like_dtls_and_still_round_trip() {
    let (initiator_socket, responder_addr, mut initiator_session, responder_socket, _initiator_addr, mut responder_session) =
        handshake_pair().await;

    let obfuscator = Obfuscator::new(true);

    send_data_packet(&initiator_socket, responder_addr, &mut initiator_session, &obfuscator, 7, MARKER)
        .await
        .expect("send succeeds");

    let mut buf = [0u8; 4096];
    let (n, _from) = tokio::time::timeout(std::time::Duration::from_secs(2), responder_socket.recv_from(&mut buf))
        .await
        .expect("recv within timeout")
        .expect("recv succeeds");
    let captured = &buf[..n];

    assert!(
        !captured.windows(MARKER.len()).any(|w| w == MARKER),
        "plaintext marker leaked onto the wire uncrypted"
    );

    // Fake DTLS 1.2 application-data record header: ContentType=23 (0x17),
    // ProtocolVersion={0xfe,0xfd}.
    assert_eq!(captured[0], 0x17, "obfuscated packet should start with fake DTLS content type");
    assert_eq!(&captured[1..3], &[0xfe, 0xfd], "obfuscated packet should carry fake DTLS 1.2 version bytes");
    // Structurally different from the un-obfuscated format, whose first
    // byte is the small MSG_DATA tag (5), not 0x17.
    assert_ne!(captured[0], MSG_DATA);

    let decrypted = decrypt_captured(&mut responder_session, &obfuscator, captured).expect("decrypts cleanly");
    assert_eq!(decrypted, MARKER);
}

#[tokio::test]
async fn full_round_trip_multiple_packets_both_directions() {
    let (initiator_socket, responder_addr, mut initiator_session, responder_socket, initiator_addr, mut responder_session) =
        handshake_pair().await;
    let obfuscator = Obfuscator::new(false);

    for (i, payload) in [b"hello-a".as_slice(), b"hello-b", b"hello-c"].iter().enumerate() {
        send_data_packet(&initiator_socket, responder_addr, &mut initiator_session, &obfuscator, i as u64, payload)
            .await
            .unwrap();
        let mut buf = [0u8; 4096];
        let (n, _) = responder_socket.recv_from(&mut buf).await.unwrap();
        let decrypted = decrypt_captured(&mut responder_session, &obfuscator, &buf[..n]).unwrap();
        assert_eq!(decrypted, *payload);
    }

    // And the reverse direction.
    send_data_packet(&responder_socket, initiator_addr, &mut responder_session, &obfuscator, 0, b"reply")
        .await
        .unwrap();
    let mut buf = [0u8; 4096];
    let (n, _) = initiator_socket.recv_from(&mut buf).await.unwrap();
    let decrypted = decrypt_captured(&mut initiator_session, &obfuscator, &buf[..n]).unwrap();
    assert_eq!(decrypted, b"reply");
}
