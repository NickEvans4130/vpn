use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, ValueEnum};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, RwLock};

use pqvpn::crypto::dh_ratchet::Role;
use pqvpn::crypto::handshake_wire;
use pqvpn::crypto::noise::StaticIdentity;
use pqvpn::crypto::obfuscation::{Obfuscator, DTLS_CONTENT_TYPE_APPLICATION_DATA};
use pqvpn::crypto::vpn_session::VpnSession;
use pqvpn::tun::Tun;
use pqvpn::web::{DashboardState, SharedDashboardState};

#[derive(Clone, Copy, Debug, ValueEnum)]
enum RoleArg {
    Initiator,
    Responder,
}

/// Milestone 12: real encrypted TUN <-> UDP forwarding. Plaintext never
/// touches the wire -- see `crypto::vpn_session::VpnSession` for the
/// single source of truth the packet loop below reads/mutates.
#[derive(Parser, Debug)]
#[command(name = "pqvpnd")]
struct Args {
    /// Name for the TUN interface (e.g. pqvpn0)
    #[arg(long, default_value = "pqvpn0")]
    tun_name: String,

    /// IPv4 address to assign to the TUN interface
    #[arg(long)]
    tun_addr: Ipv4Addr,

    /// Prefix length for the TUN interface address
    #[arg(long, default_value_t = 24)]
    tun_prefix: u8,

    /// Local UDP address to bind for peer traffic
    #[arg(long)]
    listen: SocketAddr,

    /// Peer's UDP address to forward packets to
    #[arg(long)]
    peer: SocketAddr,

    /// MTU for the TUN interface
    #[arg(long, default_value_t = 1400)]
    mtu: u16,

    /// Local address to serve the web dashboard on
    #[arg(long, default_value = "127.0.0.1:8787")]
    dashboard_bind: SocketAddr,

    /// Directory containing the dashboard's static assets
    #[arg(long, default_value = "web")]
    dashboard_static: PathBuf,

    /// Disable the local web dashboard
    #[arg(long)]
    no_dashboard: bool,

    /// Which side of the Noise_IK handshake this instance plays. The
    /// initiator starts the exchange (and later, periodic rekeys); the
    /// responder waits for it. Exactly one side of a link must be each.
    #[arg(long, value_enum)]
    role: RoleArg,

    /// Wrap outbound data packets in a fake-DTLS record header to defeat
    /// byte-pattern DPI classifiers. Off by default: it adds a small
    /// per-packet header and does nothing useful on an unfiltered link.
    #[arg(long)]
    obfuscate: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let tun = Tun::create(&args.tun_name, args.tun_addr, args.tun_prefix, args.mtu)?;
    println!(
        "tun device '{}' up at {}/{} (mtu {})",
        tun.name()?,
        args.tun_addr,
        args.tun_prefix,
        tun.mtu()?
    );

    let socket = Arc::new(UdpSocket::bind(args.listen).await?);
    println!("udp listening on {}, peer {}", args.listen, args.peer);

    let role = match args.role {
        RoleArg::Initiator => Role::Initiator,
        RoleArg::Responder => Role::Responder,
    };

    // See `crypto::handshake_wire::exchange_hello`'s doc comment: this
    // bootstrap step is a known, flagged gap (no peer-key provisioning
    // system exists yet), not a design decision to treat as final.
    let local_identity = StaticIdentity::generate();
    println!("bootstrapping static keys with {} (see design notes: TOFU, not MITM-safe)...", args.peer);
    let (peer_static, peer_kem_encap) = handshake_wire::exchange_hello(&socket, args.peer, &local_identity).await?;

    println!("running Noise_IK handshake as {:?}...", args.role);
    let transport_keys = match role {
        Role::Initiator => {
            handshake_wire::handshake_as_initiator(&socket, args.peer, &local_identity, peer_static, &peer_kem_encap)
                .await?
        }
        Role::Responder => {
            let (keys, from) = handshake_wire::handshake_as_responder(&socket, &local_identity).await?;
            if from != args.peer {
                anyhow::bail!(
                    "handshake initiator {from} does not match configured peer {}",
                    args.peer
                );
            }
            keys
        }
    };
    println!("handshake complete, encrypted transport session established");

    let session = Arc::new(Mutex::new(VpnSession::new(transport_keys, role)));
    let obfuscator = Arc::new(Obfuscator::new(args.obfuscate));

    let tun = Arc::new(tun);
    let tx_bytes = Arc::new(AtomicU64::new(0));
    let rx_bytes = Arc::new(AtomicU64::new(0));

    let dashboard_state: SharedDashboardState = Arc::new(RwLock::new(DashboardState {
        connected: true,
        peer_name: args.peer.to_string(),
        ..Default::default()
    }));

    if !args.no_dashboard {
        let router = pqvpn::web::router(dashboard_state.clone(), args.dashboard_static.clone());
        let bind = args.dashboard_bind;
        tokio::spawn(async move {
            match tokio::net::TcpListener::bind(bind).await {
                Ok(listener) => {
                    println!("dashboard listening on http://{bind}");
                    if let Err(e) = axum::serve(listener, router).await {
                        eprintln!("dashboard server error: {e}");
                    }
                }
                Err(e) => eprintln!("failed to bind dashboard on {bind}: {e}"),
            }
        });

        let dashboard_state = dashboard_state.clone();
        let tx_bytes = tx_bytes.clone();
        let rx_bytes = rx_bytes.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(1));
            let mut last_tx = 0u64;
            let mut last_rx = 0u64;
            loop {
                ticker.tick().await;
                let tx = tx_bytes.load(Ordering::Relaxed);
                let rx = rx_bytes.load(Ordering::Relaxed);
                let mut guard = dashboard_state.write().await;
                guard.tx_bytes_per_sec = (tx - last_tx) as f64;
                guard.rx_bytes_per_sec = (rx - last_rx) as f64;
                last_tx = tx;
                last_rx = rx;
            }
        });
    }

    let tun_to_udp = {
        let tun = tun.clone();
        let socket = socket.clone();
        let peer = args.peer;
        let tx_bytes = tx_bytes.clone();
        let session = session.clone();
        let obfuscator = obfuscator.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; args.mtu as usize + 64];
            let mut record_seq: u64 = 0;
            loop {
                match tun.recv(&mut buf).await {
                    Ok(n) => {
                        let plaintext = &buf[..n];
                        let (on_wire, wants_rekey) = {
                            let mut guard = session.lock().await;
                            let data_wire = guard.encrypt_for_wire(0x01, plaintext);
                            let mut outer = Vec::with_capacity(1 + data_wire.len());
                            outer.push(handshake_wire::MSG_DATA);
                            outer.extend_from_slice(&data_wire);
                            let framed = obfuscator.wrap(&outer, record_seq);
                            (framed, guard.should_rekey())
                        };
                        record_seq += 1;
                        tx_bytes.fetch_add(on_wire.len() as u64, Ordering::Relaxed);
                        if let Err(e) = socket.send_to(&on_wire, peer).await {
                            eprintln!("udp send error: {e}");
                        }

                        // Volume/time-based periodic rekey trigger, driven
                        // by the real packet counter and Instant::now()
                        // inside DhRatchetState (see should_rekey()).
                        if wants_rekey {
                            let offer_wire = {
                                let mut guard = session.lock().await;
                                guard.begin_rekey()
                            };
                            if let Err(e) = socket.send_to(&offer_wire, peer).await {
                                eprintln!("rekey offer send error: {e}");
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("tun recv error: {e}");
                        break;
                    }
                }
            }
        })
    };

    let udp_to_tun = {
        let tun = tun.clone();
        let socket = socket.clone();
        let peer = args.peer;
        let rx_bytes = rx_bytes.clone();
        let session = session.clone();
        let obfuscator = obfuscator.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; args.mtu as usize + 128];
            loop {
                match socket.recv_from(&mut buf).await {
                    Ok((n, from)) => {
                        if from != peer {
                            continue;
                        }
                        rx_bytes.fetch_add(n as u64, Ordering::Relaxed);

                        // Control-plane messages (handshake/rekey/hello)
                        // are never obfuscated (see handshake_wire.rs);
                        // only data packets are. The DTLS content-type
                        // byte (0x17) never collides with our control
                        // message type tags (0..=5), so peeking at the
                        // first byte is enough to tell them apart without
                        // needing to know whether --obfuscate is active.
                        let received = &buf[..n];
                        let (msg_type, payload): (u8, &[u8]) =
                            if !received.is_empty() && received[0] == DTLS_CONTENT_TYPE_APPLICATION_DATA {
                                match obfuscator.unwrap(received) {
                                    Ok(body) if !body.is_empty() => (body[0], &body[1..]),
                                    Ok(_) => {
                                        eprintln!("dropping packet: empty obfuscated body");
                                        continue;
                                    }
                                    Err(e) => {
                                        eprintln!("dropping packet: obfuscation unwrap failed: {e}");
                                        continue;
                                    }
                                }
                            } else if !received.is_empty() {
                                (received[0], &received[1..])
                            } else {
                                continue;
                            };

                        match msg_type {
                            handshake_wire::MSG_DATA => {
                                let plaintext = {
                                    let mut guard = session.lock().await;
                                    guard.decrypt_from_wire(payload)
                                };
                                match plaintext {
                                    Ok(plaintext) => {
                                        if let Err(e) = tun.send(&plaintext).await {
                                            eprintln!("tun send error: {e}");
                                        }
                                    }
                                    Err(e) => {
                                        // Drop on any decrypt failure; never
                                        // write anything to TUN, never crash
                                        // the loop.
                                        eprintln!("dropping packet: decrypt failed: {e}");
                                    }
                                }
                            }
                            handshake_wire::MSG_REKEY_OFFER if role == Role::Responder => {
                                // Full control-message bytes (msg_type +
                                // payload) are what respond_to_rekey
                                // expects -- reconstruct them since we
                                // split them above for the data-packet
                                // fast path.
                                let mut full = vec![msg_type];
                                full.extend_from_slice(payload);
                                let result = {
                                    let mut guard = session.lock().await;
                                    guard.respond_to_rekey(&full)
                                };
                                match result {
                                    Ok(response_wire) => {
                                        if let Err(e) = socket.send_to(&response_wire, peer).await {
                                            eprintln!("rekey response send error: {e}");
                                        }
                                    }
                                    Err(e) => eprintln!("rekey offer rejected: {e}"),
                                }
                            }
                            handshake_wire::MSG_REKEY_RESPONSE if role == Role::Initiator => {
                                let mut full = vec![msg_type];
                                full.extend_from_slice(payload);
                                let mut guard = session.lock().await;
                                if let Err(e) = guard.finish_rekey(&full) {
                                    eprintln!("rekey response rejected: {e}");
                                }
                            }
                            other => {
                                eprintln!("dropping unexpected control message type {other} from {from}");
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("udp recv error: {e}");
                        break;
                    }
                }
            }
        })
    };

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            println!("shutting down");
        }
        _ = tun_to_udp => {}
        _ = udp_to_tun => {}
    }

    Ok(())
}
