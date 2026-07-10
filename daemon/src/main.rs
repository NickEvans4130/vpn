mod crypto;
mod tun;
mod web;

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;

use crate::tun::Tun;
use crate::web::{DashboardState, SharedDashboardState};

/// Milestone 2: plaintext TUN <-> UDP passthrough, no crypto yet.
/// Proves the packet plumbing works before the ratchet/AEAD layers are added.
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
    println!("udp listening on {}, forwarding to peer {}", args.listen, args.peer);

    let tun = Arc::new(tun);
    let tx_bytes = Arc::new(AtomicU64::new(0));
    let rx_bytes = Arc::new(AtomicU64::new(0));

    let dashboard_state: SharedDashboardState = Arc::new(RwLock::new(DashboardState {
        connected: true,
        peer_name: args.peer.to_string(),
        ..Default::default()
    }));

    if !args.no_dashboard {
        let router = web::router(dashboard_state.clone(), args.dashboard_static.clone());
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

        // Note: the daemon doesn't run the crypto handshake/ratchet on this
        // path yet (still plaintext passthrough per the build order), so
        // there's no real ratchet epoch to report. This just turns byte
        // counters from the forwarding loops into a live throughput graph
        // so the dashboard's wiring is provably correct end to end; the
        // ratchet fields get fed from the real DhRatchetState once the
        // transport loop is upgraded to use it.
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
        tokio::spawn(async move {
            let mut buf = vec![0u8; args.mtu as usize + 64];
            loop {
                match tun.recv(&mut buf).await {
                    Ok(n) => {
                        tx_bytes.fetch_add(n as u64, Ordering::Relaxed);
                        if let Err(e) = socket.send_to(&buf[..n], peer).await {
                            eprintln!("udp send error: {e}");
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
        let rx_bytes = rx_bytes.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; args.mtu as usize + 64];
            loop {
                match socket.recv_from(&mut buf).await {
                    Ok((n, _from)) => {
                        rx_bytes.fetch_add(n as u64, Ordering::Relaxed);
                        if let Err(e) = tun.send(&buf[..n]).await {
                            eprintln!("tun send error: {e}");
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
