mod crypto;
mod tun;

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use clap::Parser;
use tokio::net::UdpSocket;

use crate::tun::Tun;

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

    let tun_to_udp = {
        let tun = tun.clone();
        let socket = socket.clone();
        let peer = args.peer;
        tokio::spawn(async move {
            let mut buf = vec![0u8; args.mtu as usize + 64];
            loop {
                match tun.recv(&mut buf).await {
                    Ok(n) => {
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
        tokio::spawn(async move {
            let mut buf = vec![0u8; args.mtu as usize + 64];
            loop {
                match socket.recv_from(&mut buf).await {
                    Ok((n, _from)) => {
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
