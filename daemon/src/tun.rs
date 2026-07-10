use std::net::Ipv4Addr;
use std::sync::Arc;

use anyhow::Context;
use tun_rs::{AsyncDevice, DeviceBuilder};

/// Thin wrapper around the platform TUN device so the rest of the daemon
/// only deals with raw IP packet bytes, never OS-specific setup.
pub struct Tun {
    device: Arc<AsyncDevice>,
}

impl Tun {
    pub fn create(name: &str, addr: Ipv4Addr, prefix: u8, mtu: u16) -> anyhow::Result<Self> {
        let device = DeviceBuilder::new()
            .name(name)
            .ipv4(addr, prefix, None)
            .mtu(mtu)
            .build_async()
            .with_context(|| {
                format!(
                    "failed to create TUN device '{name}' \
                     (needs CAP_NET_ADMIN; run with sudo or `setcap cap_net_admin+ep` on the binary)"
                )
            })?;
        Ok(Self {
            device: Arc::new(device),
        })
    }

    pub async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.device.recv(buf).await
    }

    pub async fn send(&self, buf: &[u8]) -> std::io::Result<usize> {
        self.device.send(buf).await
    }

    pub fn mtu(&self) -> std::io::Result<u16> {
        self.device.mtu()
    }

    pub fn name(&self) -> std::io::Result<String> {
        self.device.name()
    }
}
