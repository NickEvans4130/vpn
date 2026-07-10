# pqvpn

A VPN built from primitives rather than assembled from an existing protocol.
No WireGuard code is reused — the handshake, ratchet, and transport crypto
are implemented directly against `x25519-dalek`, `ml-kem`, and
`chacha20poly1305`.

## Design

```
TUN device (raw IP packets)
  -> symmetric ratchet (per-packet key derivation)
  -> AEAD encryption (XChaCha20-Poly1305)
  -> periodic DH+KEM ratchet (session key renewal)
  -> UDP transport
```

- **Handshake**: hybrid Noise_IK-style exchange combining X25519 (static +
  ephemeral) with ML-KEM-768 encapsulation. Root key is
  `HKDF-SHA512(dh1 || dh2 || dh3 || kem_secret)`, with an optional PSK
  mixed in.
- **Ratchet**: a symmetric per-packet chain (HKDF advance, old keys zeroed
  immediately) plus a periodic DH+KEM ratchet that re-runs the hybrid
  exchange every 60s or every 2^16 packets, whichever comes first.
- **Transport**: XChaCha20-Poly1305 with a random 192-bit nonce per packet,
  AAD covering packet type/sequence metadata.
- **Replay protection**: sliding-window sequence counter, backed by the
  fact that ratchet keys are single-use so a replay fails AEAD auth
  regardless.
- **Hardening**: constant-size padding, optional cover traffic, and an
  obfuscation layer that shapes UDP payloads to resemble QUIC/DTLS.

## Status

Early scaffold. See commit history for build order — TUN passthrough,
classical Noise_IK, symmetric ratchet, DH ratchet, hybrid PQ, padding
and replay protection, obfuscation, then the web dashboard.

## Layout

- `daemon/` — Rust VPN daemon (handshake, ratchet, transport, TUN I/O)
- `web/` — local dashboard served by the daemon (status, peers, security
  panel, settings)

## Platforms

Primary target is Fedora (daily driver). Also runs on Ubuntu Server for
homelab exit-node deployment, with an aarch64 cross-compile target for
Raspberry Pi 5.

## Fedora install

`scripts/install-fedora.sh` automates the steps below -- run it from the
repo root, or follow them by hand.

### Dependencies

```
sudo dnf install -y gcc pkgconf-pkg-config systemd-devel iproute
```

Rust itself isn't packaged via `dnf` here -- install it with
[rustup](https://rustup.rs) if you don't already have it.

### Build

```
cargo build --release
```

Produces `target/release/pqvpnd`.

### Running without root: CAP_NET_ADMIN

`pqvpnd` needs `CAP_NET_ADMIN` to create and configure the TUN device --
it should never need to run as root. Two ways to grant it:

- **systemd** (recommended, see `packaging/pqvpn.service`): runs as a
  dedicated unprivileged `pqvpn` system user with
  `AmbientCapabilities=CAP_NET_ADMIN` and `CapabilityBoundingSet=CAP_NET_ADMIN`.
- **Manual/testing**: `sudo setcap cap_net_admin+ep /usr/local/bin/pqvpnd`,
  then run the binary as your normal user.

### SELinux

Fedora's default enforcing SELinux policy generally allows TUN device
creation (`/dev/net/tun`) without extra configuration when the process
holds `CAP_NET_ADMIN` the ways above. If you see a TUN-related denial:

```
sudo ausearch -m avc -ts recent | audit2why
```

If it flags a `tun_device` denial for a custom install path, either
relabel the binary to a standard context or generate a local policy
module for it:

```
sudo ausearch -m avc -ts recent | audit2allow -M pqvpn_local
sudo semodule -i pqvpn_local.pp
```

Avoid `setenforce 0` (disabling SELinux entirely) -- scope the fix to
the actual denial instead.

### Coexisting with NetworkManager

`pqvpnd` doesn't touch the system's default route. Instead:

1. **Tell NetworkManager to ignore the TUN interface** so it doesn't try
   to DHCP it or reset it on a network change:
   ```
   sudo cp packaging/NetworkManager-pqvpn.conf /etc/NetworkManager/conf.d/pqvpn.conf
   sudo systemctl reload NetworkManager
   ```
2. **Route VPN traffic via a separate table**, selected by an `ip rule`,
   rather than overwriting the main default route (which NM would just
   revert on the next network change):
   ```
   sudo scripts/pqvpn-routing.sh up pqvpn0 <tun-peer-gateway>
   ```
   See `scripts/pqvpn-routing.sh` for the underlying `ip rule`/`ip route`
   commands, and wire it into `ExecStartPost=`/`ExecStopPost=` in the
   systemd unit if you want it applied automatically.

### systemd service

```
sudo cp packaging/pqvpn.service /etc/systemd/system/pqvpn.service
sudo mkdir -p /etc/pqvpn
sudo cp packaging/pqvpn.env.example /etc/pqvpn/pqvpn.env
# edit /etc/pqvpn/pqvpn.env with your peer address and TUN settings
sudo systemctl daemon-reload
sudo systemctl enable --now pqvpn
journalctl -u pqvpn -f
```

Dashboard is then reachable at `http://127.0.0.1:8787`.

## Cross-compiling for Raspberry Pi 5 (aarch64)

```
rustup target add aarch64-unknown-linux-gnu
scripts/aarch64-cross-setup.sh   # one-time: toolchain, sysroot, libgcc_s shim
cargo build --release --target aarch64-unknown-linux-gnu
```

Fedora's cross packages need three things stitched together that aren't
wired up by default, which is what `aarch64-cross-setup.sh` automates:

1. `gcc-aarch64-linux-gnu` / `binutils-aarch64-linux-gnu` -- the cross
   compiler and linker.
2. `sysroot-aarch64-fc43-glibc` -- the target's C library and headers.
   It installs to `/usr/aarch64-redhat-linux/sys-root/fc43`, but the
   cross-gcc looks for its sysroot at `/usr/aarch64-linux-gnu/sys-root`
   (`aarch64-linux-gnu-gcc -print-sysroot`), so the script symlinks one
   to the other.
3. A shared `libgcc_s` -- the sysroot package only ships the static
   `libgcc.a`, but rustc unconditionally passes `-lgcc_s` for glibc
   targets. The script writes a linker script named `libgcc_s.so` (a
   `GROUP ( libgcc.a )` shim) into `.cargo/aarch64-shim/` and points
   `.cargo/config.toml`'s `rustflags` at it -- this path is
   machine-specific, so it isn't pre-filled in the committed config.

Verified end-to-end on this repo: a clean `cargo build --release
--target aarch64-unknown-linux-gnu` produces
`target/aarch64-unknown-linux-gnu/release/pqvpnd` as a real aarch64 ELF
(`file` reports `ELF 64-bit LSB pie executable, ARM aarch64`). Running
it on actual Pi 5 hardware hasn't been tested yet -- that's still a
follow-up.

## License

MIT, see `LICENSE`.
