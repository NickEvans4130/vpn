#!/usr/bin/env bash
# Fedora install script: build pqvpn, install the binary and dashboard
# assets, set up a dedicated system user with CAP_NET_ADMIN, and install
# (but not enable) the systemd unit. Run from the repo root as a user
# with sudo access.

set -euo pipefail

if ! command -v cargo >/dev/null; then
  echo "cargo not found -- install the Rust toolchain first (e.g. via rustup.rs)" >&2
  exit 1
fi

echo "==> installing build dependencies (dnf)"
sudo dnf install -y \
  gcc \
  pkgconf-pkg-config \
  systemd-devel \
  iproute

echo "==> building release binary"
cargo build --release

echo "==> installing binary"
sudo install -Dm755 target/release/pqvpnd /usr/local/bin/pqvpnd

echo "==> installing dashboard static assets"
sudo mkdir -p /usr/local/share/pqvpn/web
sudo cp -r web/* /usr/local/share/pqvpn/web/

echo "==> creating pqvpn system user"
if ! id pqvpn >/dev/null 2>&1; then
  sudo useradd --system --no-create-home --shell /usr/sbin/nologin pqvpn
fi

echo "==> granting CAP_NET_ADMIN to the binary (alternative to systemd AmbientCapabilities,
    useful for running pqvpnd manually outside systemd during testing)"
sudo setcap cap_net_admin+ep /usr/local/bin/pqvpnd

echo "==> installing config"
sudo mkdir -p /etc/pqvpn
if [ ! -f /etc/pqvpn/pqvpn.env ]; then
  sudo cp packaging/pqvpn.env.example /etc/pqvpn/pqvpn.env
  echo "    edit /etc/pqvpn/pqvpn.env before starting the service"
fi

echo "==> installing systemd unit"
sudo cp packaging/pqvpn.service /etc/systemd/system/pqvpn.service
sudo systemctl daemon-reload

echo "==> installing NetworkManager unmanaged-device config"
sudo cp packaging/NetworkManager-pqvpn.conf /etc/NetworkManager/conf.d/pqvpn.conf
sudo systemctl reload NetworkManager || true

cat <<'EOF'

Install complete. Next steps:

  1. Edit /etc/pqvpn/pqvpn.env with your peer address and TUN settings.
  2. Review packaging/pqvpn.service -- it runs as the unprivileged
     `pqvpn` user with only CAP_NET_ADMIN, per the README's Fedora
     section.
  3. Start it:   sudo systemctl enable --now pqvpn
  4. Check logs: journalctl -u pqvpn -f
  5. Dashboard:  http://127.0.0.1:8787

If SELinux denies TUN device access, see the README's Fedora section
for the `semanage`/`setsebool` steps and how to check `audit2why`.
EOF
