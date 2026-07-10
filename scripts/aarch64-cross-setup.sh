#!/usr/bin/env bash
# One-time setup for cross-compiling pqvpnd to aarch64 (Raspberry Pi 5)
# from a Fedora x86_64 host. Run once, then use:
#   cargo build --release --target aarch64-unknown-linux-gnu
#
# Fedora's cross packages need three things stitched together that
# aren't wired up by default:
#   1. gcc-aarch64-linux-gnu / binutils-aarch64-linux-gnu -- the cross
#      compiler and linker themselves.
#   2. sysroot-aarch64-fc43-glibc -- the target's C library and headers.
#      It installs to /usr/aarch64-redhat-linux/sys-root/fc43, but the
#      cross-gcc looks for its sysroot at /usr/aarch64-linux-gnu/sys-root
#      (`aarch64-linux-gnu-gcc -print-sysroot`), so that needs a symlink.
#   3. A shared libgcc_s -- the sysroot package doesn't ship one, only
#      the static libgcc.a, but rustc unconditionally passes `-lgcc_s`
#      for glibc targets. The standard fix is a linker script named
#      `libgcc_s.so` that just pulls in the static archive instead.

set -euo pipefail

echo "==> installing aarch64 cross-toolchain and sysroot (dnf)"
sudo dnf install -y \
  gcc-aarch64-linux-gnu \
  binutils-aarch64-linux-gnu \
  sysroot-aarch64-fc43-glibc

if [ ! -e /usr/aarch64-linux-gnu/sys-root/usr/lib ]; then
  echo "==> pointing the cross-gcc's expected sysroot at the installed one"
  sudo rm -rf /usr/aarch64-linux-gnu/sys-root
  sudo ln -s /usr/aarch64-redhat-linux/sys-root/fc43 /usr/aarch64-linux-gnu/sys-root
fi

SHIM_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/.cargo/aarch64-shim"
LIBGCC_A="$(aarch64-linux-gnu-gcc -print-file-name=libgcc.a)"
if [ "${LIBGCC_A}" = "libgcc.a" ]; then
  echo "error: aarch64-linux-gnu-gcc can't find libgcc.a -- is gcc-aarch64-linux-gnu installed?" >&2
  exit 1
fi

echo "==> writing libgcc_s shim (GROUP linker script over ${LIBGCC_A})"
mkdir -p "${SHIM_DIR}"
echo "GROUP ( ${LIBGCC_A} )" >"${SHIM_DIR}/libgcc_s.so"

CONFIG_TOML="$(dirname "${SHIM_DIR}")/config.toml"
if ! grep -q "aarch64-shim" "${CONFIG_TOML}" 2>/dev/null; then
  echo "==> recording the shim path in .cargo/config.toml (machine-specific, not committed as a default)"
  printf 'rustflags = ["-L", "%s"]\n' "${SHIM_DIR}" >>"${CONFIG_TOML}"
fi

echo "==> done. Build with:"
echo "    cargo build --release --target aarch64-unknown-linux-gnu"
