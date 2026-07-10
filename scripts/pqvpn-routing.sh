#!/usr/bin/env bash
# Policy routing setup so pqvpn coexists with NetworkManager instead of
# fighting it for the default route: traffic gets routed through the VPN
# via a separate routing table, selected by an ip rule, rather than by
# rewriting the system's main default route (which NM would just revert
# on the next network change).
#
# Usage: pqvpn-routing.sh up   <tun-iface> <tun-peer-gateway>
#        pqvpn-routing.sh down <tun-iface>
#
# Run as root (or with CAP_NET_ADMIN). Intended to be called from an
# ExecStartPost=/ExecStopPost= in the systemd unit, or by hand for
# testing.

set -euo pipefail

TABLE=pqvpn
TABLE_ID=51820
RULE_PRIORITY=10000

ensure_table_name() {
  if ! grep -q "^${TABLE_ID}[[:space:]]\+${TABLE}\$" /etc/iproute2/rt_tables 2>/dev/null; then
    echo "${TABLE_ID} ${TABLE}" >>/etc/iproute2/rt_tables
  fi
}

case "${1:-}" in
  up)
    iface="${2:?tun interface name required}"
    gateway="${3:?tun peer gateway required}"
    ensure_table_name
    ip route replace default via "${gateway}" dev "${iface}" table "${TABLE}"
    ip rule add priority "${RULE_PRIORITY}" not fwmark 0x51820 table "${TABLE}" 2>/dev/null || true
    echo "pqvpn policy routing up: table=${TABLE} iface=${iface} via=${gateway}"
    ;;
  down)
    iface="${2:?tun interface name required}"
    ip rule del priority "${RULE_PRIORITY}" table "${TABLE}" 2>/dev/null || true
    ip route flush table "${TABLE}" 2>/dev/null || true
    echo "pqvpn policy routing down for ${iface}"
    ;;
  *)
    echo "usage: $0 {up <iface> <gateway>|down <iface>}" >&2
    exit 1
    ;;
esac
