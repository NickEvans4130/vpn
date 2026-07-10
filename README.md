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

## License

MIT, see `LICENSE`.
