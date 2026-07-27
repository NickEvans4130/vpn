//! Library surface for the daemon binary, so integration tests (and any
//! future secondary binaries) can exercise the crypto/tun/web modules
//! directly without needing a full `main()`.

pub mod crypto;
pub mod tun;
pub mod web;
