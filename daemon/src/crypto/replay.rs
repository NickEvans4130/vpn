//! Sliding-window replay protection, standard bitmap style (as in
//! WireGuard/IPsec): tracks the highest sequence number seen and a bitmap
//! of the last `WINDOW_SIZE` sequence numbers below it. This is on top of
//! -- not instead of -- the structural replay rejection that falls out of
//! the ratchet: since packet keys are single-use, a replayed ciphertext
//! fails AEAD auth even if it somehow got past this check. The window
//! exists to reject obvious replays cheaply, before spending a ratchet
//! key derivation and an AEAD decrypt on them.

pub const WINDOW_SIZE: u64 = 64;

pub struct ReplayWindow {
    highest_seq: Option<u64>,
    bitmap: u64,
}

impl ReplayWindow {
    pub fn new() -> Self {
        ReplayWindow {
            highest_seq: None,
            bitmap: 0,
        }
    }

    /// Check whether `seq` is acceptable (not a duplicate, not too far
    /// behind the window). Does not mark it as seen -- call `commit`
    /// after the packet has been authenticated, so an attacker can't use
    /// this check alone to probe the window state pre-auth.
    pub fn check(&self, seq: u64) -> bool {
        match self.highest_seq {
            None => true,
            Some(highest) => {
                if seq > highest {
                    true
                } else {
                    let diff = highest - seq;
                    diff < WINDOW_SIZE && (self.bitmap >> diff) & 1 == 0
                }
            }
        }
    }

    /// Mark `seq` as seen. Must only be called after successful AEAD
    /// authentication of the packet at that sequence number.
    pub fn commit(&mut self, seq: u64) {
        match self.highest_seq {
            None => {
                self.highest_seq = Some(seq);
                self.bitmap = 1;
            }
            Some(highest) if seq > highest => {
                let shift = seq - highest;
                self.bitmap = if shift >= WINDOW_SIZE {
                    1
                } else {
                    (self.bitmap << shift) | 1
                };
                self.highest_seq = Some(seq);
            }
            Some(highest) => {
                let diff = highest - seq;
                if diff < WINDOW_SIZE {
                    self.bitmap |= 1 << diff;
                }
            }
        }
    }
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_strictly_increasing_sequence() {
        let mut w = ReplayWindow::new();
        for seq in 0..200u64 {
            assert!(w.check(seq));
            w.commit(seq);
        }
    }

    #[test]
    fn rejects_exact_duplicate() {
        let mut w = ReplayWindow::new();
        w.commit(10);
        assert!(!w.check(10));
    }

    #[test]
    fn accepts_reordered_packet_within_window() {
        let mut w = ReplayWindow::new();
        w.commit(50);
        assert!(w.check(45));
        w.commit(45);
        assert!(!w.check(45));
    }

    #[test]
    fn rejects_packet_older_than_window() {
        let mut w = ReplayWindow::new();
        w.commit(1000);
        assert!(!w.check(1000 - WINDOW_SIZE));
    }

    #[test]
    fn large_forward_jump_resets_window() {
        let mut w = ReplayWindow::new();
        w.commit(5);
        w.commit(5 + WINDOW_SIZE * 10);
        // The old seq is now far outside the window.
        assert!(!w.check(5));
    }
}
