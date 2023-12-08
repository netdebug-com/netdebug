use std::num::Wrapping;

/// A helper struct to keep track of uni-directional TCP sequence number state. I.e.,
/// the current window of acceptable seq/ack numbers and also the number of times the
/// seq numbers have wrapped.
/// This struct also allows us to convert the 32bit seq/ack numbers into 64bit ones that
/// take wrapping into account, so the 64bit seq numbers can easily be compared or added/
/// subtracted without having to worry about wrapping.
///
/// This struct maintains a window of allowed sequence numbers. The window center would
/// usually be the current seq number seen in packets. Typically the center seq would
/// be updated based on observered seq numbers.
///
/// We allow a windows of `center +/- 2^30`. Note that 2^30 if the largest receive
/// window once can announce (max window scale shift is 14). Note that the edges of
/// the window are inclusive. We call `center - 2^30` the left edge and
/// `center + 2^30` the right edge
///
/// TODO: We currently don't implement PAWS (Protection Against Wrapped Sequence numbers),
/// i.e., we don't use TCP timestamp to protect against old segments with old wrapped
/// sequence numbers.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct TcpSeqState {
    /// The current center of window
    window_center: Wrapping<u32>,
    /// The number of times the *left edge* of the window has warped.
    /// The left edge is the lowest possible  seq number inside the window,
    /// so `center - 2^30`
    num_wraps: u32,
}

#[inline(always)]
fn mku64(upper: u32, lower: u32) -> u64 {
    ((upper as u64) << 32) | (lower as u64)
}

impl From<u32> for TcpSeqState {
    fn from(seq: u32) -> Self {
        TcpSeqState::new(seq)
    }
}

impl TcpSeqState {
    const HALF_WINDOW_SIZE: Wrapping<u32> = Wrapping(1 << 30);
    pub fn new(seq: u32) -> Self {
        TcpSeqState {
            window_center: Wrapping(seq),
            num_wraps: 0,
        }
    }

    /// Update the window, i.e., move it forward. The window will be centered
    /// on `seq`. If `seq` is outside the current window or if `seq` is less than
    /// the current centers the window will *NOT* be updated
    pub fn update_window(&mut self, seq: u32) {
        // Only advance the window if the new seq number is in the range
        // between the current center and the right edge
        if !self.is_in_range((self.window_center, self.window_edges().1), seq) {
            return;
        }
        let seq = Wrapping(seq);
        let old_left_edge = self.window_center - Self::HALF_WINDOW_SIZE;
        let new_left_edge = seq - Self::HALF_WINDOW_SIZE;
        if old_left_edge > new_left_edge {
            // if we get here it means new left edge has wrapped around 0 (and the old
            // old left edge is before 0). So we increment the number of wraps
            self.num_wraps += 1
        }
        self.window_center = seq;
    }

    /// Return true if `seq` is in the current window
    pub fn is_in_window(&self, seq: u32) -> bool {
        self.is_in_range(self.window_edges(), seq)
    }

    /// If `seq` is in the current window, return a 64bit sequence number
    /// that can be correctly compared (Ord, PartialOrd) and added/subtraced
    /// from outer 64bit seq numbers from the same TcpSeqState.
    pub fn seq64(&self, seq: u32) -> Option<u64> {
        if !self.is_in_window(seq) {
            return None;
        }

        let seq = Wrapping(seq);
        let (left_edge, right_edge) = self.window_edges();
        if left_edge > right_edge {
            // the current window wraps around 0
            if seq < left_edge {
                // the left-edge is before 0 and seq is past 0. So seq has wrapped
                Some(mku64(self.num_wraps + 1, seq.0))
            } else {
                Some(mku64(self.num_wraps, seq.0))
            }
        } else {
            // the window doesn't wrap around 0. Trivial case
            Some(mku64(self.num_wraps, seq.0))
        }
    }

    /// First update the window with seq,
    /// then return seq64 for seq
    pub fn seq64_and_update(&mut self, seq: u32) -> Option<u64> {
        self.update_window(seq);
        self.seq64(seq)
    }

    /// Returns the left and right edge of the current window
    fn window_edges(&self) -> (Wrapping<u32>, Wrapping<u32>) {
        (
            self.window_center - Self::HALF_WINDOW_SIZE,
            self.window_center + Self::HALF_WINDOW_SIZE,
        )
    }

    fn is_in_range(
        &self,
        (left_edge, right_edge): (Wrapping<u32>, Wrapping<u32>),
        seq: u32,
    ) -> bool {
        let seq = Wrapping(seq);
        if left_edge > right_edge {
            // window wraps around 0 and the lower bound has a larger
            // absolute value
            seq <= right_edge || seq >= left_edge
        } else {
            seq >= left_edge && seq <= right_edge
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_tcp_seq_state_wrapping_case() {
        let tss = TcpSeqState::new(0x4200);
        let left_edge = 0xc000_4200u32; // 0x4200 - 2^30
        let right_edge = 0x4000_4200u32; // 0x4200 + 2^30

        assert!(tss.is_in_window(0));
        assert_eq!(tss.seq64(0), Some(0x1_0000_0000));

        assert!(tss.is_in_window(0x4200));
        assert_eq!(tss.seq64(0x4200), Some(0x1_0000_4200));

        assert!(!tss.is_in_window(left_edge - 1));
        assert_eq!(tss.seq64(left_edge - 1), None);

        assert!(tss.is_in_window(left_edge));
        assert_eq!(tss.seq64(left_edge), Some(0xc000_4200));

        assert!(tss.is_in_window(left_edge + 1));
        assert_eq!(tss.seq64(left_edge + 1), Some(0xc000_4201));

        assert!(tss.is_in_window(right_edge - 1));
        assert_eq!(tss.seq64(right_edge - 1), Some(0x1_4000_4200 - 1));

        assert!(tss.is_in_window(right_edge));
        assert_eq!(tss.seq64(right_edge), Some(0x1_4000_4200));

        assert!(!tss.is_in_window(right_edge + 1));
        assert_eq!(tss.seq64(right_edge + 1), None);

        assert!(tss.seq64(left_edge).unwrap() < tss.seq64(right_edge).unwrap()); // YAY

        assert!(!tss.is_in_window(1 << 31));
    }

    #[test]
    fn test_tcp_seq_state_non_wrapping_case() {
        let tss = TcpSeqState::new(0x8000_0000);
        let left_edge = 0x4000_0000u32;
        let right_edge = 0xc000_0000u32;

        assert!(!tss.is_in_window(0));

        assert!(tss.is_in_window(0x8000_4200));
        assert_eq!(tss.seq64(0x8000_4200), Some(0x8000_4200));

        assert!(!tss.is_in_window(left_edge - 1));
        assert_eq!(tss.seq64(left_edge - 1), None);

        assert!(tss.is_in_window(left_edge));
        assert_eq!(tss.seq64(left_edge), Some(0x4000_0000));

        assert!(tss.is_in_window(left_edge + 1));
        assert_eq!(tss.seq64(left_edge + 1), Some(0x4000_0001));

        assert!(tss.is_in_window(right_edge - 1));
        assert_eq!(tss.seq64(right_edge - 1), Some(0xc000_0000 - 1));

        assert!(tss.is_in_window(right_edge));
        assert_eq!(tss.seq64(right_edge), Some(0xc000_0000));

        assert!(!tss.is_in_window(right_edge + 1));
        assert_eq!(tss.seq64(right_edge + 1), None);

        assert!(tss.seq64(left_edge).unwrap() < tss.seq64(right_edge).unwrap()); // YAY

        assert!(tss.is_in_window(1 << 31));
    }

    #[test]
    fn test_tcp_seq_state_edges_at_0() {
        // left edge == 0
        let tss = TcpSeqState::new(0x4000_0000);
        assert!(tss.is_in_window(0));
        assert!(tss.is_in_window(1));
        assert!(!tss.is_in_window(0xFFFF_FFFF));
        assert_eq!(tss.seq64(0), Some(0));
        assert_eq!(tss.seq64(1 << 31), Some(1 << 31));

        // right edge == 0
        let tss = TcpSeqState::new(0xC000_0000);
        assert!(tss.is_in_window(0));
        assert!(!tss.is_in_window(1));
        assert!(tss.is_in_window(0xFFFF_FFFF));
        assert_eq!(tss.seq64(0), Some(0x1_0000_0000));
        assert_eq!(tss.seq64(1 << 31), Some(1 << 31));
        assert!(!tss.is_in_window((1 << 31) - 1));
    }

    #[test]
    fn test_tcp_seq_state_advance_window() {
        let mut tss = TcpSeqState::new(0x5000_0000);
        assert_eq!(tss.seq64(0x5000_0000), Some(0x5000_0000));
        tss.update_window(0x6000_0000);
        assert_eq!(tss.window_center, Wrapping(0x6000_0000));
        // Don't allow window to go backwards
        tss.update_window(0x5000_0000);
        assert_eq!(tss.window_center, Wrapping(0x6000_0000));
        tss.update_window(0x5FFF_FFFF);
        assert_eq!(tss.window_center, Wrapping(0x6000_0000));
        // Also, don't allow window to go more than 1<<30
        tss.update_window(0x6000_0000 + (1 << 30) + 1);
        assert_eq!(tss.window_center, Wrapping(0x6000_0000));
        tss.update_window(0x6000_0000 + (1 << 30));
        assert_eq!(tss.window_center, Wrapping(0xA000_0000));

        let mut tss = TcpSeqState::new(1);
        // window wraps around 0, so
        assert_eq!(tss.seq64(1), Some(0x1_0000_0001));
        // lets wrap around once
        for i in 1..=4u32 {
            tss.update_window(i.wrapping_mul(1 << 30));
        }
        assert_eq!(tss.window_center, Wrapping(0));
        assert_eq!(tss.seq64(0), Some(0x2_0000_0000));
        assert_eq!(tss.seq64(1), Some(0x2_0000_0001));
        assert_eq!(tss.seq64(0xFFFF_1234), Some(0x1_FFFF_1234));
    }
}
