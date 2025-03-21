use std::{fmt::Display, num::Wrapping};

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
pub struct TcpWindow {
    /// The current center of window
    window_center: Wrapping<u32>,
    /// The number of times the *left edge* of the window has warped.
    /// The left edge is the lowest possible  seq number inside the window,
    /// so `center - 2^30`
    num_wraps: u32,
}

#[inline(always)]
fn mku64(upper: u32, lower: u32) -> TcpSeq64 {
    ((upper as u64) << 32) | (lower as u64)
}

impl From<u32> for TcpWindow {
    fn from(seq: u32) -> Self {
        TcpWindow::new(seq)
    }
}

impl TcpWindow {
    const HALF_WINDOW_SIZE: Wrapping<u32> = Wrapping(1 << 30);
    pub fn new(seq: u32) -> Self {
        TcpWindow {
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
    pub fn seq64(&self, seq: u32) -> Option<TcpSeq64> {
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
    pub fn seq64_and_update(&mut self, seq: u32) -> Option<TcpSeq64> {
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

// Represents a 64bit sequence (or ack) number
pub type TcpSeq64 = u64;

/// A range of 64bit TCP sequence numbers (as generated by `TcpSeqState`). This
/// struct guarantees that `left edge < right edge`. The left edge is included in
/// range but the right edge is not. So it's similar to rust's std `Range` and to
/// how ACK and SACK numbers are interpreted.
/// Note, that this struct cannot represent the empty range. We just use `None` instead.
#[derive(Clone, Copy, Debug, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct SeqRange {
    left: TcpSeq64,
    right: TcpSeq64,
}

impl SeqRange {
    /// Create a new range from a tuple of 64bit sequence numbers, if
    /// `left < right`. Otherwise returns `None`
    pub fn try_from_seq64((left, right): (TcpSeq64, TcpSeq64)) -> Option<Self> {
        if left < right {
            Some(SeqRange { left, right })
        } else {
            None
        }
    }

    /// Create a new range from a tuple of 32bit "raw" sequence numbers (as we'd see them in a
    /// TCP header. Returns a new range if both `left` and `right` are in the window for
    /// `seq_stat` and if `left < right` (based on their 64bit representation)
    pub fn try_from_seq(tcp_window: &TcpWindow, (left, right): (u32, u32)) -> Option<Self> {
        match (tcp_window.seq64(left), tcp_window.seq64(right)) {
            (Some(left), Some(right)) if left < right => Some(SeqRange { left, right }),
            _ => None,
        }
    }

    pub fn left(&self) -> TcpSeq64 {
        self.left
    }

    pub fn right(&self) -> TcpSeq64 {
        self.right
    }

    /// Return the number of bytes covered by this range.
    pub fn bytes(&self) -> u64 {
        self.right - self.left
    }
}

impl Display for SeqRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{},{})", self.left, self.right)
    }
}

/// Given a list of `SeqRanges`, we first sort them (first by left edge, then
/// by right edge) and then merge any overlapping ranges.
pub fn sort_and_merge_ranges(mut ranges: Vec<SeqRange>) -> Vec<SeqRange> {
    if ranges.len() < 2 {
        return ranges;
    }
    ranges.sort();
    let mut previous = *ranges.first().unwrap();

    let mut ret = Vec::new();

    for cur in ranges.into_iter().skip(1) {
        debug_assert!(previous.left <= cur.left);
        if previous.right >= cur.left {
            // ranges overlap. Merge
            previous.right = previous.right.max(cur.right);
        } else {
            // no overlap
            ret.push(previous);
            previous = cur;
        }
    }
    ret.push(previous);
    ret
}

/// Give an ACK number and a list of SACK block ranges, return a list of holes in
/// the sequence space.
/// The ACK number is last cummulative ACK received (i.e., everything that has been
/// received w/o holes)
pub fn get_holes_from_sack(ack_no: TcpSeq64, sacks: Vec<SeqRange>) -> Vec<SeqRange> {
    let sacks = sort_and_merge_ranges(sacks);
    let mut holes = Vec::new();
    let mut previous_right_edge = ack_no;
    for s in sacks {
        if s.left() <= previous_right_edge {
            // Might be a probe.
            continue;
        }
        holes.push(SeqRange::try_from_seq64((previous_right_edge, s.left())).unwrap());
        previous_right_edge = s.right();
    }
    holes
}

/// Given an ACK no and a Vec of holes, that is *sorted and non-overlapping*, remove/close any holes
/// that the ACK has acknoledged. Returns the number of bytes in closed holes.
pub fn remove_filled_holes(ack_no: TcpSeq64, holes: &mut Vec<SeqRange>) -> u64 {
    let mut lost_bytes = 0;
    // TODO: maybe echeck that holes are sorted and non-overlapping... (which is a pre-condition for
    // calling this function)
    while let Some(hole) = holes.first_mut() {
        if hole.right() <= ack_no {
            // Hole completely filled
            lost_bytes += hole.bytes();
            holes.remove(0);
        } else if hole.left() < ack_no {
            // hole is partially filled
            lost_bytes += ack_no - hole.left();
            hole.left = ack_no;
            break;
        } else {
            // Remaining holes are not yet ACKed
            break;
        }
    }
    lost_bytes
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_tcp_tcp_window_wrapping_case() {
        let win = TcpWindow::new(0x4200);
        let left_edge = 0xc000_4200u32; // 0x4200 - 2^30
        let right_edge = 0x4000_4200u32; // 0x4200 + 2^30

        assert!(win.is_in_window(0));
        assert_eq!(win.seq64(0), Some(0x1_0000_0000));

        assert!(win.is_in_window(0x4200));
        assert_eq!(win.seq64(0x4200), Some(0x1_0000_4200));

        assert!(!win.is_in_window(left_edge - 1));
        assert_eq!(win.seq64(left_edge - 1), None);

        assert!(win.is_in_window(left_edge));
        assert_eq!(win.seq64(left_edge), Some(0xc000_4200));

        assert!(win.is_in_window(left_edge + 1));
        assert_eq!(win.seq64(left_edge + 1), Some(0xc000_4201));

        assert!(win.is_in_window(right_edge - 1));
        assert_eq!(win.seq64(right_edge - 1), Some(0x1_4000_4200 - 1));

        assert!(win.is_in_window(right_edge));
        assert_eq!(win.seq64(right_edge), Some(0x1_4000_4200));

        assert!(!win.is_in_window(right_edge + 1));
        assert_eq!(win.seq64(right_edge + 1), None);

        assert!(win.seq64(left_edge).unwrap() < win.seq64(right_edge).unwrap()); // YAY

        assert!(!win.is_in_window(1 << 31));
    }

    #[test]
    fn test_tcp_tcp_window_non_wrapping_case() {
        let win = TcpWindow::new(0x8000_0000);
        let left_edge = 0x4000_0000u32;
        let right_edge = 0xc000_0000u32;

        assert!(!win.is_in_window(0));

        assert!(win.is_in_window(0x8000_4200));
        assert_eq!(win.seq64(0x8000_4200), Some(0x8000_4200));

        assert!(!win.is_in_window(left_edge - 1));
        assert_eq!(win.seq64(left_edge - 1), None);

        assert!(win.is_in_window(left_edge));
        assert_eq!(win.seq64(left_edge), Some(0x4000_0000));

        assert!(win.is_in_window(left_edge + 1));
        assert_eq!(win.seq64(left_edge + 1), Some(0x4000_0001));

        assert!(win.is_in_window(right_edge - 1));
        assert_eq!(win.seq64(right_edge - 1), Some(0xc000_0000 - 1));

        assert!(win.is_in_window(right_edge));
        assert_eq!(win.seq64(right_edge), Some(0xc000_0000));

        assert!(!win.is_in_window(right_edge + 1));
        assert_eq!(win.seq64(right_edge + 1), None);

        assert!(win.seq64(left_edge).unwrap() < win.seq64(right_edge).unwrap()); // YAY

        assert!(win.is_in_window(1 << 31));
    }

    #[test]
    fn test_tcp_tcp_window_edges_at_0() {
        // left edge == 0
        let win = TcpWindow::new(0x4000_0000);
        assert!(win.is_in_window(0));
        assert!(win.is_in_window(1));
        assert!(!win.is_in_window(0xFFFF_FFFF));
        assert_eq!(win.seq64(0), Some(0));
        assert_eq!(win.seq64(1 << 31), Some(1 << 31));

        // right edge == 0
        let win = TcpWindow::new(0xC000_0000);
        assert!(win.is_in_window(0));
        assert!(!win.is_in_window(1));
        assert!(win.is_in_window(0xFFFF_FFFF));
        assert_eq!(win.seq64(0), Some(0x1_0000_0000));
        assert_eq!(win.seq64(1 << 31), Some(1 << 31));
        assert!(!win.is_in_window((1 << 31) - 1));
    }

    #[test]
    fn test_tcp_tcp_window_advance_window() {
        let mut win = TcpWindow::new(0x5000_0000);
        assert_eq!(win.seq64(0x5000_0000), Some(0x5000_0000));
        win.update_window(0x6000_0000);
        assert_eq!(win.window_center, Wrapping(0x6000_0000));
        // Don't allow window to go backwards
        win.update_window(0x5000_0000);
        assert_eq!(win.window_center, Wrapping(0x6000_0000));
        win.update_window(0x5FFF_FFFF);
        assert_eq!(win.window_center, Wrapping(0x6000_0000));
        // Also, don't allow window to go more than 1<<30
        win.update_window(0x6000_0000 + (1 << 30) + 1);
        assert_eq!(win.window_center, Wrapping(0x6000_0000));
        win.update_window(0x6000_0000 + (1 << 30));
        assert_eq!(win.window_center, Wrapping(0xA000_0000));

        let mut win = TcpWindow::new(1);
        // window wraps around 0, so
        assert_eq!(win.seq64(1), Some(0x1_0000_0001));
        // lets wrap around once
        for i in 1..=4u32 {
            win.update_window(i.wrapping_mul(1 << 30));
        }
        assert_eq!(win.window_center, Wrapping(0));
        assert_eq!(win.seq64(0), Some(0x2_0000_0000));
        assert_eq!(win.seq64(1), Some(0x2_0000_0001));
        assert_eq!(win.seq64(0xFFFF_1234), Some(0x1_FFFF_1234));
    }

    #[test]
    fn test_seq_range() {
        assert!(SeqRange::try_from_seq64((5, 1)).is_none());
        assert_eq!(
            SeqRange::try_from_seq64((1, 5)).unwrap(),
            SeqRange { left: 1, right: 5 }
        );

        let win = TcpWindow::new(0x8000_0000);
        assert_eq!(
            SeqRange::try_from_seq(&win, (0x8000_0010, 0x8000_0022)).unwrap(),
            SeqRange {
                left: 0x8000_0010,
                right: 0x8000_0022
            }
        );
        assert!(SeqRange::try_from_seq(&win, (0x8000_0022, 0x8000_0010)).is_none());
        assert!(SeqRange::try_from_seq(&win, (0x0, 0x8000_0000)).is_none());
        assert!(SeqRange::try_from_seq(&win, (0x8000_0000, 0x0)).is_none());

        // Empty range is represented as None
        assert!(SeqRange::try_from_seq(&win, (0x8000_0000, 0x8000_0000)).is_none());
        assert!(SeqRange::try_from_seq64((5, 5)).is_none());

        let r = SeqRange::try_from_seq64((1, 5)).unwrap();
        assert_eq!(r.left(), 1);
        assert_eq!(r.right(), 5);
        assert_eq!(r.to_string(), "[1,5)");
        assert_eq!(r.bytes(), 4);
    }

    fn mkrange(left: u64, right: u64) -> SeqRange {
        SeqRange::try_from_seq64((left, right)).unwrap()
    }

    #[test]
    fn test_sort_and_merge_ranges() {
        assert_eq!(sort_and_merge_ranges(Vec::new()), &[]);
        assert_eq!(sort_and_merge_ranges(vec![mkrange(1, 2)]), &[mkrange(1, 2)]);
        // Overlap in pre-sorted ranges
        assert_eq!(
            sort_and_merge_ranges(vec![mkrange(1, 2), mkrange(3, 4)]),
            &[mkrange(1, 2), mkrange(3, 4)]
        );
        // overlap in unsorted
        assert_eq!(
            sort_and_merge_ranges(vec![mkrange(3, 4), mkrange(1, 2)]),
            &[mkrange(1, 2), mkrange(3, 4)]
        );
        // ranges "touch" ==> merge them
        assert_eq!(
            sort_and_merge_ranges(vec![mkrange(1, 2), mkrange(2, 4)]),
            &[mkrange(1, 4)]
        );
        // overlap
        assert_eq!(
            sort_and_merge_ranges(vec![mkrange(1, 3), mkrange(2, 4)]),
            &[mkrange(1, 4)]
        );
        // one range contained in other
        assert_eq!(
            sort_and_merge_ranges(vec![mkrange(2, 4), mkrange(1, 5)]),
            &[mkrange(1, 5)]
        );
        // same left edge
        assert_eq!(
            sort_and_merge_ranges(vec![mkrange(1, 2), mkrange(1, 5)]),
            &[mkrange(1, 5)]
        );
        assert_eq!(
            sort_and_merge_ranges(vec![mkrange(1, 5), mkrange(1, 2)]),
            &[mkrange(1, 5)]
        );
        // merge multiple
        assert_eq!(
            sort_and_merge_ranges(vec![
                mkrange(1, 2),
                mkrange(2, 3),
                mkrange(2, 5),
                mkrange(4, 7)
            ]),
            &[mkrange(1, 7)]
        );
        // Mix of mergable and unmergable
        assert_eq!(
            sort_and_merge_ranges(vec![
                mkrange(11, 12),
                mkrange(12, 13),
                mkrange(3, 5),
                mkrange(12, 15),
                mkrange(20, 23),
                mkrange(14, 17)
            ]),
            &[mkrange(3, 5), mkrange(11, 17), mkrange(20, 23)]
        );
        assert_eq!(
            sort_and_merge_ranges(vec![
                mkrange(7, 8),
                mkrange(1, 2),
                mkrange(2, 4),
                mkrange(11, 12),
                mkrange(12, 13),
                mkrange(3, 5),
                mkrange(12, 15),
                mkrange(14, 17)
            ]),
            &[mkrange(1, 5), mkrange(7, 8), mkrange(11, 17)]
        );
    }

    #[test]
    fn test_get_holes_from_sack() {
        assert_eq!(
            get_holes_from_sack(
                100,
                vec![mkrange(110, 115), mkrange(113, 118), mkrange(120, 123)]
            ),
            &[mkrange(100, 110), mkrange(118, 120)]
        );
        assert_eq!(
            get_holes_from_sack(
                100,
                vec![mkrange(110, 115), mkrange(115, 120), mkrange(120, 123)]
            ),
            &[mkrange(100, 110)]
        );
        // no holes
        assert_eq!(get_holes_from_sack(110, vec![mkrange(110, 115)]), &[]);
        assert_eq!(get_holes_from_sack(112, vec![mkrange(110, 115)]), &[]);
        // one byte hole
        assert_eq!(
            get_holes_from_sack(109, vec![mkrange(110, 115)]),
            &[mkrange(109, 110)]
        );
    }

    #[test]
    fn test_remove_filled_holes() {
        assert_eq!(remove_filled_holes(100, &mut Vec::new()), 0);

        // single hole completely filled
        let mut holes = vec![mkrange(1, 5)];
        assert_eq!(remove_filled_holes(100, &mut holes), 4);
        assert!(holes.is_empty());

        // single hole not filled
        let mut holes = vec![mkrange(101, 105)];
        assert_eq!(remove_filled_holes(100, &mut holes), 0);
        assert_eq!(holes, vec![mkrange(101, 105)]);

        // multiple holes completely filled
        let mut holes = vec![mkrange(1, 5), mkrange(10, 20), mkrange(30, 40)];
        assert_eq!(remove_filled_holes(100, &mut holes), 24);
        assert!(holes.is_empty());

        // some holes filled some not
        let mut holes = vec![
            mkrange(1, 5),
            mkrange(10, 20),
            mkrange(30, 40),
            mkrange(110, 120),
            mkrange(130, 140),
        ];
        assert_eq!(remove_filled_holes(100, &mut holes), 24);
        assert_eq!(holes, vec![mkrange(110, 120), mkrange(130, 140)]);

        // single hole partially filled
        let mut holes = vec![mkrange(90, 110)];
        assert_eq!(remove_filled_holes(100, &mut holes), 10);
        assert_eq!(holes, vec![mkrange(100, 110)]);

        // some holes filled some not, some partially
        let mut holes = vec![
            mkrange(1, 5),
            mkrange(10, 20),
            mkrange(90, 105),
            mkrange(110, 120),
            mkrange(130, 140),
        ];
        assert_eq!(remove_filled_holes(100, &mut holes), 24);
        assert_eq!(
            holes,
            vec![mkrange(100, 105), mkrange(110, 120), mkrange(130, 140)]
        );
    }
}
