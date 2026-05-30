use crate::pattern::Signature;

pub struct CompiledPattern {
    bytes: Vec<u8>,
    mask: Vec<bool>,
    anchor: Option<(usize, u8)>,
    secondary: Option<(usize, u8)>,
}

impl CompiledPattern {
    #[must_use]
    pub fn new(signature: &Signature) -> Option<Self> {
        if signature.is_empty() {
            return None;
        }
        let fixed = |skip: Option<usize>| {
            signature
                .mask
                .iter()
                .enumerate()
                .filter(|&(_, &significant)| significant)
                .filter(|&(i, _)| Some(i) != skip)
                .map(|(i, _)| (i, signature.bytes[i]))
                .min_by_key(|&(_, byte)| byte_frequency(byte))
        };
        let anchor = fixed(None)?;
        let secondary = fixed(Some(anchor.0));
        Some(Self {
            bytes: signature.bytes.clone(),
            mask: signature.mask.clone(),
            anchor: Some(anchor),
            secondary,
        })
    }

    #[must_use]
    pub fn secondary_anchor(&self) -> Option<(usize, u8)> {
        self.secondary
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

#[must_use]
pub fn byte_frequency(b: u8) -> u32 {
    match b {
        0x00 => 1000,
        0xFF => 700,
        0x48 => 650,
        0xCC => 500,
        0x8B => 420,
        0x40 | 0x41 | 0x44 | 0x45 | 0x49 | 0x4C => 360,
        0x0F | 0x83 | 0x84 | 0x85 | 0x89 | 0xC0 | 0xE8 => 300,
        0x01 | 0x10 | 0x20 | 0x90 => 240,
        _ => 100,
    }
}

#[inline]
fn matches_at(bytes: &[u8], mask: &[bool], haystack: &[u8], start: usize) -> bool {
    for (k, (&byte, &significant)) in bytes.iter().zip(mask).enumerate() {
        if significant && haystack[start + k] != byte {
            return false;
        }
    }
    true
}

#[must_use]
pub fn find_all(haystack: &[u8], pat: &CompiledPattern) -> Vec<usize> {
    let len = pat.bytes.len();
    let n = haystack.len();
    if len == 0 || n < len {
        return Vec::new();
    }
    let last_start = n - len;
    if pat.anchor.is_none() {
        return (0..=last_start).collect();
    }
    #[cfg(target_arch = "x86_64")]
    {
        if std::is_x86_feature_detected!("avx2") {
            return unsafe { find_all_avx2(haystack, pat) };
        }
    }
    find_all_scalar(haystack, pat)
}

fn find_all_scalar(haystack: &[u8], pat: &CompiledPattern) -> Vec<usize> {
    let (anchor_pos, anchor_byte) = pat.anchor.expect("anchor required");
    let len = pat.bytes.len();
    let n = haystack.len();
    let mut out = Vec::new();
    if len == 0 || n < len {
        return out;
    }
    let last_start = n - len;
    for start in 0..=last_start {
        if haystack[start + anchor_pos] == anchor_byte
            && matches_at(&pat.bytes, &pat.mask, haystack, start)
        {
            out.push(start);
        }
    }
    out
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn find_all_avx2(haystack: &[u8], pat: &CompiledPattern) -> Vec<usize> {
    use core::arch::x86_64::{
        __m256i, _mm256_cmpeq_epi8, _mm256_loadu_si256, _mm256_movemask_epi8, _mm256_set1_epi8,
    };
    let (anchor_pos, anchor_byte) = pat.anchor.expect("anchor required");
    let len = pat.bytes.len();
    let n = haystack.len();
    let mut out = Vec::new();
    if len == 0 || n < len {
        return out;
    }
    let last_start = n - len;
    let scan_end = last_start + anchor_pos;
    let ptr = haystack.as_ptr();
    let va = _mm256_set1_epi8(anchor_byte as i8);
    let mut i = anchor_pos;
    while i + 32 <= n && i <= scan_end {
        let chunk = unsafe { _mm256_loadu_si256(ptr.add(i).cast::<__m256i>()) };
        let eq = _mm256_cmpeq_epi8(chunk, va);
        let mut bits = _mm256_movemask_epi8(eq) as u32;
        while bits != 0 {
            let bit = bits.trailing_zeros() as usize;
            let anchor_abs = i + bit;
            if anchor_abs <= scan_end {
                let start = anchor_abs - anchor_pos;
                if matches_at(&pat.bytes, &pat.mask, haystack, start) {
                    out.push(start);
                }
            }
            bits &= bits - 1;
        }
        i += 32;
    }
    while i <= scan_end {
        if unsafe { *ptr.add(i) } == anchor_byte {
            let start = i - anchor_pos;
            if matches_at(&pat.bytes, &pat.mask, haystack, start) {
                out.push(start);
            }
        }
        i += 1;
    }
    out
}

struct Anchored<'a> {
    idx: usize,
    anchor_pos: usize,
    secondary: Option<(usize, u8)>,
    pat: &'a CompiledPattern,
}

/// A multi-pattern index that scans a buffer once for many patterns instead of rescanning it per
/// pattern. Each pattern is bucketed by its anchor byte; a position whose byte hits a bucket is
/// verified against only the patterns in that bucket, so the work is proportional to the buffer
/// plus the matches, not to the buffer times the pattern count.
///
/// When many patterns share a common anchor byte (the worst case for an anchor-only index, for
/// example a corpus of `48 ...` x64 prologues), the single byte stops discriminating and every
/// position in that bucket pays a full verification. Each bucket entry therefore also carries a
/// second fixed byte at a different offset, the next rarest in the pattern, and the scan rejects a
/// candidate on that one extra comparison before the full compare. The accepted match set is
/// unchanged; the second byte is part of the pattern that the full compare would check regardless.
pub struct ScannerIndex<'a> {
    by_anchor: Vec<Vec<Anchored<'a>>>,
}

impl<'a> ScannerIndex<'a> {
    #[must_use]
    pub fn build(patterns: impl Iterator<Item = (usize, &'a CompiledPattern)>) -> Self {
        let mut by_anchor: Vec<Vec<Anchored<'a>>> = (0..256).map(|_| Vec::new()).collect();
        for (idx, pat) in patterns {
            if let Some((anchor_pos, anchor_byte)) = pat.anchor {
                by_anchor[anchor_byte as usize].push(Anchored {
                    idx,
                    anchor_pos,
                    secondary: pat.secondary,
                    pat,
                });
            }
        }
        Self { by_anchor }
    }

    /// Scan `haystack` once, calling `hit(pattern_idx, start)` for every match whose start is below
    /// `accept_len`. The set of `(pattern_idx, start)` pairs is identical to running [`find_all`]
    /// per pattern; only the order differs (callers sort).
    pub fn scan(&self, haystack: &[u8], accept_len: usize, mut hit: impl FnMut(usize, usize)) {
        let n = haystack.len();
        for pos in 0..n {
            for a in &self.by_anchor[haystack[pos] as usize] {
                if pos < a.anchor_pos {
                    continue;
                }
                let start = pos - a.anchor_pos;
                if start >= accept_len {
                    continue;
                }
                if start + a.pat.bytes.len() > n {
                    continue;
                }
                if let Some((sec_pos, sec_byte)) = a.secondary
                    && haystack[start + sec_pos] != sec_byte
                {
                    continue;
                }
                if matches_at(&a.pat.bytes, &a.pat.mask, haystack, start) {
                    hit(a.idx, start);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference(haystack: &[u8], sig: &Signature) -> Vec<usize> {
        let len = sig.bytes.len();
        let mut out = Vec::new();
        if len == 0 || haystack.len() < len {
            return out;
        }
        for start in 0..=haystack.len() - len {
            let mut ok = true;
            for (k, (&byte, &significant)) in sig.bytes.iter().zip(&sig.mask).enumerate() {
                if significant && haystack[start + k] != byte {
                    ok = false;
                    break;
                }
            }
            if ok {
                out.push(start);
            }
        }
        out
    }

    fn sig(bytes: &[u8], mask: &[bool]) -> Signature {
        Signature {
            bytes: bytes.to_vec(),
            mask: mask.to_vec(),
        }
    }

    #[test]
    fn finds_single_known_offset() {
        let mut blob = vec![0u8; 256];
        blob[100..105].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0x12]);
        let s = sig(
            &[0xDE, 0xAD, 0x00, 0xEF, 0x12],
            &[true, true, false, true, true],
        );
        let cp = CompiledPattern::new(&s).unwrap();
        assert_eq!(find_all(&blob, &cp), vec![100]);
    }

    #[test]
    fn finds_multiple_offsets() {
        let mut blob = vec![0u8; 512];
        let needle = [0x11u8, 0x22, 0x33, 0x44];
        blob[10..14].copy_from_slice(&needle);
        blob[300..304].copy_from_slice(&needle);
        let s = sig(&needle, &[true, true, true, true]);
        let cp = CompiledPattern::new(&s).unwrap();
        assert_eq!(find_all(&blob, &cp), vec![10, 300]);
    }

    #[test]
    fn no_match_returns_empty() {
        let blob = vec![0xAAu8; 100];
        let s = sig(&[0x11, 0x22], &[true, true]);
        let cp = CompiledPattern::new(&s).unwrap();
        assert!(find_all(&blob, &cp).is_empty());
    }

    #[test]
    fn all_wildcard_is_rejected_at_compile() {
        let s = sig(&[0, 0, 0], &[false, false, false]);
        assert!(CompiledPattern::new(&s).is_none());
    }

    #[test]
    fn match_at_buffer_end() {
        let mut blob = vec![0u8; 64];
        blob[60..64].copy_from_slice(&[0xCA, 0xFE, 0xBA, 0xBE]);
        let s = sig(&[0xCA, 0xFE, 0xBA, 0xBE], &[true, true, true, true]);
        let cp = CompiledPattern::new(&s).unwrap();
        assert_eq!(find_all(&blob, &cp), vec![60]);
    }

    struct XorShift(u64);
    impl XorShift {
        fn next_u64(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
    }

    #[test]
    fn avx2_matches_reference_on_random_inputs() {
        let mut rng = XorShift(0x9E37_79B9_7F4A_7C15);
        for _ in 0..2000 {
            let n = (rng.next_u64() % 400) as usize + 1;
            let haystack: Vec<u8> = (0..n).map(|_| (rng.next_u64() & 0x7) as u8).collect();
            let plen = (rng.next_u64() % 8) as usize + 1;
            let bytes: Vec<u8> = (0..plen).map(|_| (rng.next_u64() & 0x7) as u8).collect();
            let mask: Vec<bool> = (0..plen).map(|_| rng.next_u64() & 1 == 0).collect();
            let s = sig(&bytes, &mask);
            let Some(cp) = CompiledPattern::new(&s) else {
                continue; // all-wildcard is now rejected at compile
            };
            assert_eq!(find_all(&haystack, &cp), reference(&haystack, &s), "n={n}");
        }
    }

    #[test]
    fn scalar_matches_reference_on_random_inputs() {
        let mut rng = XorShift(0xDEAD_BEEF_CAFE_F00D);
        for _ in 0..2000 {
            let n = (rng.next_u64() % 400) as usize + 1;
            let haystack: Vec<u8> = (0..n).map(|_| (rng.next_u64() & 0x7) as u8).collect();
            let plen = (rng.next_u64() % 8) as usize + 1;
            let bytes: Vec<u8> = (0..plen).map(|_| (rng.next_u64() & 0x7) as u8).collect();
            let mut mask: Vec<bool> = (0..plen).map(|_| rng.next_u64() & 1 == 0).collect();
            mask[0] = true;
            let s = sig(&bytes, &mask);
            let cp = CompiledPattern::new(&s).unwrap();
            assert_eq!(
                find_all_scalar(&haystack, &cp),
                reference(&haystack, &s),
                "n={n}"
            );
        }
    }

    #[test]
    fn scanner_index_matches_per_pattern_find_all() {
        let mut rng = XorShift(0x1234_5678_9ABC_DEF0);
        for _ in 0..1000 {
            let n = (rng.next_u64() % 400) as usize + 1;
            let haystack: Vec<u8> = (0..n).map(|_| (rng.next_u64() & 0x7) as u8).collect();
            let count = (rng.next_u64() % 6) as usize + 1;
            let mut cps = Vec::new();
            for _ in 0..count {
                let plen = (rng.next_u64() % 8) as usize + 1;
                let bytes: Vec<u8> = (0..plen).map(|_| (rng.next_u64() & 0x7) as u8).collect();
                let mut mask: Vec<bool> = (0..plen).map(|_| rng.next_u64() & 1 == 0).collect();
                mask[0] = true;
                cps.push(CompiledPattern::new(&sig(&bytes, &mask)).unwrap());
            }
            let mut expected: Vec<(usize, usize)> = Vec::new();
            for (i, cp) in cps.iter().enumerate() {
                for off in find_all(&haystack, cp) {
                    expected.push((i, off));
                }
            }
            expected.sort_unstable();
            let index = ScannerIndex::build(cps.iter().enumerate());
            let mut actual: Vec<(usize, usize)> = Vec::new();
            index.scan(&haystack, n, |idx, start| actual.push((idx, start)));
            actual.sort_unstable();
            assert_eq!(actual, expected, "n={n}");
        }
    }

    #[test]
    fn secondary_anchor_is_a_distinct_fixed_byte() {
        let s = sig(&[0x48, 0x8B, 0x0D, 0x00], &[true, true, true, false]);
        let cp = CompiledPattern::new(&s).unwrap();
        let (ap, _) = cp.anchor.unwrap();
        let (sp, sb) = cp.secondary_anchor().expect("a second fixed byte exists");
        assert_ne!(
            sp, ap,
            "secondary must sit at a different offset than the anchor"
        );
        assert!(cp.mask[sp], "secondary must land on a fixed byte");
        assert_eq!(cp.bytes[sp], sb);
    }

    #[test]
    fn single_fixed_byte_pattern_has_no_secondary() {
        let s = sig(&[0x48, 0x00, 0x00], &[true, false, false]);
        let cp = CompiledPattern::new(&s).unwrap();
        assert!(cp.secondary_anchor().is_none());
    }

    #[test]
    fn scanner_index_matches_when_patterns_share_an_anchor() {
        let mut rng = XorShift(0x0FEE_1DAD_5EED_C0DE);
        for _ in 0..1000 {
            let n = (rng.next_u64() % 400) as usize + 8;
            // A narrow byte alphabet plus a forced common anchor makes buckets collide, which is
            // the case the secondary pre-filter exists for.
            let haystack: Vec<u8> = (0..n)
                .map(|_| {
                    if rng.next_u64() & 3 == 0 {
                        0x48
                    } else {
                        (rng.next_u64() & 0x7) as u8
                    }
                })
                .collect();
            let count = (rng.next_u64() % 8) as usize + 4;
            let mut cps = Vec::new();
            for _ in 0..count {
                let plen = (rng.next_u64() % 6) as usize + 2;
                let mut bytes: Vec<u8> = (0..plen).map(|_| (rng.next_u64() & 0x7) as u8).collect();
                bytes[0] = 0x48;
                let mut mask: Vec<bool> = (0..plen).map(|_| rng.next_u64() & 1 == 0).collect();
                mask[0] = true;
                cps.push(CompiledPattern::new(&sig(&bytes, &mask)).unwrap());
            }
            let mut expected: Vec<(usize, usize)> = Vec::new();
            for (i, cp) in cps.iter().enumerate() {
                for off in find_all(&haystack, cp) {
                    expected.push((i, off));
                }
            }
            expected.sort_unstable();
            let index = ScannerIndex::build(cps.iter().enumerate());
            let mut actual: Vec<(usize, usize)> = Vec::new();
            index.scan(&haystack, n, |idx, start| actual.push((idx, start)));
            actual.sort_unstable();
            assert_eq!(actual, expected, "n={n}");
        }
    }
}
