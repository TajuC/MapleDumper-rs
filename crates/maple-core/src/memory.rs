use std::io;

/// A source of bytes addressed by absolute virtual address (a live process or a mapped file).
pub trait MemorySource {
    /// Read into `buf` starting at `address`, returning how many bytes were written. An
    /// implementation writes only `buf[..n]` for the returned `n` and never reads `buf`. A short
    /// return means the readable range ended; it is not an error.
    fn read_into(&self, address: usize, buf: &mut [u8]) -> io::Result<usize>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Region {
    pub base: usize,
    pub size: usize,
}

impl Region {
    #[must_use]
    pub fn end(&self) -> usize {
        self.base.saturating_add(self.size)
    }
}

#[must_use]
pub fn coalesce(mut regions: Vec<Region>) -> Vec<Region> {
    if regions.is_empty() {
        return regions;
    }
    regions.sort_by_key(|r| r.base);
    let mut merged: Vec<Region> = Vec::with_capacity(regions.len());
    let mut cur = regions[0];
    for next in regions.into_iter().skip(1) {
        if next.base <= cur.end() {
            let new_end = cur.end().max(next.end());
            cur.size = new_end - cur.base;
        } else {
            merged.push(cur);
            cur = next;
        }
    }
    merged.push(cur);
    merged
}

#[must_use]
pub fn clip_regions(regions: &[Region], from: Option<usize>, to: Option<usize>) -> Vec<Region> {
    let lo = from.unwrap_or(0);
    let hi = to.unwrap_or(usize::MAX);
    if lo >= hi {
        return Vec::new();
    }
    regions
        .iter()
        .filter_map(|r| {
            let start = r.base.max(lo);
            let end = r.end().min(hi);
            (start < end).then(|| Region {
                base: start,
                size: end - start,
            })
        })
        .collect()
}

pub struct BufferSource {
    base: usize,
    data: Vec<u8>,
}

impl BufferSource {
    #[must_use]
    pub fn new(base: usize, data: Vec<u8>) -> Self {
        Self { base, data }
    }
}

impl MemorySource for BufferSource {
    fn read_into(&self, address: usize, buf: &mut [u8]) -> io::Result<usize> {
        if address < self.base {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        let offset = address - self.base;
        if offset >= self.data.len() {
            return Ok(0);
        }
        let n = buf.len().min(self.data.len() - offset);
        buf[..n].copy_from_slice(&self.data[offset..offset + n]);
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(base: usize, size: usize) -> Region {
        Region { base, size }
    }

    #[test]
    fn empty_stays_empty() {
        assert!(coalesce(vec![]).is_empty());
    }

    #[test]
    fn region_end_saturates_instead_of_overflowing() {
        let r = Region {
            base: usize::MAX - 4,
            size: 16,
        };
        assert_eq!(r.end(), usize::MAX);
    }

    #[test]
    fn adjacent_regions_merge() {
        assert_eq!(coalesce(vec![r(0, 10), r(10, 10)]), vec![r(0, 20)]);
    }

    #[test]
    fn gap_is_preserved() {
        assert_eq!(
            coalesce(vec![r(0, 10), r(20, 10)]),
            vec![r(0, 10), r(20, 10)]
        );
    }

    #[test]
    fn overlap_merges() {
        assert_eq!(coalesce(vec![r(0, 15), r(10, 10)]), vec![r(0, 20)]);
    }

    #[test]
    fn unsorted_input_is_sorted_and_merged() {
        assert_eq!(
            coalesce(vec![r(20, 10), r(0, 10), r(10, 10)]),
            vec![r(0, 30)]
        );
    }

    #[test]
    fn clip_regions_intersects_with_range() {
        let regs = [r(0x1000, 0x1000), r(0x3000, 0x1000)];
        assert_eq!(
            clip_regions(&regs, Some(0x1800), Some(0x3800)),
            vec![r(0x1800, 0x800), r(0x3000, 0x800)]
        );
        assert_eq!(clip_regions(&regs, None, None), regs.to_vec());
        assert!(clip_regions(&regs, Some(0x9000), Some(0xA000)).is_empty());
        assert!(clip_regions(&regs, Some(0x4000), Some(0x1000)).is_empty());
    }

    #[test]
    fn buffer_source_reads_within_range() {
        let src = BufferSource::new(0x1000, vec![1, 2, 3, 4, 5]);
        let mut buf = [0u8; 3];
        assert_eq!(src.read_into(0x1002, &mut buf).unwrap(), 3);
        assert_eq!(buf, [3, 4, 5]);
    }

    #[test]
    fn buffer_source_truncates_at_end() {
        let src = BufferSource::new(0x1000, vec![1, 2, 3]);
        let mut buf = [0u8; 8];
        assert_eq!(src.read_into(0x1001, &mut buf).unwrap(), 2);
        assert_eq!(&buf[..2], &[2, 3]);
    }
}
