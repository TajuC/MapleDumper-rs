use crate::pattern::Signature;
use crate::scanner::byte_frequency;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lint {
    NoFixedBytes,
    FewFixedBytes(usize),
    ShortPattern(usize),
    WeakAnchor(u8),
}

impl Lint {
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            Lint::NoFixedBytes => "no fixed bytes, so it matches everywhere".to_string(),
            Lint::FewFixedBytes(n) => {
                format!("only {n} fixed bytes, so it is likely to match in several places")
            }
            Lint::ShortPattern(n) => format!("only {n} bytes long, which is prone to collisions"),
            Lint::WeakAnchor(b) => {
                format!(
                    "its rarest fixed byte is 0x{b:02X}, a common one, so the prefilter hits often"
                )
            }
        }
    }
}

#[must_use]
pub fn lint(signature: &Signature) -> Vec<Lint> {
    let fixed: Vec<u8> = signature
        .bytes
        .iter()
        .zip(&signature.mask)
        .filter_map(|(&byte, &significant)| significant.then_some(byte))
        .collect();

    let mut lints = Vec::new();
    if fixed.is_empty() {
        lints.push(Lint::NoFixedBytes);
        return lints;
    }
    if fixed.len() < 4 {
        lints.push(Lint::FewFixedBytes(fixed.len()));
    }
    if signature.bytes.len() < 5 {
        lints.push(Lint::ShortPattern(signature.bytes.len()));
    }
    let rarest = fixed
        .iter()
        .copied()
        .min_by_key(|&b| byte_frequency(b))
        .expect("fixed is non-empty");
    if byte_frequency(rarest) > 100 {
        lints.push(Lint::WeakAnchor(rarest));
    }
    lints
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sig(bytes: &[u8], mask: &[bool]) -> Signature {
        Signature {
            bytes: bytes.to_vec(),
            mask: mask.to_vec(),
        }
    }

    #[test]
    fn rare_and_long_pattern_is_clean() {
        let s = sig(
            &[0xDE, 0xAD, 0xBE, 0xEF, 0x3C, 0x7D],
            &[true, true, true, true, true, true],
        );
        assert!(lint(&s).is_empty());
    }

    #[test]
    fn all_wildcard_is_flagged() {
        let s = sig(&[0, 0, 0], &[false, false, false]);
        assert_eq!(lint(&s), vec![Lint::NoFixedBytes]);
    }

    #[test]
    fn short_common_pattern_collects_every_lint() {
        let s = sig(&[0x48, 0x48], &[true, true]);
        let lints = lint(&s);
        assert!(lints.contains(&Lint::FewFixedBytes(2)));
        assert!(lints.contains(&Lint::ShortPattern(2)));
        assert!(lints.contains(&Lint::WeakAnchor(0x48)));
    }

    #[test]
    fn wildcards_do_not_count_toward_length_anchor() {
        let s = sig(
            &[0xE8, 0x00, 0x00, 0x00, 0x00, 0x8B, 0x42, 0x0F],
            &[true, false, false, false, false, true, true, true],
        );
        assert!(!lint(&s).iter().any(|l| matches!(l, Lint::WeakAnchor(_))));
    }
}
