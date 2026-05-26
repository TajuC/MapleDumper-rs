use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    X86,
    X64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    pub bytes: Vec<u8>,
    pub mask: Vec<bool>,
}

impl Signature {
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pattern {
    pub name: String,
    pub category: String,
    pub signature: Signature,
}

enum Token {
    Byte(u8),
    Wild,
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn parse_token(raw: &str) -> Option<Token> {
    let trimmed = raw.trim_end_matches(',');
    if trimmed.is_empty() {
        return None;
    }
    let upper = trimmed.to_ascii_uppercase();
    if upper == "?" || upper == "??" {
        return Some(Token::Wild);
    }
    let bytes = upper.as_bytes();
    if upper.len() == 2 && (bytes[0] == b'?' || bytes[1] == b'?') {
        return Some(Token::Wild);
    }
    let hex = upper.strip_prefix("0X").unwrap_or(upper.as_str());
    let hex_bytes = hex.as_bytes();
    if hex_bytes.len() != 2 {
        return None;
    }
    let hi = hex_val(hex_bytes[0])?;
    let lo = hex_val(hex_bytes[1])?;
    Some(Token::Byte((hi << 4) | lo))
}

fn parse_signature(aob: &str) -> Signature {
    let mut bytes = Vec::new();
    let mut mask = Vec::new();
    for tok in aob.split_whitespace() {
        match parse_token(tok) {
            Some(Token::Byte(value)) => {
                bytes.push(value);
                mask.push(true);
            }
            Some(Token::Wild) => {
                bytes.push(0);
                mask.push(false);
            }
            None => {}
        }
    }
    Signature { bytes, mask }
}

fn strip_quotes(s: &str) -> &str {
    let b = s.as_bytes();
    if b.len() >= 2 && b[0] == b'"' && b[b.len() - 1] == b'"' {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

fn split_name_aob(line: &str) -> Option<(String, String)> {
    let without_comment = match line.find([';', '#']) {
        Some(i) => &line[..i],
        None => line,
    };
    let s = without_comment.trim();
    if s.is_empty() {
        return None;
    }
    let (name, aob) = if let Some(i) = s.find('=').or_else(|| s.find(':')) {
        (s[..i].trim(), s[i + 1..].trim())
    } else {
        let i = s.find([' ', '\t'])?;
        (s[..i].trim(), s[i + 1..].trim())
    };
    let aob = strip_quotes(aob);
    if name.is_empty() || aob.is_empty() {
        return None;
    }
    Some((name.to_string(), aob.to_string()))
}

#[must_use]
pub fn parse_patterns(text: &str, arch: Arch) -> Vec<Pattern> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut out = Vec::new();
    let mut section: Option<Arch> = None;
    let mut category = String::from("globals");
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('#') {
            if line.contains("32BIT") {
                section = Some(Arch::X86);
            } else if line.contains("64BIT") {
                section = Some(Arch::X64);
            }
            continue;
        }
        if let Some(inner) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            let trimmed = inner.trim();
            if !trimmed.is_empty() {
                category = trimmed.to_string();
            }
            continue;
        }
        if let Some(sec) = section
            && sec != arch
        {
            continue;
        }
        if let Some((name, aob)) = split_name_aob(line) {
            let signature = parse_signature(&aob);
            if !signature.is_empty() {
                out.push(Pattern {
                    name,
                    category: category.clone(),
                    signature,
                });
            }
        }
    }
    out
}

pub fn parse_patterns_file(path: &Path, arch: Arch) -> std::io::Result<Vec<Pattern>> {
    let raw = std::fs::read(path)?;
    let text = String::from_utf8_lossy(&raw);
    Ok(parse_patterns(&text, arch))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(patterns: &[Pattern]) -> Vec<&str> {
        patterns.iter().map(|p| p.name.as_str()).collect()
    }

    #[test]
    fn equals_separator() {
        let p = parse_patterns("Foo = AA BB CC ?? DD", Arch::X64);
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].name, "Foo");
        assert_eq!(p[0].signature.bytes, vec![0xAA, 0xBB, 0xCC, 0x00, 0xDD]);
        assert_eq!(p[0].signature.mask, vec![true, true, true, false, true]);
    }

    #[test]
    fn colon_separator_and_0x_prefix() {
        let p = parse_patterns("Bar: 0xAA 0xBB ?? DD", Arch::X64);
        assert_eq!(p[0].name, "Bar");
        assert_eq!(p[0].signature.bytes, vec![0xAA, 0xBB, 0x00, 0xDD]);
        assert_eq!(p[0].signature.mask, vec![true, true, false, true]);
    }

    #[test]
    fn space_separator() {
        let p = parse_patterns("Baz AA BB ?? DD", Arch::X64);
        assert_eq!(p[0].name, "Baz");
        assert_eq!(p[0].signature.bytes.len(), 4);
    }

    #[test]
    fn single_question_mark_is_wildcard() {
        let p = parse_patterns("W = AA ? BB", Arch::X64);
        assert_eq!(p[0].signature.mask, vec![true, false, true]);
    }

    #[test]
    fn commas_are_allowed() {
        let p = parse_patterns("C = AA, BB, ??, DD", Arch::X64);
        assert_eq!(p[0].signature.bytes, vec![0xAA, 0xBB, 0x00, 0xDD]);
        assert_eq!(p[0].signature.mask, vec![true, true, false, true]);
    }

    #[test]
    fn semicolon_inline_comment_ignored() {
        let p = parse_patterns("C = AA BB ; comment CC DD", Arch::X64);
        assert_eq!(p[0].signature.bytes, vec![0xAA, 0xBB]);
    }

    #[test]
    fn hash_inline_comment_ignored() {
        let p = parse_patterns("C = AA BB # comment", Arch::X64);
        assert_eq!(p[0].signature.bytes, vec![0xAA, 0xBB]);
    }

    #[test]
    fn quoted_aob_unwrapped() {
        let p = parse_patterns("C = \"AA BB CC\"", Arch::X64);
        assert_eq!(p[0].signature.bytes, vec![0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn section_filtering_selects_arch() {
        let text = "#64BIT\nA = 11 22\n#32BIT\nB = 33 44";
        assert_eq!(names(&parse_patterns(text, Arch::X64)), vec!["A"]);
        assert_eq!(names(&parse_patterns(text, Arch::X86)), vec!["B"]);
    }

    #[test]
    fn comment_line_does_not_reset_section() {
        let text = "#64BIT\nA = 11 22\n# just a comment\nB = 33 44\n#32BIT\nC = 55 66";
        assert_eq!(names(&parse_patterns(text, Arch::X86)), vec!["C"]);
        assert_eq!(names(&parse_patterns(text, Arch::X64)), vec!["A", "B"]);
    }

    #[test]
    fn patterns_before_any_section_apply_to_both() {
        let text = "Both = AA\n#64BIT\nOnly64 = BB";
        assert!(
            parse_patterns(text, Arch::X86)
                .iter()
                .any(|p| p.name == "Both")
        );
        assert!(
            parse_patterns(text, Arch::X64)
                .iter()
                .any(|p| p.name == "Both")
        );
        assert!(
            !parse_patterns(text, Arch::X86)
                .iter()
                .any(|p| p.name == "Only64")
        );
    }

    #[test]
    fn bom_is_stripped() {
        let p = parse_patterns("\u{feff}Foo = AA BB", Arch::X64);
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].name, "Foo");
    }

    #[test]
    fn crlf_lines_handled() {
        let p = parse_patterns("A = AA BB\r\nB = CC DD\r\n", Arch::X64);
        assert_eq!(p.len(), 2);
        assert_eq!(p[1].signature.bytes, vec![0xCC, 0xDD]);
    }

    #[test]
    fn invalid_tokens_skipped() {
        let p = parse_patterns("A = AA ZZ BB", Arch::X64);
        assert_eq!(p[0].signature.bytes, vec![0xAA, 0xBB]);
    }

    #[test]
    fn lowercase_hex_accepted() {
        let p = parse_patterns("A = aa bb cc", Arch::X64);
        assert_eq!(p[0].signature.bytes, vec![0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn lines_without_aob_are_skipped() {
        assert!(parse_patterns("JustAName", Arch::X64).is_empty());
        assert!(parse_patterns("", Arch::X64).is_empty());
        assert!(parse_patterns("   ", Arch::X64).is_empty());
    }

    #[test]
    fn default_category_is_globals() {
        let p = parse_patterns("Foo = AA", Arch::X64);
        assert_eq!(p[0].category, "globals");
    }

    #[test]
    fn category_sections_apply_to_following_patterns() {
        let text = "[functions]\nFoo = AA\n[offsets]\nBar = BB\nBaz = CC";
        let p = parse_patterns(text, Arch::X64);
        assert_eq!(p[0].category, "functions");
        assert_eq!(p[1].category, "offsets");
        assert_eq!(p[2].category, "offsets");
    }
}
