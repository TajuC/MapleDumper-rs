use crate::domain::{ExpectedHits, ResolvePlan, ResolverSpec, SectionKind, StringAnchor};
use crate::resolver::Kind;
use std::collections::HashMap;
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

    #[must_use]
    pub fn to_aob(&self) -> String {
        self.bytes
            .iter()
            .zip(&self.mask)
            .map(|(b, &significant)| {
                if significant {
                    format!("{b:02X}")
                } else {
                    "??".to_string()
                }
            })
            .collect::<Vec<_>>()
            .join(" ")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pattern {
    pub name: String,
    pub category: Option<String>,
    pub note: Option<String>,
    pub signature: Signature,
    /// An explicit, typed resolution plan from a pattern schema. `None` means the resolver kind is
    /// derived from the name suffix (the legacy form).
    pub resolve: Option<ResolvePlan>,
    /// A string-anchored target (located by referenced strings, not bytes). When set, `signature` is
    /// empty and the engine resolves this by string reference instead of scanning.
    pub string_anchor: Option<StringAnchor>,
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

#[must_use]
pub fn signature_from_aob(aob: &str) -> Signature {
    parse_signature(aob)
}

/// Like [`signature_from_aob`] but rejects malformed input instead of silently dropping unparseable
/// tokens. Use this at trust boundaries (CLI/GUI) where the AOB comes from a user.
pub fn try_signature_from_aob(aob: &str) -> Result<Signature, String> {
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
            None => return Err(format!("invalid AOB token: '{tok}'")),
        }
    }
    if bytes.is_empty() {
        return Err("signature is empty".to_string());
    }
    Ok(Signature { bytes, mask })
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

fn split_name_aob(line: &str) -> Option<(String, String, String)> {
    let (body, note) = match line.find([';', '#']) {
        Some(i) => (&line[..i], line[i + 1..].trim()),
        None => (line, ""),
    };
    let s = body.trim();
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
    Some((name.to_string(), aob.to_string(), note.to_string()))
}

// Split `@key=value` schema directives out of an AOB, returning the AOB without them and the
// directive list. Tokens without a leading `@` are signature bytes.
fn split_directives(aob: &str) -> (String, Vec<(String, String)>) {
    let mut sig = Vec::new();
    let mut directives = Vec::new();
    for tok in aob.split_whitespace() {
        if let Some(rest) = tok.strip_prefix('@') {
            let (k, v) = rest.split_once('=').unwrap_or((rest, ""));
            directives.push((k.to_ascii_lowercase(), v.to_string()));
        } else {
            sig.push(tok);
        }
    }
    (sig.join(" "), directives)
}

// Build a typed resolve plan from schema directives. With no directives the resolver kind stays
// derived from the name suffix (returns `None`). A directive sets the kind explicitly and refines
// how the target is read and validated.
fn build_resolve_plan(
    name: &str,
    directives: &[(String, String)],
) -> Result<Option<ResolvePlan>, String> {
    if directives.is_empty() {
        return Ok(None);
    }
    let (suffix_kind, _) = Kind::classify(name);
    let mut plan = ResolvePlan::new(suffix_kind.spec());
    for (k, v) in directives {
        match k.as_str() {
            "kind" => {
                plan.kind = ResolverSpec::from_keyword(v)
                    .ok_or_else(|| format!("unknown resolver kind '{v}'"))?;
            }
            "instr" | "instruction" => {
                plan.instruction_offset = v
                    .trim()
                    .parse()
                    .map_err(|_| format!("invalid instruction offset '{v}'"))?;
            }
            "operand" => {
                plan.operand_index = Some(
                    v.trim()
                        .parse()
                        .map_err(|_| format!("invalid operand index '{v}'"))?,
                );
            }
            "section" => {
                plan.expected_section = Some(
                    SectionKind::from_keyword(v).ok_or_else(|| format!("unknown section '{v}'"))?,
                );
            }
            "hits" => {
                plan.expected_hits =
                    ExpectedHits::from_keyword(v).ok_or_else(|| format!("invalid hits '{v}'"))?;
            }
            other => return Err(format!("unknown directive '@{other}'")),
        }
    }
    Ok(Some(plan))
}

fn build_string_anchor(directives: &[(String, String)]) -> Option<StringAnchor> {
    let find = |key: &str| {
        directives
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.clone())
    };
    find("string")
        .filter(|t| !t.is_empty())
        .map(|text| StringAnchor {
            text,
            also: find("also").filter(|t| !t.is_empty()),
        })
}

fn partition_anchor_directives(
    directives: Vec<(String, String)>,
) -> (Option<StringAnchor>, Vec<(String, String)>) {
    let (anchor, resolve): (Vec<_>, Vec<_>) = directives
        .into_iter()
        .partition(|(k, _)| matches!(k.as_str(), "string" | "also"));
    (build_string_anchor(&anchor), resolve)
}

#[must_use]
pub fn parse_patterns(text: &str, arch: Arch) -> Vec<Pattern> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut out = Vec::new();
    let mut section: Option<Arch> = None;
    let mut category: Option<String> = None;
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
                category = Some(trimmed.to_string());
            }
            continue;
        }
        if let Some(sec) = section
            && sec != arch
        {
            continue;
        }
        if let Some((name, aob, note)) = split_name_aob(line) {
            let (aob, directives) = split_directives(&aob);
            let (string_anchor, directives) = partition_anchor_directives(directives);
            let resolve = build_resolve_plan(&name, &directives).ok().flatten();
            let signature = parse_signature(&aob);
            if !signature.is_empty() || string_anchor.is_some() {
                out.push(Pattern {
                    name,
                    category: category.clone(),
                    note: (!note.is_empty()).then_some(note),
                    signature,
                    resolve,
                    string_anchor,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseSeverity {
    Error,
    Warning,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseIssue {
    pub line: usize,
    pub severity: ParseSeverity,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedPatterns {
    pub patterns: Vec<Pattern>,
    pub warnings: Vec<ParseIssue>,
}

fn parse_token_strict(raw: &str) -> Result<Token, String> {
    let trimmed = raw.trim_end_matches(',');
    if trimmed.is_empty() {
        return Err("empty token".to_string());
    }
    let upper = trimmed.to_ascii_uppercase();
    if upper == "?" || upper == "??" {
        return Ok(Token::Wild);
    }
    let hex = upper.strip_prefix("0X").unwrap_or(upper.as_str());
    let bytes = hex.as_bytes();
    if bytes.len() == 2 && (bytes[0] == b'?' || bytes[1] == b'?') {
        return Err(format!("partial-nibble wildcard '{raw}'; use ?? instead"));
    }
    if bytes.len() != 2 {
        return Err(format!("invalid token '{raw}'"));
    }
    match (hex_val(bytes[0]), hex_val(bytes[1])) {
        (Some(hi), Some(lo)) => Ok(Token::Byte((hi << 4) | lo)),
        _ => Err(format!("invalid hex byte '{raw}'")),
    }
}

/// Parse a pattern list with validation instead of silently dropping malformed input. A bad token,
/// a partial-nibble wildcard, an all-wildcard or empty signature, and a duplicate name are hard
/// errors; a very short or duplicated signature is a warning. Use this on every load path that
/// comes from a user, and keep [`parse_patterns`] only where lenient best-effort parsing is wanted.
///
/// # Errors
/// Returns the collected issues when any of them is an error.
pub fn parse_patterns_strict(text: &str, arch: Arch) -> Result<ParsedPatterns, Vec<ParseIssue>> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut out = Vec::new();
    let mut issues = Vec::new();
    let mut section: Option<Arch> = None;
    let mut category: Option<String> = None;
    let mut seen_names: HashMap<String, usize> = HashMap::new();
    let mut seen_sigs: HashMap<String, String> = HashMap::new();

    for (i, raw_line) in text.lines().enumerate() {
        let line_no = i + 1;
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
                category = Some(trimmed.to_string());
            }
            continue;
        }
        if let Some(sec) = section
            && sec != arch
        {
            continue;
        }
        let Some((name, aob, note)) = split_name_aob(line) else {
            issues.push(ParseIssue {
                line: line_no,
                severity: ParseSeverity::Warning,
                message: format!("ignored line (not a 'name = AOB' pattern): {line}"),
            });
            continue;
        };

        let (aob, directives) = split_directives(&aob);
        let (string_anchor, directives) = partition_anchor_directives(directives);
        if let Some(anchor) = string_anchor {
            if let Some(prev) = seen_names.get(&name) {
                issues.push(ParseIssue {
                    line: line_no,
                    severity: ParseSeverity::Error,
                    message: format!("duplicate pattern name '{name}' (first seen on line {prev})"),
                });
                continue;
            }
            seen_names.insert(name.clone(), line_no);
            out.push(Pattern {
                name,
                category: category.clone(),
                note: (!note.is_empty()).then_some(note),
                signature: Signature {
                    bytes: Vec::new(),
                    mask: Vec::new(),
                },
                resolve: None,
                string_anchor: Some(anchor),
            });
            continue;
        }
        let resolve = match build_resolve_plan(&name, &directives) {
            Ok(plan) => plan,
            Err(msg) => {
                issues.push(ParseIssue {
                    line: line_no,
                    severity: ParseSeverity::Error,
                    message: format!("{name}: {msg}"),
                });
                continue;
            }
        };

        let mut bytes = Vec::new();
        let mut mask = Vec::new();
        let mut token_error = false;
        for tok in aob.split_whitespace() {
            match parse_token_strict(tok) {
                Ok(Token::Byte(value)) => {
                    bytes.push(value);
                    mask.push(true);
                }
                Ok(Token::Wild) => {
                    bytes.push(0);
                    mask.push(false);
                }
                Err(msg) => {
                    issues.push(ParseIssue {
                        line: line_no,
                        severity: ParseSeverity::Error,
                        message: format!("{name}: {msg}"),
                    });
                    token_error = true;
                }
            }
        }
        if token_error {
            continue;
        }
        if bytes.is_empty() {
            issues.push(ParseIssue {
                line: line_no,
                severity: ParseSeverity::Error,
                message: format!("{name}: empty signature"),
            });
            continue;
        }
        if mask.iter().all(|&m| !m) {
            issues.push(ParseIssue {
                line: line_no,
                severity: ParseSeverity::Error,
                message: format!("{name}: all-wildcard signature would match everywhere"),
            });
            continue;
        }
        if let Some(prev) = seen_names.get(&name) {
            issues.push(ParseIssue {
                line: line_no,
                severity: ParseSeverity::Error,
                message: format!("duplicate pattern name '{name}' (first seen on line {prev})"),
            });
            continue;
        }
        if bytes.len() < 4 {
            issues.push(ParseIssue {
                line: line_no,
                severity: ParseSeverity::Warning,
                message: format!(
                    "{name}: signature is only {} bytes and may match widely",
                    bytes.len()
                ),
            });
        }
        let signature = Signature { bytes, mask };
        let aob_norm = signature.to_aob();
        if let Some(prev_name) = seen_sigs.get(&aob_norm) {
            issues.push(ParseIssue {
                line: line_no,
                severity: ParseSeverity::Warning,
                message: format!("{name}: identical signature to '{prev_name}'"),
            });
        } else {
            seen_sigs.insert(aob_norm, name.clone());
        }
        seen_names.insert(name.clone(), line_no);
        out.push(Pattern {
            name,
            category: category.clone(),
            note: (!note.is_empty()).then_some(note),
            signature,
            resolve,
            string_anchor: None,
        });
    }

    if issues.iter().any(|x| x.severity == ParseSeverity::Error) {
        Err(issues)
    } else {
        Ok(ParsedPatterns {
            patterns: out,
            warnings: issues,
        })
    }
}

/// Strict variant of [`parse_patterns_file`]. The outer result is the file read; the inner result
/// is the validation outcome.
///
/// # Errors
/// Returns an I/O error if the file cannot be read.
pub fn parse_patterns_file_strict(
    path: &Path,
    arch: Arch,
) -> std::io::Result<Result<ParsedPatterns, Vec<ParseIssue>>> {
    let raw = std::fs::read(path)?;
    let text = String::from_utf8_lossy(&raw);
    Ok(parse_patterns_strict(&text, arch))
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
    fn default_category_is_unspecified() {
        let p = parse_patterns("Foo = AA", Arch::X64);
        assert_eq!(p[0].category, None);
    }

    #[test]
    fn category_sections_apply_to_following_patterns() {
        let text = "[functions]\nFoo = AA\n[offsets]\nBar = BB\nBaz = CC";
        let p = parse_patterns(text, Arch::X64);
        assert_eq!(p[0].category.as_deref(), Some("functions"));
        assert_eq!(p[1].category.as_deref(), Some("offsets"));
        assert_eq!(p[2].category.as_deref(), Some("offsets"));
    }

    #[test]
    fn strict_rejects_bad_token_instead_of_dropping_it() {
        let err = parse_patterns_strict("A = AA ZZ BB", Arch::X64).unwrap_err();
        assert!(
            err.iter()
                .any(|i| i.severity == ParseSeverity::Error && i.message.contains("ZZ"))
        );
    }

    #[test]
    fn strict_rejects_partial_nibble_wildcard() {
        let err = parse_patterns_strict("A = AA B? CC DD", Arch::X64).unwrap_err();
        assert!(err.iter().any(|i| i.message.contains("partial-nibble")));
    }

    #[test]
    fn strict_rejects_all_wildcard() {
        let err = parse_patterns_strict("A = ?? ?? ??", Arch::X64).unwrap_err();
        assert!(err.iter().any(|i| i.message.contains("all-wildcard")));
    }

    #[test]
    fn strict_rejects_duplicate_name() {
        let err =
            parse_patterns_strict("Foo = AA BB CC DD\nFoo = 11 22 33 44", Arch::X64).unwrap_err();
        assert!(
            err.iter()
                .any(|i| i.message.contains("duplicate pattern name 'Foo'"))
        );
    }

    #[test]
    fn strict_warns_on_short_and_duplicate_signature() {
        let parsed = parse_patterns_strict("A = AA BB\nB = AA BB", Arch::X64).unwrap();
        assert_eq!(parsed.patterns.len(), 2);
        assert!(
            parsed
                .warnings
                .iter()
                .any(|w| w.message.contains("2 bytes"))
        );
        assert!(
            parsed
                .warnings
                .iter()
                .any(|w| w.message.contains("identical signature"))
        );
    }

    #[test]
    fn strict_accepts_clean_patterns_without_warnings() {
        let parsed = parse_patterns_strict(
            "Foo = AA BB CC DD\nBar_PTR = 48 8D 0D ?? ?? ?? ??",
            Arch::X64,
        )
        .unwrap();
        assert_eq!(parsed.patterns.len(), 2);
        assert!(parsed.warnings.is_empty());
    }

    #[test]
    fn schema_kind_overrides_the_suffix() {
        let parsed = parse_patterns_strict("Foo_CALL = AA BB CC DD @kind=ptr", Arch::X64).unwrap();
        assert_eq!(
            parsed.patterns[0].resolve.as_ref().unwrap().kind,
            ResolverSpec::MemoryPointer
        );
    }

    #[test]
    fn schema_refinements_parse() {
        let parsed = parse_patterns_strict(
            "Foo = AA BB CC DD @kind=ptr @section=code @hits=unique @instr=1 @operand=0",
            Arch::X64,
        )
        .unwrap();
        let plan = parsed.patterns[0].resolve.as_ref().unwrap();
        assert_eq!(plan.kind, ResolverSpec::MemoryPointer);
        assert_eq!(plan.expected_section, Some(SectionKind::Code));
        assert_eq!(plan.expected_hits, ExpectedHits::Unique);
        assert_eq!(plan.instruction_offset, 1);
        assert_eq!(plan.operand_index, Some(0));
    }

    #[test]
    fn schema_unknown_directive_is_an_error() {
        assert!(parse_patterns_strict("Foo = AA BB CC DD @kind=bogus", Arch::X64).is_err());
        assert!(parse_patterns_strict("Foo = AA BB CC DD @whatever=1", Arch::X64).is_err());
    }

    #[test]
    fn no_directives_means_legacy_suffix() {
        let parsed = parse_patterns_strict("Foo_PTR = AA BB CC DD", Arch::X64).unwrap();
        assert!(parsed.patterns[0].resolve.is_none());
    }

    #[test]
    fn directives_are_stripped_from_the_signature() {
        let p = parse_patterns("Foo = AA BB @kind=call CC DD", Arch::X64);
        assert_eq!(p[0].signature.bytes.len(), 4);
        assert_eq!(
            p[0].resolve.as_ref().unwrap().kind,
            ResolverSpec::NestedCall
        );
    }

    #[test]
    fn parses_a_string_anchored_pattern() {
        let pats = parse_patterns("Stat = @string=UI/UIWindow2.img/Stat", Arch::X86);
        assert_eq!(pats.len(), 1);
        let anchor = pats[0].string_anchor.as_ref().unwrap();
        assert_eq!(anchor.text, "UI/UIWindow2.img/Stat");
        assert!(anchor.also.is_none());
        assert!(pats[0].signature.is_empty());
    }

    #[test]
    fn parses_a_paired_string_anchor() {
        let pats = parse_patterns("Stat = @string=pathA @also=pathB", Arch::X86);
        let anchor = pats[0].string_anchor.as_ref().unwrap();
        assert_eq!(anchor.text, "pathA");
        assert_eq!(anchor.also.as_deref(), Some("pathB"));
    }

    #[test]
    fn strict_accepts_a_string_anchored_pattern() {
        let parsed = parse_patterns_strict("Stat = @string=UI/Foo", Arch::X86).unwrap();
        assert_eq!(parsed.patterns.len(), 1);
        assert_eq!(
            parsed.patterns[0].string_anchor.as_ref().unwrap().text,
            "UI/Foo"
        );
        assert!(parsed.patterns[0].signature.is_empty());
    }
}
