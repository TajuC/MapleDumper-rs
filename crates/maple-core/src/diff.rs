use crate::output::Finding;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Moved {
    pub name: String,
    pub category: String,
    pub old: u64,
    pub new: u64,
    pub is_offset: bool,
}

#[derive(Debug, Clone, Default)]
pub struct DiffReport {
    pub added: Vec<Finding>,
    pub removed: Vec<Finding>,
    pub moved: Vec<Moved>,
    pub unchanged: usize,
    /// Advisories about the inputs, currently duplicate symbol names that the name-keyed diff cannot
    /// represent. Surfaced so a collapsed duplicate is visible instead of silently deciding it.
    pub warnings: Vec<String>,
}

// Index findings by name, recording a warning once per name that appears more than once. A duplicate
// name has no well-defined diff (which value is "the" one?), so the last is kept and the ambiguity is
// reported rather than silently resolved.
fn index_by_name<'a>(
    items: &'a [Finding],
    side: &str,
    warnings: &mut Vec<String>,
) -> BTreeMap<&'a str, &'a Finding> {
    let mut map = BTreeMap::new();
    let mut warned = std::collections::BTreeSet::new();
    for f in items {
        if map.insert(f.name.as_str(), f).is_some() && warned.insert(f.name.as_str()) {
            warnings.push(format!(
                "duplicate symbol \"{}\" in the {side} dump; only the last value is compared",
                f.name
            ));
        }
    }
    map
}

#[must_use]
pub fn diff(old: &[Finding], new: &[Finding]) -> DiffReport {
    let mut report = DiffReport::default();
    let old_by_name = index_by_name(old, "old", &mut report.warnings);
    let new_by_name = index_by_name(new, "new", &mut report.warnings);

    for (name, found) in &new_by_name {
        match old_by_name.get(name) {
            None => report.added.push((*found).clone()),
            Some(before) if before.value == found.value => report.unchanged += 1,
            Some(before) => report.moved.push(Moved {
                name: found.name.clone(),
                category: found.category.clone(),
                old: before.value,
                new: found.value,
                is_offset: found.is_offset,
            }),
        }
    }
    for (name, before) in &old_by_name {
        if !new_by_name.contains_key(name) {
            report.removed.push((*before).clone());
        }
    }
    report
}

#[must_use]
pub fn parse_dump(text: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for line in text.lines() {
        let Some(rest) = line.trim().strip_prefix('[') else {
            continue;
        };
        let Some((category, rest)) = rest.split_once(']') else {
            continue;
        };
        let Some((name, value)) = rest.split_once('=') else {
            continue;
        };
        let is_offset = value.contains("(offset)");
        let hex = value.split_whitespace().next().unwrap_or_default();
        let hex = hex
            .strip_prefix("0x")
            .or_else(|| hex.strip_prefix("0X"))
            .unwrap_or(hex);
        let Ok(value) = u64::from_str_radix(hex, 16) else {
            continue;
        };
        findings.push(Finding {
            name: name.trim().to_string(),
            category: category.trim().to_string(),
            value,
            is_offset,
        });
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::plain_text;

    fn f(name: &str, value: u64) -> Finding {
        Finding {
            name: name.to_string(),
            category: "globals".to_string(),
            value,
            is_offset: false,
        }
    }

    #[test]
    fn classifies_each_symbol() {
        let old = vec![f("A", 1), f("B", 2), f("C", 3)];
        let new = vec![f("A", 1), f("B", 9), f("D", 4)];
        let report = diff(&old, &new);
        assert_eq!(report.unchanged, 1);
        assert_eq!(report.moved.len(), 1);
        assert_eq!(report.moved[0].name, "B");
        assert_eq!((report.moved[0].old, report.moved[0].new), (2, 9));
        assert_eq!(report.added.len(), 1);
        assert_eq!(report.added[0].name, "D");
        assert_eq!(report.removed.len(), 1);
        assert_eq!(report.removed[0].name, "C");
    }

    #[test]
    fn parses_a_plain_text_dump_back() {
        let findings = vec![
            Finding {
                name: "Hp".to_string(),
                category: "offsets".to_string(),
                value: 0x40,
                is_offset: true,
            },
            f("Foo", 0xABCD),
        ];
        let parsed = parse_dump(&plain_text(&findings, "MapleStory.exe", 0x1000, None));
        let report = diff(&findings, &parsed);
        assert_eq!(report.unchanged, 2);
        assert!(report.added.is_empty() && report.removed.is_empty() && report.moved.is_empty());
        assert!(
            parsed
                .iter()
                .any(|f| f.name == "Hp" && f.value == 0x40 && f.is_offset)
        );
    }

    #[test]
    fn duplicate_names_are_flagged_not_silently_collapsed() {
        let old = vec![f("A", 1), f("A", 2), f("B", 5)];
        let new = vec![f("A", 2), f("B", 5)];
        let report = diff(&old, &new);
        assert!(
            report
                .warnings
                .iter()
                .any(|w| w.contains("duplicate symbol \"A\"") && w.contains("old")),
            "a duplicate name must be surfaced, got {:?}",
            report.warnings
        );
        // The last A (value 2) is what gets compared, so A reads as unchanged against the new A=2.
        assert_eq!(report.unchanged, 2);
    }
}
