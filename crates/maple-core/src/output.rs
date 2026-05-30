use std::collections::BTreeMap;
use std::fmt::Write;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub name: String,
    pub category: String,
    pub value: u64,
    pub is_offset: bool,
}

fn sanitize_ident(name: &str) -> String {
    let mut s: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let first_is_digit = s.as_bytes().first().is_some_and(u8::is_ascii_digit);
    if s.is_empty() || first_is_digit {
        s.insert(0, '_');
    }
    s
}

fn grouped(findings: &[Finding]) -> BTreeMap<&str, Vec<&Finding>> {
    let mut map: BTreeMap<&str, Vec<&Finding>> = BTreeMap::new();
    for f in findings {
        map.entry(f.category.as_str()).or_default().push(f);
    }
    for items in map.values_mut() {
        items.sort_by(|a, b| a.name.cmp(&b.name));
        items.dedup_by(|a, b| a.name == b.name);
    }
    map
}

#[must_use]
pub fn offsets_header(findings: &[Finding], module_name: &str, module_base: u64) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "#pragma once");
    let _ = writeln!(out, "#include <cstdint>");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "// module-relative RVAs for {module_name} (base 0x{module_base:X})"
    );
    let _ = writeln!(out, "namespace maple {{");
    for (category, items) in grouped(findings) {
        let _ = writeln!(out, "    namespace {} {{", sanitize_ident(category));
        let _ = writeln!(out, "        inline constexpr uintptr_t");
        for (i, f) in items.iter().enumerate() {
            let sep = if i + 1 < items.len() { "," } else { ";" };
            let _ = writeln!(
                out,
                "            {} = 0x{:X}{sep}",
                sanitize_ident(&f.name),
                f.value
            );
        }
        let _ = writeln!(out, "    }}");
    }
    let _ = writeln!(out, "}}");
    out
}

#[must_use]
pub fn cheat_table(findings: &[Finding], module_name: &str) -> String {
    let mut out = String::new();
    for (_, items) in grouped(findings) {
        for f in items {
            let ident = sanitize_ident(&f.name);
            if f.is_offset {
                let _ = writeln!(out, "define({ident}, 0x{:X})", f.value);
            } else {
                let _ = writeln!(out, "define({ident}, \"{module_name}\"+{:X})", f.value);
            }
            let _ = writeln!(out, "registersymbol({ident})");
        }
    }
    out
}

#[must_use]
pub fn plain_text(
    findings: &[Finding],
    module_name: &str,
    module_base: u64,
    extra_header: Option<&str>,
) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "module {module_name} base 0x{module_base:X}");
    if let Some(header) = extra_header {
        let _ = writeln!(out, "{header}");
    }
    let _ = writeln!(out, "###################");
    for (category, items) in grouped(findings) {
        for f in items {
            let suffix = if f.is_offset { " (offset)" } else { "" };
            let _ = writeln!(out, "[{category}] {} = 0x{:X}{suffix}", f.name, f.value);
        }
    }
    let _ = writeln!(out, "###################");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(name: &str, category: &str, value: u64, is_offset: bool) -> Finding {
        Finding {
            name: name.to_string(),
            category: category.to_string(),
            value,
            is_offset,
        }
    }

    #[test]
    fn identifiers_are_sanitized() {
        assert_eq!(sanitize_ident("Foo.Bar"), "Foo_Bar");
        assert_eq!(sanitize_ident("123abc"), "_123abc");
        assert_eq!(sanitize_ident("Ok_Name"), "Ok_Name");
    }

    #[test]
    fn offsets_header_is_sorted_deduped_and_namespaced() {
        let findings = vec![
            f("Zeta", "globals", 0x100, false),
            f("Alpha", "globals", 0x200, false),
            f("Alpha", "globals", 0x999, false),
            f("Hp", "offsets", 0x40, true),
        ];
        let h = offsets_header(&findings, "MapleStory.exe", 0x1_4000_0000);
        assert!(h.find("Alpha").unwrap() < h.find("Zeta").unwrap());
        assert_eq!(h.matches("Alpha = ").count(), 1);
        assert!(h.contains("namespace globals"));
        assert!(h.contains("namespace offsets"));
        assert!(h.contains("Hp = 0x40"));
        assert!(h.contains("#pragma once"));
    }

    #[test]
    fn cheat_table_uses_module_for_rva_and_bare_for_offset() {
        let findings = vec![
            f("Func", "functions", 0x1234, false),
            f("HpOff", "offsets", 0x40, true),
        ];
        let ct = cheat_table(&findings, "MapleStory.exe");
        assert!(ct.contains("define(Func, \"MapleStory.exe\"+1234)"));
        assert!(ct.contains("registersymbol(Func)"));
        assert!(ct.contains("define(HpOff, 0x40)"));
    }

    #[test]
    fn plain_text_lists_findings() {
        let findings = vec![f("Foo", "globals", 0xABCD, false)];
        let t = plain_text(&findings, "MapleStory.exe", 0x1_4000_0000, None);
        assert!(t.contains("[globals] Foo = 0xABCD"));
    }
}
