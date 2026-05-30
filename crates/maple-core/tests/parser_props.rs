use maple_core::pattern::{parse_patterns, parse_patterns_strict};
use maple_core::{Arch, signature_from_aob, try_signature_from_aob};
use proptest::prelude::*;

fn arbitrary_text() -> impl Strategy<Value = String> {
    proptest::collection::vec(any::<char>(), 0..200).prop_map(|chars| chars.into_iter().collect())
}

fn aob_of(tokens: &[Option<u8>]) -> String {
    tokens
        .iter()
        .map(|t| t.map_or_else(|| "??".to_string(), |b| format!("{b:02X}")))
        .collect::<Vec<_>>()
        .join(" ")
}

proptest! {
    #[test]
    fn strict_parser_survives_arbitrary_input(s in arbitrary_text()) {
        let _ = parse_patterns_strict(&s, Arch::X64);
        let _ = parse_patterns_strict(&s, Arch::X86);
    }

    #[test]
    fn lenient_parser_survives_arbitrary_input(s in arbitrary_text()) {
        let _ = parse_patterns(&s, Arch::X64);
    }

    #[test]
    fn aob_parser_survives_arbitrary_input(s in arbitrary_text()) {
        let _ = try_signature_from_aob(&s);
        let _ = signature_from_aob(&s);
    }

    #[test]
    fn well_formed_aob_roundtrips(
        tokens in proptest::collection::vec(proptest::option::of(0u8..=255u8), 1..24),
    ) {
        let sig = try_signature_from_aob(&aob_of(&tokens)).expect("a non-empty aob parses");
        let reparsed = try_signature_from_aob(&sig.to_aob()).expect("a serialized aob parses");
        prop_assert_eq!(&sig.bytes, &reparsed.bytes);
        prop_assert_eq!(&sig.mask, &reparsed.mask);
        prop_assert_eq!(sig.bytes.len(), tokens.len());
    }

    #[test]
    fn one_valid_line_yields_one_pattern(
        mut tokens in proptest::collection::vec(proptest::option::of(0u8..=255u8), 4..24),
    ) {
        tokens[0] = Some(0x48);
        let parsed = parse_patterns_strict(&format!("Sym = {}", aob_of(&tokens)), Arch::X64)
            .expect("a well-formed line parses");
        prop_assert_eq!(parsed.patterns.len(), 1);
        prop_assert_eq!(parsed.patterns[0].signature.bytes.len(), tokens.len());
    }
}
