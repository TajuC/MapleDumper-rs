use std::path::PathBuf;

use clap::Parser;
use maple_core::pattern::Arch;
use maple_core::{
    BuildStamp, FindingStatus, Grade, NegativeHit, PatternRow, PerVersion, ScanResult,
    SigCandidate, SigReport, SubScores, Suffix, TargetKind, arch_mismatch,
};

use crate::cli::*;
use crate::config::*;
use crate::exit::*;
use crate::json::*;

fn mkrow(name: &str, status: FindingStatus, candidates: Vec<u64>) -> PatternRow {
    PatternRow {
        name: name.to_string(),
        category: "globals".to_string(),
        pattern: "48 8B ?? ??".to_string(),
        value: candidates.first().copied(),
        is_offset: false,
        matches: candidates.len(),
        status,
        note: String::new(),
        candidates,
        confidence: 0,
        trace: None,
        trace_detail: None,
    }
}

fn result_of(rows: Vec<PatternRow>, unresolved: Vec<&str>, not_found: Vec<&str>) -> ScanResult {
    let found = rows
        .iter()
        .filter(|r| r.status.is_found())
        .map(|r| r.name.clone())
        .collect();
    let total_matches = rows.iter().map(|r| r.matches).sum();
    ScanResult {
        findings: Vec::new(),
        rows,
        found,
        matched_unresolved: unresolved.iter().map(|s| s.to_string()).collect(),
        not_found: not_found.iter().map(|s| s.to_string()).collect(),
        total_matches,
        read_gaps: Vec::new(),
        warnings: Vec::new(),
    }
}

#[test]
fn json_report_pins_the_address_and_field_contract() {
    use maple_core::sigmaker::{AobRange, Shortlist, ShortlistEntry};
    use maple_core::{
        Diag, DupGroup, HoldoutResult, InputInfo, NegativeHit, SigCandidate, SigReport, TargetKind,
    };
    use serde_json::Value;

    let chosen = SigCandidate {
        aob: "48 8B 05 ?? ?? ?? ??".to_string(),
        suffix: Suffix::Call,
        grade: Grade::A,
        score: 84,
        bytes_len: 16,
        fixed: 9,
        wildcards: 7,
        fixed_ratio: 0.5625,
        reloc_safe: true,
        gated: false,
        packed: false,
        scores: SubScores {
            uniqueness: 90,
            stability: 80,
            entropy: 70,
            semantic: 60,
            resolver_confidence: 88,
            cross_build: 77,
            final_score: 84,
        },
        reasons: vec!["unique across corpus".to_string()],
        per_version: vec![PerVersion {
            label: "v83".to_string(),
            match_rva: Some(0x0040_1000),
            resolved_target_rva: Some(0x0040_2ABC),
            target_kind: Some(TargetKind::Code),
            fingerprint_similarity: Some(0.95),
            aob: Some("AA BB CC".to_string()),
        }],
        diags: vec![Diag::CalleeMismatch],
        relocation: Some(maple_core::RelocationLedger {
            anchor: "string".to_string(),
            support: 2,
            corroborators: vec!["caller".to_string()],
            conflict: false,
        }),
    };
    let report = SigReport {
        arch: Arch::X64,
        inputs: vec![InputInfo {
            label: "v83".to_string(),
            packed: false,
            reasons: vec![],
        }],
        unique_builds: 1,
        duplicate_groups: vec![DupGroup {
            code_hash: 0xDEAD_BEEF,
            labels: vec!["v83".to_string(), "v84".to_string()],
        }],
        chosen: Some(chosen),
        alternates: vec![],
        rejected: vec![],
        shortlists: vec![Shortlist {
            label: "v95".to_string(),
            entries: vec![ShortlistEntry {
                rva: 0x0040_10F0,
                similarity: 0.81,
                aob: None,
            }],
        }],
        aob_ranges: vec![AobRange {
            aob: "48 8B".to_string(),
            minted_in: "v83".to_string(),
            first_label: "v83".to_string(),
            last_label: "v88".to_string(),
            labels: vec!["v83".to_string(), "v88".to_string()],
        }],
        diagnostics: vec![Diag::NotUnique],
    };
    let negatives = vec![NegativeHit {
        label: "kernel32.dll".to_string(),
        count: 2,
    }];
    let holdout = vec![HoldoutResult {
        held_out: "v84".to_string(),
        generated: true,
        matched_holdout: true,
    }];

    let json = json_report(&report, &negatives, 5, &holdout, Some("@anchor")).unwrap();
    let v: Value = serde_json::from_str(&json).expect("--json output must be valid JSON");

    // Addresses serialize as hex strings, never integers. This is the load-bearing part of the
    // --json contract: a consumer parses "0x401000", not 4198400. The eventual Serialize refactor
    // must preserve it (a plain derive on the u64 fields would silently break every consumer).
    assert_eq!(v["arch"], "x64");
    assert_eq!(v["duplicate_groups"][0]["code_hash"], "00000000DEADBEEF");
    let pv = &v["chosen"]["per_version"][0];
    assert_eq!(pv["match_rva"], "0x401000");
    assert_eq!(pv["resolved_target_rva"], "0x402ABC");
    assert_eq!(pv["target_type"], "code");
    assert_eq!(v["shortlists"][0]["candidates"][0]["rva"], "0x4010F0");
    // The relocation evidence ledger surfaces the ensemble's vote in the JSON contract.
    assert_eq!(v["chosen"]["relocation"]["anchor"], "string");
    assert_eq!(v["chosen"]["relocation"]["support"], 2);
    assert_eq!(v["chosen"]["relocation"]["corroborators"][0], "caller");
    assert_eq!(v["chosen"]["relocation"]["conflict"], false);

    // Field names the core types do not themselves carry are pinned here.
    assert_eq!(v["chosen"]["bytes"], 16);
    assert!(v["chosen"].get("bytes_len").is_none());
    assert_eq!(v["holdout"][0]["matched"], true);
    assert!(v["holdout"][0].get("matched_holdout").is_none());

    // negative_summary is derived CLI-side from the raw per-module hit counts.
    assert_eq!(v["negative_summary"]["modules_scanned"], 5);
    assert_eq!(v["negative_summary"]["modules_hit"], 1);
    assert_eq!(v["negative_summary"]["total_hits"], 2);
    assert_eq!(v["negative_summary"]["max_hits_per_module"], 2);

    // Enum and suffix rendering go through the CLI's display helpers.
    assert_eq!(v["chosen"]["grade"], "A");
    assert_eq!(v["chosen"]["suffix"], "_CALL");
    assert_eq!(v["chosen"]["scores"]["final_score"], 84);
    assert_eq!(v["string_anchor"], "@anchor");
}

#[test]
fn exit_codes_are_stable() {
    assert_eq!(ExitKind::Success.code(), 0);
    assert_eq!(ExitKind::Internal.code(), 1);
    assert_eq!(ExitKind::SuccessWithWarnings.code(), 2);
    assert_eq!(ExitKind::Unresolved.code(), 3);
    assert_eq!(ExitKind::Ambiguous.code(), 4);
    assert_eq!(ExitKind::InvalidInput.code(), 5);
    assert_eq!(ExitKind::AccessDenied.code(), 6);
}

#[test]
fn arch_mismatch_detects_definite_conflicts() {
    // requested x64 but the module is x86: actionable message naming the right bitness
    let msg = arch_mismatch(Arch::X64, Some(Arch::X86), "MapleStory.exe").unwrap();
    assert!(msg.contains("32-bit"), "{msg}");
    assert!(msg.contains("x86"));
    // matching architectures: no complaint
    assert!(arch_mismatch(Arch::X64, Some(Arch::X64), "m").is_none());
    // unknown actual architecture: cannot tell, so never block a scan on a guess
    assert!(arch_mismatch(Arch::X64, None, "m").is_none());
}

#[test]
fn attach_permission_error_maps_to_access_denied() {
    let denied = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
    assert_eq!(attach_err(denied).kind, ExitKind::AccessDenied);
    let missing = std::io::Error::from(std::io::ErrorKind::NotFound);
    assert_eq!(attach_err(missing).kind, ExitKind::InvalidInput);
}

#[test]
fn scan_exit_kind_ranks_ambiguous_over_unresolved_over_clean() {
    let clean = result_of(
        vec![mkrow("A", FindingStatus::FoundUnique, vec![0x10])],
        vec![],
        vec![],
    );
    assert_eq!(scan_exit_kind(&clean), ExitKind::Success);

    let unresolved = result_of(
        vec![mkrow("A", FindingStatus::NotFound, vec![])],
        vec![],
        vec!["A"],
    );
    assert_eq!(scan_exit_kind(&unresolved), ExitKind::Unresolved);

    let ambiguous = result_of(
        vec![mkrow(
            "A",
            FindingStatus::FoundAmbiguous { candidates: 2 },
            vec![0x10, 0x20],
        )],
        vec![],
        vec!["B"],
    );
    assert_eq!(scan_exit_kind(&ambiguous), ExitKind::Ambiguous);
}

#[test]
fn scan_json_is_valid_and_marks_exportability() {
    let result = result_of(
        vec![
            mkrow("Uniq", FindingStatus::FoundUnique, vec![0x140]),
            mkrow(
                "Amb",
                FindingStatus::FoundAmbiguous { candidates: 2 },
                vec![0x10, 0x20],
            ),
        ],
        vec![],
        vec![],
    );
    let stamp = BuildStamp {
        hash: 0xDEAD_BEEF,
        bytes: 2048,
        timestamp: 0,
        version: Some("1.0".to_string()),
    };
    let json = scan_json(&result, "MapleStory.exe", 0x1_4000_0000, &stamp).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).expect("scan_json emits valid JSON");
    assert_eq!(v["module"], "MapleStory.exe");
    assert_eq!(v["ambiguous"], 1);
    assert_eq!(v["build_hash"], "00000000DEADBEEF");
    let findings = v["findings"].as_array().unwrap();
    let uniq = findings.iter().find(|f| f["name"] == "Uniq").unwrap();
    assert_eq!(uniq["exported"], true);
    let amb = findings.iter().find(|f| f["name"] == "Amb").unwrap();
    // an ambiguous row is reported but never exportable as an offset
    assert_eq!(amb["exported"], false);
    assert_eq!(amb["candidates"].as_array().unwrap().len(), 2);
}

#[test]
fn json_includes_ptr_target_fields() {
    let cand = SigCandidate {
        aob: "48 8D 05 ?? ?? ?? ??".to_string(),
        suffix: Suffix::Ptr,
        grade: Grade::A,
        score: 90,
        scores: SubScores {
            uniqueness: 90,
            stability: 80,
            entropy: 40,
            semantic: 82,
            resolver_confidence: 100,
            cross_build: 100,
            final_score: 90,
        },
        reasons: vec!["target validated as code".to_string()],
        bytes_len: 7,
        fixed: 3,
        wildcards: 4,
        fixed_ratio: 0.42,
        reloc_safe: true,
        gated: false,
        packed: false,
        per_version: vec![PerVersion {
            label: "a.exe".to_string(),
            match_rva: Some(0x20),
            resolved_target_rva: Some(0x1000),
            target_kind: Some(TargetKind::Code),
            fingerprint_similarity: Some(1.0),
            aob: None,
        }],
        diags: Vec::new(),
        relocation: None,
    };
    let report = SigReport {
        arch: Arch::X64,
        inputs: Vec::new(),
        unique_builds: 1,
        duplicate_groups: Vec::new(),
        chosen: Some(cand.clone()),
        alternates: vec![cand.clone()],
        rejected: vec![cand],
        shortlists: Vec::new(),
        aob_ranges: Vec::new(),
        diagnostics: Vec::new(),
    };
    let json = json_report(&report, &[], 0, &[], None).unwrap();
    assert_eq!(
        json.matches("\"resolved_target_rva\": \"0x1000\"").count(),
        3
    );
    assert_eq!(json.matches("\"target_type\": \"code\"").count(), 3);
    // the JSON carries the scoring evidence: sub-scores, final_score, reasons, and the per-build
    // fingerprint similarity
    let v: serde_json::Value = serde_json::from_str(&json).expect("valid json");
    let chosen = &v["chosen"];
    assert_eq!(chosen["scores"]["resolver_confidence"], 100);
    assert_eq!(chosen["scores"]["final_score"], 90);
    assert!(!chosen["reasons"].as_array().unwrap().is_empty());
    assert_eq!(chosen["per_version"][0]["fingerprint_similarity"], 1.0);
    // the negative-corpus evidence is always present, even when nothing was scanned
    assert_eq!(v["negative_summary"]["modules_scanned"], 0);
    assert_eq!(v["negative_summary"]["modules_hit"], 0);
}

#[test]
fn json_report_carries_negative_corpus_summary() {
    let report = SigReport {
        arch: Arch::X64,
        inputs: Vec::new(),
        unique_builds: 1,
        duplicate_groups: Vec::new(),
        chosen: None,
        alternates: Vec::new(),
        rejected: Vec::new(),
        shortlists: Vec::new(),
        aob_ranges: Vec::new(),
        diagnostics: Vec::new(),
    };
    let hits = [
        NegativeHit {
            label: "other.dll".into(),
            count: 2,
        },
        NegativeHit {
            label: "third.dll".into(),
            count: 1,
        },
    ];
    let json = json_report(&report, &hits, 5, &[], None).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).expect("valid json");
    assert_eq!(v["negative_summary"]["modules_scanned"], 5);
    assert_eq!(v["negative_summary"]["modules_hit"], 2);
    assert_eq!(v["negative_summary"]["total_hits"], 3);
    assert_eq!(v["negative_summary"]["max_hits_per_module"], 2);
}

#[test]
fn cli_mksig_accepts_holdout_flag() {
    let cli = Cli::try_parse_from([
        "mapledumper",
        "mksig",
        "--client",
        "a.exe",
        "--sig",
        "48 8B",
        "--holdout",
    ])
    .unwrap();
    match cli.command {
        Command::Mksig(m) => assert!(m.holdout),
        _ => panic!("expected mksig"),
    }
}

#[test]
fn cli_parses_scan_with_attach() {
    let cli =
        Cli::try_parse_from(["mapledumper", "scan", "--process", "x.exe", "--arch", "32"]).unwrap();
    match cli.command {
        Command::Scan(a) => {
            assert_eq!(a.attach.process.as_deref(), Some("x.exe"));
            assert_eq!(a.arch.as_deref(), Some("32"));
        }
        _ => panic!("expected scan"),
    }
}

#[test]
fn cli_rejects_process_and_class_together() {
    let r = Cli::try_parse_from(["mapledumper", "scan", "--process", "x.exe", "--class", "W"]);
    assert!(r.is_err());
}

#[test]
fn cli_requires_a_subcommand() {
    assert!(Cli::try_parse_from(["mapledumper"]).is_err());
}

#[test]
fn cli_diff_takes_two_positionals() {
    let cli = Cli::try_parse_from(["mapledumper", "diff", "a.txt", "b.txt"]).unwrap();
    match cli.command {
        Command::Diff(a) => {
            assert_eq!(a.old, PathBuf::from("a.txt"));
            assert_eq!(a.new, PathBuf::from("b.txt"));
        }
        _ => panic!("expected diff"),
    }
}

#[test]
fn cli_mksig_collects_repeated_clients() {
    let cli = Cli::try_parse_from([
        "mapledumper",
        "mksig",
        "--client",
        "a.exe",
        "--client",
        "b.exe",
        "--sig",
        "48 8B",
    ])
    .unwrap();
    match cli.command {
        Command::Mksig(m) => {
            assert_eq!(m.client.len(), 2);
            assert_eq!(m.sig.as_deref(), Some("48 8B"));
        }
        _ => panic!("expected mksig"),
    }
}

#[test]
fn cli_mksig_collects_negatives() {
    let cli = Cli::try_parse_from([
        "mapledumper",
        "mksig",
        "--client",
        "a.exe",
        "--sig",
        "48 8B",
        "--negative",
        "other.dll",
        "--negative",
        "more.dll",
    ])
    .unwrap();
    match cli.command {
        Command::Mksig(m) => assert_eq!(m.negative.len(), 2),
        _ => panic!("expected mksig"),
    }
}

#[test]
fn config_parses_known_keys() {
    let cfg = parse_config(
        "# a comment\nprocess = Maple.exe\narch = 32\nstrict = false\nout = dump\n",
        "test",
    )
    .unwrap();
    assert_eq!(cfg.process.as_deref(), Some("Maple.exe"));
    assert!(matches!(cfg.arch, Some(Arch::X86)));
    assert_eq!(cfg.strict, Some(false));
    assert_eq!(cfg.out, Some(PathBuf::from("dump")));
}

#[test]
fn config_rejects_unknown_key() {
    assert!(parse_config("bogus = 1\n", "test").is_err());
}

#[test]
fn cli_arch_overrides_config_but_config_fills_gaps() {
    let cfg = parse_config("arch = 32\n", "test").unwrap();
    assert!(matches!(resolve_arch(Some("64"), &cfg), Ok(Arch::X64)));
    assert!(matches!(resolve_arch(None, &cfg), Ok(Arch::X86)));
}

#[test]
fn resolve_attach_prefers_cli_class_over_config_process() {
    let cfg = parse_config("process = Cfg.exe\n", "test").unwrap();
    let a = AttachArgs {
        process: None,
        class: Some("Win".to_string()),
        pid: None,
        module: None,
        no_wait: false,
        timeout: None,
    };
    let r = resolve_attach(&a, &cfg);
    assert_eq!(r.class.as_deref(), Some("Win"));
    assert!(r.process.is_none());
    assert_eq!(r.module, "MapleStory.exe");
}

#[test]
fn resolve_attach_falls_back_to_config_process_and_module() {
    let cfg = parse_config("process = Cfg.exe\nmodule = Cfg.dll\n", "test").unwrap();
    let a = AttachArgs {
        process: None,
        class: None,
        pid: None,
        module: None,
        no_wait: true,
        timeout: None,
    };
    let r = resolve_attach(&a, &cfg);
    assert_eq!(r.process.as_deref(), Some("Cfg.exe"));
    assert_eq!(r.module, "Cfg.dll");
    assert!(!r.wait);
}

#[test]
fn lenient_flag_overrides_config_strict() {
    let cfg = parse_config("strict = true\n", "test").unwrap();
    assert!(!resolve_strict(true, &cfg));
    assert!(resolve_strict(false, &cfg));
    assert!(resolve_strict(false, &Config::default()));
}
