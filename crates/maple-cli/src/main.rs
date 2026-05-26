use std::path::PathBuf;
use std::process::ExitCode;

use maple_core::output::{cheat_table, offsets_header, plain_text};
use maple_core::pattern::{Arch, parse_patterns_file};
use maple_core::{ScanResult, Target, scan};

struct Args {
    process: Option<String>,
    class: Option<String>,
    module: Option<String>,
    patterns: PathBuf,
    arch: String,
    out: PathBuf,
    ce: bool,
}

const HELP: &str = "\
mapledumper - AOB/pattern scanner and offset dumper for Windows x64 processes

USAGE:
    mapledumper (--process <name> | --class <window-class>) [options]

OPTIONS:
    --process <name>   attach by process name (e.g. MapleStory.exe)
    --class <class>    attach by top-level window class
    --module <name>    module to scan (default: process name)
    --patterns <file>  pattern file (default: patterns.txt)
    --arch <32|64>     architecture section to load (default: 64)
    --out <dir>        output directory (default: .)
    --ce               write update.txt as a Cheat Engine table
    -h, --help         print this help
";

fn value(it: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    it.next().ok_or_else(|| format!("{flag} requires a value"))
}

fn parse_args() -> Result<Args, String> {
    let mut process = None;
    let mut class = None;
    let mut module = None;
    let mut patterns = PathBuf::from("patterns.txt");
    let mut arch = String::from("64");
    let mut out = PathBuf::from(".");
    let mut ce = false;

    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--process" => process = Some(value(&mut it, "--process")?),
            "--class" => class = Some(value(&mut it, "--class")?),
            "--module" => module = Some(value(&mut it, "--module")?),
            "--patterns" => patterns = PathBuf::from(value(&mut it, "--patterns")?),
            "--arch" => arch = value(&mut it, "--arch")?,
            "--out" => out = PathBuf::from(value(&mut it, "--out")?),
            "--ce" => ce = true,
            "-h" | "--help" => {
                print!("{HELP}");
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    if process.is_some() && class.is_some() {
        return Err("--process and --class are mutually exclusive".to_string());
    }
    Ok(Args {
        process,
        class,
        module,
        patterns,
        arch,
        out,
        ce,
    })
}

fn module_name(args: &Args) -> String {
    args.module
        .clone()
        .or_else(|| args.process.clone())
        .unwrap_or_else(|| "MapleStory.exe".to_string())
}

fn attach(args: &Args) -> Result<Target, String> {
    let module = module_name(args);
    if let Some(process) = &args.process {
        Target::attach_by_name(process, &module).map_err(|e| format!("attach by name failed: {e}"))
    } else if let Some(class) = &args.class {
        Target::attach_by_class(class, &module).map_err(|e| format!("attach by class failed: {e}"))
    } else {
        Err("specify --process <name> or --class <window-class> (see --help)".to_string())
    }
}

fn write_outputs(args: &Args, result: &ScanResult, module: &str, base: u64) -> Result<(), String> {
    let update = args.out.join("update.txt");
    let contents = if args.ce {
        cheat_table(&result.findings, module)
    } else {
        plain_text(&result.findings, module, base)
    };
    std::fs::write(&update, contents).map_err(|e| format!("write {}: {e}", update.display()))?;
    println!("[+] wrote {}", update.display());

    let header = args.out.join("offsets.h");
    std::fs::write(&header, offsets_header(&result.findings, module, base))
        .map_err(|e| format!("write {}: {e}", header.display()))?;
    println!("[+] wrote {}", header.display());
    Ok(())
}

fn run() -> Result<(), String> {
    let args = parse_args()?;
    let arch = match args.arch.as_str() {
        "32" => Arch::X86,
        "64" => Arch::X64,
        other => return Err(format!("invalid --arch {other}, expected 32 or 64")),
    };

    let patterns = parse_patterns_file(&args.patterns, arch)
        .map_err(|e| format!("failed to read {}: {e}", args.patterns.display()))?;
    if patterns.is_empty() {
        return Err(format!(
            "no patterns loaded from {}",
            args.patterns.display()
        ));
    }
    println!("[+] loaded {} patterns", patterns.len());

    let target = attach(&args)?;
    println!(
        "[+] attached; module base 0x{:X} size 0x{:X}",
        target.module.base, target.module.size
    );

    let regions = target.regions();
    println!("[+] scanning {} regions", regions.len());
    let result = scan(&target, target.module.base, &regions, &patterns, arch);

    println!();
    println!("[+] found {}", result.found.len());
    if !result.matched_unresolved.is_empty() {
        println!(
            "[!] matched but unresolved: {}",
            result.matched_unresolved.len()
        );
        for name in &result.matched_unresolved {
            println!("    {name}");
        }
    }
    if !result.not_found.is_empty() {
        println!("[-] not found: {}", result.not_found.len());
        for name in &result.not_found {
            println!("    {name}");
        }
    }
    println!("[+] total matches {}", result.total_matches);

    let module = module_name(&args);
    write_outputs(&args, &result, &module, target.module.base as u64)
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("[error] {e}");
            ExitCode::FAILURE
        }
    }
}
