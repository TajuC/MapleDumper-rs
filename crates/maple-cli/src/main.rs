use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use maple_core::output::{cheat_table, offsets_header, plain_text};
use maple_core::pattern::{Arch, parse_patterns_file};
use maple_core::{AttachOptions, Locator, ScanResult, Target, scan};

struct Args {
    process: Option<String>,
    class: Option<String>,
    module: Option<String>,
    patterns: PathBuf,
    arch: Arch,
    out: PathBuf,
    ce: bool,
    offsets: bool,
    wait: bool,
    timeout: Option<Duration>,
}

const HELP: &str = "\
mapledumper - AOB/pattern scanner and offset dumper for Windows x64 processes

USAGE:
    mapledumper (--process <name> | --class <window-class>) [options]

ATTACH:
    --process <name>   attach by process name (\".exe\" optional, case-insensitive)
    --class <class>    attach by top-level window class
    --module <name>    module to scan (default: process name)
    --no-wait          fail immediately if the target is not running
    --timeout <secs>   max seconds to wait for the target (0 = forever, default)

OUTPUT:
    --patterns <file>  pattern file (default: patterns.txt)
    --arch <32|64>     architecture section to load (default: 64)
    --out <dir>        output directory, created if missing (default: .)
    --ce               write update.txt as a Cheat Engine table
    --no-offsets       do not write offsets.h

    -h, --help         print this help
    -V, --version      print version

By default mapledumper waits for the target, so you can start it before the game.";

fn value(it: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    it.next().ok_or_else(|| format!("{flag} requires a value"))
}

fn parse_arch(s: &str) -> Result<Arch, String> {
    match s.trim().to_ascii_lowercase().as_str() {
        "64" | "x64" | "amd64" | "x86_64" | "x86-64" => Ok(Arch::X64),
        "32" | "x86" | "i386" | "x86_32" => Ok(Arch::X86),
        other => Err(format!("invalid --arch '{other}' (use 32 or 64)")),
    }
}

fn parse_args() -> Result<Args, String> {
    let mut process = None;
    let mut class = None;
    let mut module = None;
    let mut patterns = PathBuf::from("patterns.txt");
    let mut arch = Arch::X64;
    let mut out = PathBuf::from(".");
    let mut ce = false;
    let mut offsets = true;
    let mut wait = true;
    let mut timeout = None;

    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--process" => process = Some(value(&mut it, "--process")?),
            "--class" => class = Some(value(&mut it, "--class")?),
            "--module" => module = Some(value(&mut it, "--module")?),
            "--patterns" => patterns = PathBuf::from(value(&mut it, "--patterns")?),
            "--arch" => arch = parse_arch(&value(&mut it, "--arch")?)?,
            "--out" => out = PathBuf::from(value(&mut it, "--out")?),
            "--ce" => ce = true,
            "--no-offsets" => offsets = false,
            "--no-wait" => wait = false,
            "--timeout" => {
                let raw = value(&mut it, "--timeout")?;
                let secs: u64 = raw
                    .trim()
                    .parse()
                    .map_err(|_| format!("invalid --timeout '{raw}'"))?;
                timeout = (secs > 0).then(|| Duration::from_secs(secs));
            }
            "-h" | "--help" => {
                print!("{HELP}");
                std::process::exit(0);
            }
            "-V" | "--version" => {
                println!("mapledumper {}", maple_core::VERSION);
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
        offsets,
        wait,
        timeout,
    })
}

fn module_name(args: &Args) -> String {
    args.module
        .clone()
        .or_else(|| args.process.clone())
        .unwrap_or_else(|| "MapleStory.exe".to_string())
}

fn locator(args: &Args) -> Result<Locator, String> {
    if let Some(process) = &args.process {
        Ok(Locator::Name(process.clone()))
    } else if let Some(class) = &args.class {
        Ok(Locator::Class(class.clone()))
    } else {
        Err("specify --process <name> or --class <window-class> (see --help)".to_string())
    }
}

fn write_outputs(args: &Args, result: &ScanResult, module: &str, base: u64) -> Result<(), String> {
    std::fs::create_dir_all(&args.out)
        .map_err(|e| format!("create {}: {e}", args.out.display()))?;

    let update = args.out.join("update.txt");
    let contents = if args.ce {
        cheat_table(&result.findings, module)
    } else {
        plain_text(&result.findings, module, base)
    };
    std::fs::write(&update, contents).map_err(|e| format!("write {}: {e}", update.display()))?;
    println!("[+] wrote {}", update.display());

    if args.offsets {
        let header = args.out.join("offsets.h");
        std::fs::write(&header, offsets_header(&result.findings, module, base))
            .map_err(|e| format!("write {}: {e}", header.display()))?;
        println!("[+] wrote {}", header.display());
    }
    Ok(())
}

fn run() -> Result<(), String> {
    let args = parse_args()?;

    let patterns = parse_patterns_file(&args.patterns, args.arch)
        .map_err(|e| format!("failed to read {}: {e}", args.patterns.display()))?;
    if patterns.is_empty() {
        return Err(format!(
            "no patterns loaded from {}",
            args.patterns.display()
        ));
    }
    println!("[+] loaded {} patterns", patterns.len());

    let loc = locator(&args)?;
    let module = module_name(&args);
    let opts = AttachOptions {
        wait: args.wait,
        timeout: args.timeout,
        poll: Duration::from_millis(300),
    };
    if args.wait {
        let what = match &loc {
            Locator::Name(name) => format!("process {name}"),
            Locator::Class(class) => format!("window class {class}"),
        };
        println!("[*] waiting for {what} (Ctrl-C to cancel)...");
    }
    let cancel = AtomicBool::new(false);
    let target =
        Target::attach(&loc, &module, &opts, &cancel).map_err(|e| format!("attach failed: {e}"))?;
    println!(
        "[+] attached; module {} base 0x{:X} size 0x{:X}",
        module, target.module.base, target.module.size
    );

    let regions = target.regions();
    println!("[+] scanning {} regions", regions.len());
    let result = scan(&target, target.module.base, &regions, &patterns, args.arch);

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
