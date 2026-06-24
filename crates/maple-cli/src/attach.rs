use std::sync::atomic::AtomicBool;
use std::time::Duration;

use maple_core::{AttachOptions, Locator, Target};

use crate::config::ResolvedAttach;
use crate::exit::{CliError, attach_err};

fn locator(at: &ResolvedAttach) -> Result<Locator, String> {
    if let Some(process) = &at.process {
        Ok(Locator::Name(process.clone()))
    } else if let Some(class) = &at.class {
        Ok(Locator::Class(class.clone()))
    } else {
        Err("specify --process <name> or --class <window-class>".to_string())
    }
}

pub(crate) fn attach_target(
    at: &ResolvedAttach,
    cancel: &AtomicBool,
    quiet: bool,
) -> Result<Target, CliError> {
    let opts = AttachOptions {
        wait: at.wait,
        timeout: at.timeout,
        poll: Duration::from_millis(300),
    };
    let target = if let Some(pid) = at.pid {
        if !quiet {
            println!("[+] attaching to pid {pid}");
        }
        Target::attach_pid(pid, &at.module).map_err(attach_err)?
    } else {
        let loc = locator(at)?;
        if let Locator::Name(name) = &loc {
            let candidates = maple_core::process::process_candidates(name);
            if candidates.len() > 1 {
                // A multiple-match warning matters even in --json mode, so it goes to stderr (where
                // it cannot corrupt a piped JSON document on stdout) rather than being suppressed.
                eprintln!("[!] {} processes match '{name}':", candidates.len());
                for c in &candidates {
                    eprintln!(
                        "      pid {}  {}",
                        c.pid,
                        c.path.as_deref().unwrap_or("(path unavailable)")
                    );
                }
                eprintln!("    attaching to the first; pass --pid <pid> to choose another");
            }
        }
        if at.wait && !quiet {
            let what = match &loc {
                Locator::Name(name) => format!("process {name}"),
                Locator::Class(class) => format!("window class {class}"),
            };
            println!("[*] waiting for {what} (Ctrl-C to cancel)...");
        }
        Target::attach(&loc, &at.module, &opts, cancel).map_err(attach_err)?
    };
    if !quiet {
        println!(
            "[+] attached; module {} base 0x{:X} size 0x{:X}",
            at.module, target.module.base, target.module.size
        );
    }
    Ok(target)
}
