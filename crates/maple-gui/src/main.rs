#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![allow(clippy::all, clippy::pedantic)]

mod ui {
    slint::include_modules!();
}

use std::cell::RefCell;
use std::path::Path;
use std::rc::Rc;

use maple_core::output::{offsets_header, plain_text};
use maple_core::pattern::{Arch, parse_patterns_file};
use maple_core::{Finding, Target, scan};
use slint::{ComponentHandle, ModelRc, SharedString, StandardListViewItem, VecModel};
use ui::AppWindow;

struct ScanData {
    findings: Vec<Finding>,
    module: String,
    base: u64,
}

fn run_scan(process: &str, module: &str, patterns_path: &str) -> Result<ScanData, String> {
    let patterns = parse_patterns_file(Path::new(patterns_path), Arch::X64)
        .map_err(|e| format!("read patterns: {e}"))?;
    if patterns.is_empty() {
        return Err("no patterns loaded".to_string());
    }
    let module_name = if module.is_empty() { process } else { module };
    let target = Target::attach_by_name(process, module_name).map_err(|e| e.to_string())?;
    let regions = target.regions();
    let result = scan(&target, target.module.base, &regions, &patterns);
    Ok(ScanData {
        findings: result.findings,
        module: module_name.to_string(),
        base: target.module.base as u64,
    })
}

fn rows_model(findings: &[Finding]) -> ModelRc<ModelRc<StandardListViewItem>> {
    let rows: Vec<ModelRc<StandardListViewItem>> = findings
        .iter()
        .map(|f| {
            let cells = vec![
                StandardListViewItem::from(SharedString::from(f.name.as_str())),
                StandardListViewItem::from(SharedString::from(f.category.as_str())),
                StandardListViewItem::from(SharedString::from(format!("0x{:X}", f.value))),
            ];
            ModelRc::new(VecModel::from(cells))
        })
        .collect();
    ModelRc::new(VecModel::from(rows))
}

fn main() -> Result<(), slint::PlatformError> {
    let app = AppWindow::new()?;
    let store: Rc<RefCell<Option<ScanData>>> = Rc::new(RefCell::new(None));

    app.on_scan({
        let weak = app.as_weak();
        let store = store.clone();
        move || {
            let app = weak.unwrap();
            app.set_status(SharedString::from("scanning..."));
            let result = run_scan(
                app.get_process().as_str(),
                app.get_module().as_str(),
                app.get_patterns().as_str(),
            );
            match result {
                Ok(data) => {
                    app.set_rows(rows_model(&data.findings));
                    app.set_status(SharedString::from(format!(
                        "found {} symbols",
                        data.findings.len()
                    )));
                    *store.borrow_mut() = Some(data);
                }
                Err(e) => app.set_status(SharedString::from(format!("error: {e}"))),
            }
        }
    });

    app.on_save_offsets({
        let weak = app.as_weak();
        let store = store.clone();
        move || {
            let app = weak.unwrap();
            app.set_status(save(&store, "offsets.h", |d| {
                offsets_header(&d.findings, &d.module, d.base)
            }));
        }
    });

    app.on_save_update({
        let weak = app.as_weak();
        let store = store.clone();
        move || {
            let app = weak.unwrap();
            app.set_status(save(&store, "update.txt", |d| {
                plain_text(&d.findings, &d.module, d.base)
            }));
        }
    });

    app.run()
}

fn save(
    store: &Rc<RefCell<Option<ScanData>>>,
    path: &str,
    render: impl Fn(&ScanData) -> String,
) -> SharedString {
    match store.borrow().as_ref() {
        Some(data) => match std::fs::write(path, render(data)) {
            Ok(()) => SharedString::from(format!("wrote {path}")),
            Err(e) => SharedString::from(format!("write error: {e}")),
        },
        None => SharedString::from("nothing to save; scan first"),
    }
}
