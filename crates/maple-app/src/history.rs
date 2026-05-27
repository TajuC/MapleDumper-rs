use std::path::PathBuf;

use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;

pub struct NewScan {
    pub created_at: i64,
    pub module: String,
    pub module_base: String,
    pub arch: String,
    pub build_hash: String,
    pub build_version: Option<String>,
    pub build_timestamp: i64,
    pub bytes: i64,
    pub regions: i64,
    pub found: i64,
    pub unresolved: i64,
    pub not_found: i64,
    pub total_matches: i64,
    pub scan_ms: i64,
}

pub struct NewFinding {
    pub name: String,
    pub category: String,
    pub value: Option<String>,
    pub is_offset: bool,
    pub status: String,
    pub matches: i64,
    pub note: String,
    pub bytes: Option<String>,
}

#[derive(Serialize, Clone)]
pub struct ScanRow {
    pub id: i64,
    pub created_at: i64,
    pub module: String,
    pub arch: String,
    pub module_base: String,
    pub build_hash: String,
    pub build_version: Option<String>,
    pub found: i64,
    pub not_found: i64,
    pub total_matches: i64,
    pub bytes: i64,
    pub scan_ms: i64,
}

#[derive(Serialize)]
pub struct BuildGroup {
    pub build_hash: String,
    pub build_version: Option<String>,
    pub scans: Vec<ScanRow>,
}

#[derive(Serialize)]
pub struct FindingRow {
    pub name: String,
    pub category: String,
    pub value: Option<String>,
    pub is_offset: bool,
    pub status: String,
    pub matches: i64,
    pub note: String,
    pub bytes: Option<String>,
}

#[must_use]
pub fn default_db_path() -> PathBuf {
    let dir = std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("MapleDumper");
    let _ = std::fs::create_dir_all(&dir);
    dir.join("history.db")
}

fn init(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA foreign_keys=ON;
         CREATE TABLE IF NOT EXISTS scans (
           id INTEGER PRIMARY KEY AUTOINCREMENT,
           created_at INTEGER NOT NULL,
           module TEXT NOT NULL,
           module_base TEXT NOT NULL,
           arch TEXT NOT NULL,
           build_hash TEXT NOT NULL,
           build_version TEXT,
           build_timestamp INTEGER NOT NULL,
           bytes INTEGER NOT NULL,
           regions INTEGER NOT NULL,
           found INTEGER NOT NULL,
           unresolved INTEGER NOT NULL,
           not_found INTEGER NOT NULL,
           total_matches INTEGER NOT NULL,
           scan_ms INTEGER NOT NULL,
           result_hash TEXT
         );
         CREATE TABLE IF NOT EXISTS findings (
           id INTEGER PRIMARY KEY AUTOINCREMENT,
           scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
           name TEXT NOT NULL,
           category TEXT NOT NULL,
           value TEXT,
           is_offset INTEGER NOT NULL,
           status TEXT NOT NULL,
           matches INTEGER NOT NULL,
           note TEXT NOT NULL,
           bytes TEXT
         );
         CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
         CREATE INDEX IF NOT EXISTS idx_scans_build ON scans(build_hash);",
    )?;
    let _ = conn.execute("ALTER TABLE scans ADD COLUMN result_hash TEXT", []);
    let _ = conn.execute("ALTER TABLE findings ADD COLUMN bytes TEXT", []);
    Ok(())
}

fn result_hash(scan: &NewScan, findings: &[NewFinding]) -> String {
    let mut parts: Vec<String> = findings
        .iter()
        .map(|f| {
            format!(
                "{}\u{1}{}\u{1}{}\u{1}{}\u{1}{}\u{1}{}",
                f.name,
                f.value.as_deref().unwrap_or(""),
                f.is_offset,
                f.status,
                f.matches,
                f.note
            )
        })
        .collect();
    parts.sort();
    let canonical = format!(
        "{}\u{2}{}\u{2}{}\u{2}{}",
        scan.build_hash,
        scan.module,
        scan.arch,
        parts.join("\u{2}")
    );
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in canonical.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{hash:016X}")
}

pub fn open(path: &std::path::Path) -> rusqlite::Result<Connection> {
    let conn = Connection::open(path)?;
    init(&conn)?;
    Ok(conn)
}

#[must_use]
pub fn open_memory() -> Connection {
    let conn = Connection::open_in_memory().expect("in-memory database");
    let _ = init(&conn);
    conn
}

pub fn insert_scan(
    conn: &mut Connection,
    scan: &NewScan,
    findings: &[NewFinding],
) -> rusqlite::Result<i64> {
    let rhash = result_hash(scan, findings);
    if let Some(id) = conn
        .query_row(
            "SELECT id FROM scans WHERE result_hash = ?1",
            [&rhash],
            |r| r.get::<_, i64>(0),
        )
        .optional()?
    {
        return Ok(id);
    }
    let tx = conn.transaction()?;
    tx.execute(
        "INSERT INTO scans (created_at, module, module_base, arch, build_hash, build_version,
            build_timestamp, bytes, regions, found, unresolved, not_found, total_matches, scan_ms,
            result_hash)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)",
        params![
            scan.created_at,
            scan.module,
            scan.module_base,
            scan.arch,
            scan.build_hash,
            scan.build_version,
            scan.build_timestamp,
            scan.bytes,
            scan.regions,
            scan.found,
            scan.unresolved,
            scan.not_found,
            scan.total_matches,
            scan.scan_ms,
            rhash,
        ],
    )?;
    let id = tx.last_insert_rowid();
    {
        let mut stmt = tx.prepare(
            "INSERT INTO findings (scan_id, name, category, value, is_offset, status, matches, note, bytes)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
        )?;
        for f in findings {
            stmt.execute(params![
                id,
                f.name,
                f.category,
                f.value,
                i64::from(f.is_offset),
                f.status,
                f.matches,
                f.note,
                f.bytes,
            ])?;
        }
    }
    tx.commit()?;
    Ok(id)
}

pub fn list_scans(conn: &Connection) -> rusqlite::Result<Vec<ScanRow>> {
    let mut stmt = conn.prepare(
        "SELECT id, created_at, module, arch, module_base, build_hash, build_version,
            found, not_found, total_matches, bytes, scan_ms
         FROM scans ORDER BY created_at DESC, id DESC",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(ScanRow {
            id: r.get(0)?,
            created_at: r.get(1)?,
            module: r.get(2)?,
            arch: r.get(3)?,
            module_base: r.get(4)?,
            build_hash: r.get(5)?,
            build_version: r.get(6)?,
            found: r.get(7)?,
            not_found: r.get(8)?,
            total_matches: r.get(9)?,
            bytes: r.get(10)?,
            scan_ms: r.get(11)?,
        })
    })?;
    rows.collect()
}

pub fn group_by_build(conn: &Connection) -> rusqlite::Result<Vec<BuildGroup>> {
    let mut groups: Vec<BuildGroup> = Vec::new();
    for scan in list_scans(conn)? {
        if let Some(group) = groups.iter_mut().find(|g| g.build_hash == scan.build_hash) {
            group.scans.push(scan);
        } else {
            groups.push(BuildGroup {
                build_hash: scan.build_hash.clone(),
                build_version: scan.build_version.clone(),
                scans: vec![scan],
            });
        }
    }
    Ok(groups)
}

pub fn scan_row(conn: &Connection, scan_id: i64) -> rusqlite::Result<Option<ScanRow>> {
    Ok(list_scans(conn)?.into_iter().find(|s| s.id == scan_id))
}

pub fn findings(conn: &Connection, scan_id: i64) -> rusqlite::Result<Vec<FindingRow>> {
    let mut stmt = conn.prepare(
        "SELECT name, category, value, is_offset, status, matches, note, bytes
         FROM findings WHERE scan_id = ?1 ORDER BY category, name",
    )?;
    let rows = stmt.query_map([scan_id], |r| {
        Ok(FindingRow {
            name: r.get(0)?,
            category: r.get(1)?,
            value: r.get(2)?,
            is_offset: r.get::<_, i64>(3)? != 0,
            status: r.get(4)?,
            matches: r.get(5)?,
            note: r.get(6)?,
            bytes: r.get(7)?,
        })
    })?;
    rows.collect()
}

pub fn delete_scan(conn: &Connection, scan_id: i64) -> rusqlite::Result<()> {
    conn.execute("DELETE FROM scans WHERE id = ?1", [scan_id])?;
    Ok(())
}

pub fn clear(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch("DELETE FROM findings; DELETE FROM scans;")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(name: &str, value: Option<&str>) -> NewFinding {
        NewFinding {
            name: name.to_string(),
            category: "globals".to_string(),
            value: value.map(str::to_string),
            is_offset: false,
            status: "found".to_string(),
            matches: 1,
            note: String::new(),
            bytes: None,
        }
    }

    fn scan(hash: &str) -> NewScan {
        NewScan {
            created_at: 1,
            module: "MapleStory.exe".to_string(),
            module_base: "0x140000000".to_string(),
            arch: "x64".to_string(),
            build_hash: hash.to_string(),
            build_version: Some("1.2.3.4".to_string()),
            build_timestamp: 0,
            bytes: 100,
            regions: 1,
            found: 1,
            unresolved: 0,
            not_found: 0,
            total_matches: 1,
            scan_ms: 5,
        }
    }

    #[test]
    fn inserts_groups_and_reads_back() {
        let mut conn = open_memory();
        let a = insert_scan(&mut conn, &scan("AAAA"), &[finding("Foo", Some("0x10"))]).unwrap();
        insert_scan(&mut conn, &scan("AAAA"), &[finding("Foo", Some("0x20"))]).unwrap();
        insert_scan(&mut conn, &scan("BBBB"), &[finding("Bar", Some("0x30"))]).unwrap();

        let groups = group_by_build(&conn).unwrap();
        assert_eq!(groups.len(), 2);
        assert_eq!(groups.iter().map(|g| g.scans.len()).sum::<usize>(), 3);

        let f = findings(&conn, a).unwrap();
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].name, "Foo");
    }

    #[test]
    fn identical_scan_is_not_duplicated() {
        let mut conn = open_memory();
        let id1 = insert_scan(&mut conn, &scan("AAAA"), &[finding("Foo", Some("0x10"))]).unwrap();
        let id2 = insert_scan(&mut conn, &scan("AAAA"), &[finding("Foo", Some("0x10"))]).unwrap();
        assert_eq!(id1, id2);
        assert_eq!(list_scans(&conn).unwrap().len(), 1);
    }

    #[test]
    fn different_values_are_kept_apart() {
        let mut conn = open_memory();
        insert_scan(&mut conn, &scan("AAAA"), &[finding("Foo", Some("0x10"))]).unwrap();
        insert_scan(&mut conn, &scan("AAAA"), &[finding("Foo", Some("0x20"))]).unwrap();
        assert_eq!(list_scans(&conn).unwrap().len(), 2);
    }

    #[test]
    fn delete_cascades_to_findings() {
        let mut conn = open_memory();
        let id = insert_scan(&mut conn, &scan("AAAA"), &[finding("Foo", Some("0x10"))]).unwrap();
        delete_scan(&conn, id).unwrap();
        assert!(list_scans(&conn).unwrap().is_empty());
        assert!(findings(&conn, id).unwrap().is_empty());
    }
}
