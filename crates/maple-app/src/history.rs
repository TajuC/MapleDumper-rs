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
    /// Full virtual size of the scanned module, so a saved scan records the module it ran against.
    pub module_size: i64,
    /// BLAKE3 of the canonical pattern set, so a scan can be tied to the exact patterns used.
    pub pattern_set_hash: String,
    /// The engine version that produced the scan.
    pub scanner_version: String,
    /// JSON of the scan's read gaps (`Vec<ReadGap>`), so a saved scan records that its coverage was
    /// partial. `None` when every region read in full.
    pub read_gaps: Option<String>,
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
    pub confidence: i64,
    pub trace: Option<String>,
    pub candidates: Option<String>,
    /// JSON of the structured `ResolveTrace`, so a saved finding is explained as richly as a live
    /// one (not just the human one-liner in `trace`). `None` when the resolver produced no detail.
    pub resolver_trace: Option<String>,
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
    pub confidence: Option<i64>,
    pub trace: Option<String>,
    pub candidates: Option<String>,
    /// JSON of the structured `ResolveTrace` (resolver kind, operand, target, checks, failure), so a
    /// saved finding's diagnostics match a live one. `None` for rows written before this was stored.
    pub resolver_trace: Option<String>,
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

const SCHEMA_VERSION: i64 = 5;

fn migrate(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
    let mut version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;

    if version < 1 {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS scans (
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
               bytes TEXT,
               confidence INTEGER,
               trace TEXT,
               candidates TEXT
             );
             CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
             CREATE INDEX IF NOT EXISTS idx_scans_build ON scans(build_hash);
             CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at DESC, id DESC);",
        )?;
        // A database created before versioning may predate these two columns.
        add_column_if_missing(conn, "scans", "result_hash", "TEXT")?;
        add_column_if_missing(conn, "findings", "bytes", "TEXT")?;
        version = 1;
    }
    if version < 2 {
        // The content hash moved from FNV-1a to BLAKE3, which are not comparable. Clear the old
        // digests so a stale value can never collide with a new query and dedup two real scans.
        conn.execute("UPDATE scans SET result_hash = NULL", [])?;
        version = 2;
    }
    if version < 3 {
        // Per-finding diagnostics. Nullable so rows written before this version read back as unknown
        // rather than a fabricated zero confidence.
        add_column_if_missing(conn, "findings", "confidence", "INTEGER")?;
        add_column_if_missing(conn, "findings", "trace", "TEXT")?;
        add_column_if_missing(conn, "findings", "candidates", "TEXT")?;
        version = 3;
    }
    if version < 4 {
        // Forensic provenance, so a saved scan can be tied back to the exact module and pattern set
        // that produced it. Nullable: rows written before this version read back as unknown rather
        // than a fabricated zero or empty hash.
        add_column_if_missing(conn, "scans", "module_size", "INTEGER")?;
        add_column_if_missing(conn, "scans", "pattern_set_hash", "TEXT")?;
        add_column_if_missing(conn, "scans", "scanner_version", "TEXT")?;
        version = 4;
    }
    if version < 5 {
        // The structured resolver trace (per finding) and the scan's partial-read coverage. Nullable:
        // rows written before this version read back as unknown rather than a fabricated value.
        add_column_if_missing(conn, "findings", "resolver_trace", "TEXT")?;
        add_column_if_missing(conn, "scans", "read_gaps", "TEXT")?;
        version = 5;
    }

    conn.execute_batch(&format!("PRAGMA user_version = {version}"))?;
    debug_assert_eq!(version, SCHEMA_VERSION);
    Ok(())
}

fn add_column_if_missing(
    conn: &Connection,
    table: &str,
    column: &str,
    ty: &str,
) -> rusqlite::Result<()> {
    let present = conn
        .prepare(&format!("PRAGMA table_info({table})"))?
        .query_map([], |r| r.get::<_, String>(1))?
        .filter_map(Result::ok)
        .any(|name| name == column);
    if !present {
        conn.execute(&format!("ALTER TABLE {table} ADD COLUMN {column} {ty}"), [])?;
    }
    Ok(())
}

#[must_use]
pub fn content_hash(data: &[u8]) -> String {
    blake3::hash(data).to_hex().to_string()
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
    content_hash(canonical.as_bytes())
}

pub fn open(path: &std::path::Path) -> rusqlite::Result<Connection> {
    let conn = Connection::open(path)?;
    migrate(&conn)?;
    Ok(conn)
}

#[must_use]
pub fn open_memory() -> Connection {
    let conn = Connection::open_in_memory().expect("in-memory database");
    if let Err(e) = migrate(&conn) {
        // The in-memory store is the last-resort fallback; if even its schema cannot be created, say
        // so loudly instead of returning a tableless connection that fails every later query opaquely.
        eprintln!("[warn] in-memory history schema could not be created: {e}");
    }
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
            result_hash, module_size, pattern_set_hash, scanner_version, read_gaps)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19)",
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
            scan.module_size,
            scan.pattern_set_hash,
            scan.scanner_version,
            scan.read_gaps,
        ],
    )?;
    let id = tx.last_insert_rowid();
    {
        let mut stmt = tx.prepare(
            "INSERT INTO findings (scan_id, name, category, value, is_offset, status, matches, note, bytes, confidence, trace, candidates, resolver_trace)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
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
                f.confidence,
                f.trace,
                f.candidates,
                f.resolver_trace,
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
    let rows = stmt.query_map([], map_scan_row)?;
    rows.collect()
}

pub fn count_scans(conn: &Connection) -> rusqlite::Result<i64> {
    conn.query_row("SELECT COUNT(*) FROM scans", [], |r| r.get(0))
}

pub fn list_scans_page(
    conn: &Connection,
    limit: i64,
    offset: i64,
) -> rusqlite::Result<Vec<ScanRow>> {
    let mut stmt = conn.prepare(
        "SELECT id, created_at, module, arch, module_base, build_hash, build_version,
            found, not_found, total_matches, bytes, scan_ms
         FROM scans ORDER BY created_at DESC, id DESC LIMIT ?1 OFFSET ?2",
    )?;
    let rows = stmt.query_map(params![limit, offset], map_scan_row)?;
    rows.collect()
}

fn map_scan_row(r: &rusqlite::Row) -> rusqlite::Result<ScanRow> {
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
    let mut stmt = conn.prepare(
        "SELECT id, created_at, module, arch, module_base, build_hash, build_version,
            found, not_found, total_matches, bytes, scan_ms
         FROM scans WHERE id = ?1",
    )?;
    let mut rows = stmt.query_map([scan_id], map_scan_row)?;
    rows.next().transpose()
}

pub fn findings(conn: &Connection, scan_id: i64) -> rusqlite::Result<Vec<FindingRow>> {
    let mut stmt = conn.prepare(
        "SELECT name, category, value, is_offset, status, matches, note, bytes, confidence, trace, candidates, resolver_trace
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
            confidence: r.get(8)?,
            trace: r.get(9)?,
            candidates: r.get(10)?,
            resolver_trace: r.get(11)?,
        })
    })?;
    rows.collect()
}

/// The JSON-encoded read gaps for a saved scan (its partial-read coverage), or `None` if it read in
/// full or predates the column. Kept as a focused query so the scan-list mapping stays untouched.
pub fn scan_read_gaps(conn: &Connection, scan_id: i64) -> rusqlite::Result<Option<String>> {
    conn.query_row(
        "SELECT read_gaps FROM scans WHERE id = ?1",
        [scan_id],
        |r| r.get(0),
    )
    .optional()
    .map(Option::flatten)
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
            confidence: 100,
            trace: None,
            candidates: None,
            resolver_trace: None,
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
            module_size: 0x10_0000,
            pattern_set_hash: "patternset".to_string(),
            scanner_version: "0.0.0-test".to_string(),
            read_gaps: None,
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
    fn diagnostic_columns_round_trip() {
        let mut conn = open_memory();
        let mut f = finding("Amb", Some("0x10"));
        f.status = "found (ambiguous)".to_string();
        f.confidence = 50;
        f.trace = Some("memory pointer resolved to 0x10".to_string());
        f.candidates = Some("0x10,0x20".to_string());
        f.resolver_trace = Some(r#"{"kind":"MemoryPointer","target_rva":16}"#.to_string());
        let mut s = scan("AAAA");
        s.read_gaps = Some(r#"[{"base":4096,"requested":4096,"got":2048}]"#.to_string());
        let id = insert_scan(&mut conn, &s, &[f]).unwrap();
        let rows = findings(&conn, id).unwrap();
        assert_eq!(rows[0].confidence, Some(50));
        assert_eq!(
            rows[0].trace.as_deref(),
            Some("memory pointer resolved to 0x10")
        );
        assert_eq!(rows[0].candidates.as_deref(), Some("0x10,0x20"));
        // The structured trace and the scan's partial-read coverage round-trip.
        assert_eq!(
            rows[0].resolver_trace.as_deref(),
            Some(r#"{"kind":"MemoryPointer","target_rva":16}"#)
        );
        assert_eq!(
            scan_read_gaps(&conn, id).unwrap().as_deref(),
            Some(r#"[{"base":4096,"requested":4096,"got":2048}]"#)
        );
    }

    #[test]
    fn forensic_columns_round_trip() {
        let mut conn = open_memory();
        let mut s = scan("AAAA");
        s.module_size = 0x2A_0000;
        s.pattern_set_hash = "abc123".to_string();
        s.scanner_version = "9.9.9".to_string();
        let id = insert_scan(&mut conn, &s, &[finding("Foo", Some("0x10"))]).unwrap();
        let (size, ph, sv): (i64, String, String) = conn
            .query_row(
                "SELECT module_size, pattern_set_hash, scanner_version FROM scans WHERE id = ?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(size, 0x2A_0000);
        assert_eq!(ph, "abc123");
        assert_eq!(sv, "9.9.9");
    }

    #[test]
    fn upgrades_a_v3_database_and_reads_old_rows_as_null() {
        // A database written by the previous schema, without the v4 forensic columns, and with a row
        // already in it. Migration must add the columns without rewriting the row, so the old scan
        // reads back as "unknown" (NULL) rather than a fabricated value.
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE scans (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               created_at INTEGER NOT NULL, module TEXT NOT NULL, module_base TEXT NOT NULL,
               arch TEXT NOT NULL, build_hash TEXT NOT NULL, build_version TEXT,
               build_timestamp INTEGER NOT NULL, bytes INTEGER NOT NULL, regions INTEGER NOT NULL,
               found INTEGER NOT NULL, unresolved INTEGER NOT NULL, not_found INTEGER NOT NULL,
               total_matches INTEGER NOT NULL, scan_ms INTEGER NOT NULL, result_hash TEXT
             );
             CREATE TABLE findings (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
               name TEXT NOT NULL, category TEXT NOT NULL, value TEXT, is_offset INTEGER NOT NULL,
               status TEXT NOT NULL, matches INTEGER NOT NULL, note TEXT NOT NULL, bytes TEXT,
               confidence INTEGER, trace TEXT, candidates TEXT
             );
             PRAGMA user_version = 3;",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO scans (created_at, module, module_base, arch, build_hash, build_timestamp,
                bytes, regions, found, unresolved, not_found, total_matches, scan_ms)
             VALUES (1,'m','0x0','x64','HASH',0,0,0,0,0,0,0,0)",
            [],
        )
        .unwrap();

        migrate(&conn).unwrap();

        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
        let module_size: Option<i64> = conn
            .query_row("SELECT module_size FROM scans LIMIT 1", [], |r| r.get(0))
            .unwrap();
        assert_eq!(module_size, None);
        // and a fresh insert through the normal path now populates the new columns
        let mut conn = conn;
        let id = insert_scan(&mut conn, &scan("BBBB"), &[finding("Foo", Some("0x10"))]).unwrap();
        let sv: Option<String> = conn
            .query_row(
                "SELECT scanner_version FROM scans WHERE id = ?1",
                [id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(sv.as_deref(), Some("0.0.0-test"));
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

    #[test]
    fn scan_row_fetches_by_id() {
        let mut conn = open_memory();
        let id1 = insert_scan(&mut conn, &scan("AAAA"), &[finding("Foo", Some("0x10"))]).unwrap();
        let id2 = insert_scan(&mut conn, &scan("BBBB"), &[finding("Bar", Some("0x20"))]).unwrap();
        assert_eq!(scan_row(&conn, id1).unwrap().unwrap().build_hash, "AAAA");
        assert_eq!(scan_row(&conn, id2).unwrap().unwrap().build_hash, "BBBB");
        assert!(scan_row(&conn, 9999).unwrap().is_none());
    }

    #[test]
    fn migration_stamps_the_schema_version() {
        let conn = open_memory();
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
    }

    #[test]
    fn migration_is_idempotent() {
        let conn = open_memory();
        // Running it again must not error or change the version.
        migrate(&conn).unwrap();
        migrate(&conn).unwrap();
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
    }

    #[test]
    fn content_hash_is_blake3_and_distinguishes_inputs() {
        let h = content_hash(b"abc");
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(h, blake3::hash(b"abc").to_hex().to_string());
        assert_ne!(content_hash(b"abc"), content_hash(b"abd"));
    }

    #[test]
    fn pagination_slices_in_recency_order() {
        let mut conn = open_memory();
        for k in 0..5 {
            let mut s = scan("AAAA");
            s.created_at = i64::from(k);
            insert_scan(&mut conn, &s, &[finding("Foo", Some(&format!("0x{k}")))]).unwrap();
        }
        assert_eq!(count_scans(&conn).unwrap(), 5);
        let first_two = list_scans_page(&conn, 2, 0).unwrap();
        assert_eq!(first_two.len(), 2);
        // newest first: created_at 4 then 3
        assert_eq!(first_two[0].created_at, 4);
        assert_eq!(first_two[1].created_at, 3);
        let next_two = list_scans_page(&conn, 2, 2).unwrap();
        assert_eq!(next_two[0].created_at, 2);
        let tail = list_scans_page(&conn, 10, 4).unwrap();
        assert_eq!(tail.len(), 1);
        assert_eq!(tail[0].created_at, 0);
    }
}
