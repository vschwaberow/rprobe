// File: storage.rs
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023-2025
// - Volker Schwaberow <volker@schwaberow.de>

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use dirs::data_local_dir;
use serde::{Deserialize, Serialize};
use sled::{Config, Db};
use std::collections::HashMap;
use std::path::PathBuf;

use crate::content_analyzer::{ContentFinding, FindingSeverity};
use crate::desync_scanner::DesyncResult;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRecord {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub url: String,
    pub status: String,
    pub detections: Vec<String>,
    pub content_findings: Vec<ContentFinding>,
    pub tls_info: HashMap<String, String>,
    pub response_time_ms: Option<u64>,
    pub response_headers: HashMap<String, String>,
    pub content_length: Option<u64>,
    pub desync_results: Vec<DesyncResult>,
    pub screenshot_path: Option<String>,
    pub robots_txt_content: Option<String>,
    pub scan_config: ScanConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    pub timeout: u64,
    pub http: bool,
    pub https: bool,
    pub detect_all: bool,
    pub content_analysis: bool,
    pub tls_analysis: bool,
    pub comprehensive_tls: bool,
    pub screenshot: bool,
    pub download_robots: bool,
    pub desync: bool,
    pub plugin_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSession {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub total_urls: usize,
    pub successful_scans: usize,
    pub failed_scans: usize,
    pub duration_ms: u64,
    pub config: ScanConfig,
}

#[derive(Debug, Clone)]
pub struct HistoryQuery {
    pub url_pattern: Option<String>,
    pub start_date: Option<DateTime<Utc>>,
    pub end_date: Option<DateTime<Utc>>,
    pub min_severity: Option<FindingSeverity>,
    pub has_detections: Option<bool>,
    pub has_tls_issues: Option<bool>,
    pub has_desync_findings: Option<bool>,
    pub status_codes: Option<Vec<String>>,
    pub limit: Option<usize>,
}

impl Default for HistoryQuery {
    fn default() -> Self {
        Self {
            url_pattern: None,
            start_date: None,
            end_date: None,
            min_severity: None,
            has_detections: None,
            has_tls_issues: None,
            has_desync_findings: None,
            status_codes: None,
            limit: Some(100),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComparisonResult {
    pub url: String,
    pub old_record: Option<ScanRecord>,
    pub new_record: Option<ScanRecord>,
    pub changes: Vec<String>,
}

pub struct HistoryDatabase {
    db: Db,
    scans_tree: sled::Tree,
    sessions_tree: sled::Tree,
    url_index_tree: sled::Tree,
}

impl HistoryDatabase {
    pub fn new(data_dir: Option<PathBuf>) -> Result<Self> {
        let db_path = match data_dir {
            Some(dir) => dir.join("rprobe_history"),
            None => data_local_dir()
                .or_else(|| Some(PathBuf::from(".")))
                .unwrap()
                .join("rprobe")
                .join("history"),
        };

        std::fs::create_dir_all(&db_path).context("Failed to create database directory")?;

        let db = Config::default()
            .path(&db_path)
            .compression_factor(9)
            .open()
            .context("Failed to open database")?;

        let scans_tree = db
            .open_tree(b"scans")
            .context("Failed to open scans tree")?;
        let sessions_tree = db
            .open_tree(b"sessions")
            .context("Failed to open sessions tree")?;
        let url_index_tree = db
            .open_tree(b"url_index")
            .context("Failed to open URL index tree")?;

        Ok(Self {
            db,
            scans_tree,
            sessions_tree,
            url_index_tree,
        })
    }

    pub fn store_scan(&self, record: &ScanRecord) -> Result<()> {
        let key = format!("{}_{}", record.timestamp.timestamp_millis(), record.id);
        let value = bincode::serialize(record).context("Failed to serialize scan record")?;

        self.scans_tree
            .insert(key.as_bytes(), value)
            .context("Failed to store scan record")?;

        let url_key = format!(
            "{}_{}_{}",
            record.url,
            record.timestamp.timestamp_millis(),
            record.id
        );
        self.url_index_tree
            .insert(url_key.as_bytes(), key.as_bytes())
            .context("Failed to update URL index")?;

        self.db.flush().context("Failed to flush database")?;
        Ok(())
    }

    pub fn store_scans_batch(&self, records: &[ScanRecord]) -> Result<()> {
        let mut scan_batch = sled::Batch::default();
        let mut url_index_batch = sled::Batch::default();

        for record in records {
            let key = format!("{}_{}", record.timestamp.timestamp_millis(), record.id);
            let value = bincode::serialize(record).context("Failed to serialize scan record")?;

            scan_batch.insert(key.as_bytes(), value);

            let url_key = format!(
                "{}_{}_{}",
                record.url,
                record.timestamp.timestamp_millis(),
                record.id
            );
            url_index_batch.insert(url_key.as_bytes(), key.as_bytes());
        }

        self.scans_tree
            .apply_batch(scan_batch)
            .context("Failed to store scan batch")?;

        self.url_index_tree
            .apply_batch(url_index_batch)
            .context("Failed to update URL index batch")?;

        self.db.flush().context("Failed to flush database")?;
        Ok(())
    }

    pub fn store_session(&self, session: &ScanSession) -> Result<()> {
        let key = format!("{}_{}", session.timestamp.timestamp_millis(), session.id);
        let value = bincode::serialize(session).context("Failed to serialize scan session")?;

        self.sessions_tree
            .insert(key.as_bytes(), value)
            .context("Failed to store scan session")?;

        self.db.flush().context("Failed to flush database")?;
        Ok(())
    }

    pub fn query_scans(&self, query: &HistoryQuery) -> Result<Vec<ScanRecord>> {
        let mut results = Vec::new();

        for result in self.scans_tree.iter() {
            let (_, value) = result.context("Failed to iterate over scans")?;
            let record: ScanRecord =
                bincode::deserialize(&value).context("Failed to deserialize scan record")?;

            if self.matches_query(&record, query) {
                results.push(record);
            }

            if let Some(limit) = query.limit {
                if results.len() >= limit {
                    break;
                }
            }
        }

        results.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        Ok(results)
    }

    pub fn get_url_history(&self, url: &str, limit: Option<usize>) -> Result<Vec<ScanRecord>> {
        let mut results = Vec::new();
        let url_prefix = format!("{}_", url);

        for result in self.url_index_tree.scan_prefix(url_prefix.as_bytes()) {
            let (_, scan_key) = result.context("Failed to scan URL index")?;

            if let Some(scan_data) = self
                .scans_tree
                .get(scan_key)
                .context("Failed to get scan from index")?
            {
                let record: ScanRecord = bincode::deserialize(&scan_data)
                    .context("Failed to deserialize indexed scan")?;
                results.push(record);
            }

            if let Some(limit) = limit {
                if results.len() >= limit {
                    break;
                }
            }
        }

        results.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        Ok(results)
    }

    pub fn compare_scans(
        &self,
        url: &str,
        old_timestamp: DateTime<Utc>,
        new_timestamp: DateTime<Utc>,
    ) -> Result<ComparisonResult> {
        let old_record = self.find_scan_by_url_and_time(url, old_timestamp)?;
        let new_record = self.find_scan_by_url_and_time(url, new_timestamp)?;

        let changes = self.calculate_changes(&old_record, &new_record);

        Ok(ComparisonResult {
            url: url.to_string(),
            old_record,
            new_record,
            changes,
        })
    }

    pub fn get_database_stats(&self) -> Result<HashMap<String, u64>> {
        let mut stats = HashMap::new();

        stats.insert("scans_count".to_string(), self.scans_tree.len() as u64);
        stats.insert(
            "sessions_count".to_string(),
            self.sessions_tree.len() as u64,
        );
        stats.insert(
            "url_index_entries".to_string(),
            self.url_index_tree.len() as u64,
        );

        let size_on_disk = self
            .db
            .size_on_disk()
            .context("Failed to get database size")?;
        stats.insert("size_bytes".to_string(), size_on_disk);

        Ok(stats)
    }

    pub fn clean_old_data(&self, before: DateTime<Utc>) -> Result<u64> {
        let mut deleted_count = 0;
        let cutoff_timestamp = before.timestamp_millis();

        let mut keys_to_delete = Vec::new();

        for result in self.scans_tree.iter() {
            let (key, value) = result.context("Failed to iterate during cleanup")?;
            let record: ScanRecord =
                bincode::deserialize(&value).context("Failed to deserialize for cleanup")?;

            if record.timestamp.timestamp_millis() < cutoff_timestamp {
                keys_to_delete.push(key.to_vec());
            }
        }

        for key in keys_to_delete {
            self.scans_tree
                .remove(&key)
                .context("Failed to remove old scan")?;
            deleted_count += 1;
        }

        let mut session_keys_to_delete = Vec::new();
        for result in self.sessions_tree.iter() {
            let (key, value) = result.context("Failed to iterate sessions during cleanup")?;
            let session: ScanSession = bincode::deserialize(&value)
                .context("Failed to deserialize session for cleanup")?;

            if session.timestamp.timestamp_millis() < cutoff_timestamp {
                session_keys_to_delete.push(key.to_vec());
            }
        }

        for key in session_keys_to_delete {
            self.sessions_tree
                .remove(&key)
                .context("Failed to remove old session")?;
        }

        self.rebuild_url_index()?;
        self.db.flush().context("Failed to flush after cleanup")?;

        Ok(deleted_count)
    }

    pub fn compact_database(&self) -> Result<()> {
        let stats_before = self.get_database_stats()?;

        self.scans_tree
            .flush()
            .context("Failed to flush scans tree")?;
        self.sessions_tree
            .flush()
            .context("Failed to flush sessions tree")?;
        self.url_index_tree
            .flush()
            .context("Failed to flush URL index tree")?;

        let stats_after = self.get_database_stats()?;

        let size_reduction = stats_before.get("size_bytes").unwrap_or(&0)
            - stats_after.get("size_bytes").unwrap_or(&0);
        log::info!(
            "Database compacted, reduced size by {} bytes",
            size_reduction
        );

        Ok(())
    }

    pub fn backup_database(&self, backup_path: &str) -> Result<()> {
        let backup_dir = std::path::Path::new(backup_path);
        std::fs::create_dir_all(backup_dir).context("Failed to create backup directory")?;

        let backup_db = Config::default()
            .path(backup_dir)
            .open()
            .context("Failed to open backup database")?;

        let backup_scans = backup_db
            .open_tree(b"scans")
            .context("Failed to open backup scans tree")?;
        let backup_sessions = backup_db
            .open_tree(b"sessions")
            .context("Failed to open backup sessions tree")?;
        let backup_url_index = backup_db
            .open_tree(b"url_index")
            .context("Failed to open backup URL index tree")?;

        for result in self.scans_tree.iter() {
            let (key, value) = result.context("Failed to iterate scans for backup")?;
            backup_scans
                .insert(key, value)
                .context("Failed to backup scan")?;
        }

        for result in self.sessions_tree.iter() {
            let (key, value) = result.context("Failed to iterate sessions for backup")?;
            backup_sessions
                .insert(key, value)
                .context("Failed to backup session")?;
        }

        for result in self.url_index_tree.iter() {
            let (key, value) = result.context("Failed to iterate URL index for backup")?;
            backup_url_index
                .insert(key, value)
                .context("Failed to backup URL index")?;
        }

        backup_db
            .flush()
            .context("Failed to flush backup database")?;
        Ok(())
    }

    pub fn verify_database_integrity(&self) -> Result<Vec<String>> {
        let mut issues = Vec::new();

        let scans_count = self.scans_tree.len();
        let url_index_count = self.url_index_tree.len();

        if scans_count != url_index_count {
            issues.push(format!(
                "Index mismatch: {} scans vs {} URL index entries",
                scans_count, url_index_count
            ));
        }

        for result in self.scans_tree.iter() {
            let (key, value) = result.context("Failed to iterate scans for integrity check")?;

            if bincode::deserialize::<ScanRecord>(&value).is_err() {
                issues.push(format!(
                    "Corrupted scan record with key: {}",
                    String::from_utf8_lossy(&key)
                ));
            }
        }

        for result in self.sessions_tree.iter() {
            let (key, value) = result.context("Failed to iterate sessions for integrity check")?;

            if bincode::deserialize::<ScanSession>(&value).is_err() {
                issues.push(format!(
                    "Corrupted session record with key: {}",
                    String::from_utf8_lossy(&key)
                ));
            }
        }

        Ok(issues)
    }

    fn matches_query(&self, record: &ScanRecord, query: &HistoryQuery) -> bool {
        if let Some(ref pattern) = query.url_pattern {
            if !record.url.contains(pattern) {
                return false;
            }
        }

        if let Some(start) = query.start_date {
            if record.timestamp < start {
                return false;
            }
        }

        if let Some(end) = query.end_date {
            if record.timestamp > end {
                return false;
            }
        }

        if let Some(ref status_codes) = query.status_codes {
            if !status_codes.contains(&record.status) {
                return false;
            }
        }

        if let Some(has_detections) = query.has_detections {
            let has_any = !record.detections.is_empty();
            if has_detections != has_any {
                return false;
            }
        }

        if let Some(has_tls) = query.has_tls_issues {
            let has_issues =
                record.tls_info.contains_key("warnings") || record.tls_info.contains_key("errors");
            if has_tls != has_issues {
                return false;
            }
        }

        if let Some(has_desync) = query.has_desync_findings {
            let has_findings = !record.desync_results.is_empty();
            if has_desync != has_findings {
                return false;
            }
        }

        if let Some(min_severity) = &query.min_severity {
            let has_min_severity = record
                .content_findings
                .iter()
                .any(|finding| finding.severity >= *min_severity);
            if !has_min_severity {
                return false;
            }
        }

        true
    }

    fn find_scan_by_url_and_time(
        &self,
        url: &str,
        timestamp: DateTime<Utc>,
    ) -> Result<Option<ScanRecord>> {
        let timestamp_ms = timestamp.timestamp_millis();
        let url_prefix = format!("{}_", url);

        for result in self.url_index_tree.scan_prefix(url_prefix.as_bytes()) {
            let (_, scan_key) = result.context("Failed to scan for specific timestamp")?;

            if let Some(scan_data) = self
                .scans_tree
                .get(scan_key)
                .context("Failed to get scan by timestamp")?
            {
                let record: ScanRecord = bincode::deserialize(&scan_data)
                    .context("Failed to deserialize timestamped scan")?;

                let diff = (record.timestamp.timestamp_millis() - timestamp_ms).abs();
                if diff < 60_000 {
                    return Ok(Some(record));
                }
            }
        }

        Ok(None)
    }

    fn calculate_changes(&self, old: &Option<ScanRecord>, new: &Option<ScanRecord>) -> Vec<String> {
        let mut changes = Vec::new();

        match (old, new) {
            (None, Some(_)) => changes.push("New scan result".to_string()),
            (Some(_), None) => changes.push("Scan result removed".to_string()),
            (Some(old_rec), Some(new_rec)) => {
                if old_rec.status != new_rec.status {
                    changes.push(format!(
                        "Status changed: {} -> {}",
                        old_rec.status, new_rec.status
                    ));
                }

                let old_detections: std::collections::HashSet<_> =
                    old_rec.detections.iter().collect();
                let new_detections: std::collections::HashSet<_> =
                    new_rec.detections.iter().collect();

                for detection in new_detections.difference(&old_detections) {
                    changes.push(format!("New detection: {}", detection));
                }

                for detection in old_detections.difference(&new_detections) {
                    changes.push(format!("Detection removed: {}", detection));
                }

                let old_critical_findings = old_rec
                    .content_findings
                    .iter()
                    .filter(|f| f.severity == FindingSeverity::Critical)
                    .count();
                let new_critical_findings = new_rec
                    .content_findings
                    .iter()
                    .filter(|f| f.severity == FindingSeverity::Critical)
                    .count();

                if old_critical_findings != new_critical_findings {
                    changes.push(format!(
                        "Critical findings changed: {} -> {}",
                        old_critical_findings, new_critical_findings
                    ));
                }

                let old_tls_issues = old_rec.tls_info.contains_key("warnings")
                    || old_rec.tls_info.contains_key("errors");
                let new_tls_issues = new_rec.tls_info.contains_key("warnings")
                    || new_rec.tls_info.contains_key("errors");

                if old_tls_issues != new_tls_issues {
                    if new_tls_issues && !old_tls_issues {
                        changes.push("New TLS issues detected".to_string());
                    } else if !new_tls_issues && old_tls_issues {
                        changes.push("TLS issues resolved".to_string());
                    }
                }

                if old_rec.desync_results.len() != new_rec.desync_results.len() {
                    changes.push(format!(
                        "Desync results changed: {} -> {} findings",
                        old_rec.desync_results.len(),
                        new_rec.desync_results.len()
                    ));
                }

                if old_rec.response_time_ms != new_rec.response_time_ms {
                    let old_time = old_rec.response_time_ms.unwrap_or(0);
                    let new_time = new_rec.response_time_ms.unwrap_or(0);
                    let diff = (new_time as i64 - old_time as i64).abs();
                    if diff > 100 {
                        changes.push(format!(
                            "Significant response time change: {}ms -> {}ms",
                            old_time, new_time
                        ));
                    }
                }

                let old_screenshot = old_rec.screenshot_path.is_some();
                let new_screenshot = new_rec.screenshot_path.is_some();
                if old_screenshot != new_screenshot {
                    if new_screenshot {
                        changes.push("Screenshot now available".to_string());
                    } else {
                        changes.push("Screenshot no longer available".to_string());
                    }
                }
            }
            (None, None) => {}
        }

        changes
    }

    fn rebuild_url_index(&self) -> Result<()> {
        self.url_index_tree
            .clear()
            .context("Failed to clear URL index")?;

        for result in self.scans_tree.iter() {
            let (key, value) = result.context("Failed to iterate for index rebuild")?;
            let record: ScanRecord =
                bincode::deserialize(&value).context("Failed to deserialize for index rebuild")?;

            let url_key = format!(
                "{}_{}_{}",
                record.url,
                record.timestamp.timestamp_millis(),
                record.id
            );
            self.url_index_tree
                .insert(url_key.as_bytes(), &key)
                .context("Failed to rebuild URL index entry")?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_db() -> (HistoryDatabase, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let db = HistoryDatabase::new(Some(temp_dir.path().to_path_buf())).unwrap();
        (db, temp_dir)
    }

    fn create_test_record(url: &str, timestamp: DateTime<Utc>) -> ScanRecord {
        ScanRecord {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp,
            url: url.to_string(),
            status: "200".to_string(),
            detections: vec!["Nginx".to_string()],
            content_findings: vec![],
            tls_info: HashMap::new(),
            response_time_ms: Some(150),
            response_headers: HashMap::new(),
            content_length: Some(1024),
            desync_results: vec![],
            screenshot_path: None,
            robots_txt_content: None,
            scan_config: ScanConfig {
                timeout: 10,
                http: true,
                https: true,
                detect_all: true,
                content_analysis: false,
                tls_analysis: false,
                comprehensive_tls: false,
                screenshot: false,
                download_robots: false,
                desync: false,
                plugin_name: None,
            },
        }
    }

    #[test]
    fn test_store_and_query_scans() {
        let (db, _temp_dir) = create_test_db();
        let now = Utc::now();
        let record = create_test_record("https://example.com", now);

        db.store_scan(&record).unwrap();

        let query = HistoryQuery {
            url_pattern: Some("example.com".to_string()),
            ..Default::default()
        };

        let results = db.query_scans(&query).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].url, "https://example.com");
    }

    #[test]
    fn test_url_history() {
        let (db, _temp_dir) = create_test_db();
        let now = Utc::now();
        let url = "https://example.com";

        let record1 = create_test_record(url, now - chrono::Duration::days(1));
        let record2 = create_test_record(url, now);

        db.store_scan(&record1).unwrap();
        db.store_scan(&record2).unwrap();

        let history = db.get_url_history(url, Some(10)).unwrap();
        assert_eq!(history.len(), 2);
        assert!(history[0].timestamp > history[1].timestamp);
    }

    #[test]
    fn test_database_stats() {
        let (db, _temp_dir) = create_test_db();
        let now = Utc::now();
        let record = create_test_record("https://example.com", now);

        db.store_scan(&record).unwrap();

        let stats = db.get_database_stats().unwrap();
        assert_eq!(stats.get("scans_count").unwrap(), &1);
        assert!(stats.contains_key("size_bytes"));
    }

    #[test]
    fn test_clean_old_data() {
        let (db, _temp_dir) = create_test_db();
        let now = Utc::now();

        let old_record = create_test_record("https://old.com", now - chrono::Duration::days(10));
        let new_record = create_test_record("https://new.com", now);

        db.store_scan(&old_record).unwrap();
        db.store_scan(&new_record).unwrap();

        let cutoff = now - chrono::Duration::days(5);
        let deleted = db.clean_old_data(cutoff).unwrap();

        assert_eq!(deleted, 1);

        let remaining = db.query_scans(&HistoryQuery::default()).unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].url, "https://new.com");
    }

    #[test]
    fn test_batch_storage() {
        let (db, _temp_dir) = create_test_db();
        let now = Utc::now();

        let records = vec![
            create_test_record("https://example1.com", now),
            create_test_record("https://example2.com", now),
            create_test_record("https://example3.com", now),
        ];

        db.store_scans_batch(&records).unwrap();

        let stored_records = db.query_scans(&HistoryQuery::default()).unwrap();
        assert_eq!(stored_records.len(), 3);
    }

    #[test]
    fn test_response_time_storage() {
        let (db, _temp_dir) = create_test_db();
        let now = Utc::now();

        let mut record = create_test_record("https://example.com", now);
        record.response_time_ms = Some(500);

        db.store_scan(&record).unwrap();

        let stored_records = db.query_scans(&HistoryQuery::default()).unwrap();
        assert_eq!(stored_records.len(), 1);
        assert_eq!(stored_records[0].response_time_ms, Some(500));
    }

    #[test]
    fn test_desync_results_query() {
        let (db, _temp_dir) = create_test_db();
        let now = Utc::now();

        let mut record_with_desync = create_test_record("https://example.com", now);
        record_with_desync.desync_results = vec![];

        let mut record_without_desync = create_test_record("https://example2.com", now);
        record_without_desync.desync_results = vec![];

        db.store_scan(&record_with_desync).unwrap();
        db.store_scan(&record_without_desync).unwrap();

        let query = HistoryQuery {
            has_desync_findings: Some(false),
            ..Default::default()
        };

        let results = db.query_scans(&query).unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_database_maintenance() {
        let (db, _temp_dir) = create_test_db();
        let now = Utc::now();

        let record = create_test_record("https://example.com", now);
        db.store_scan(&record).unwrap();

        let stats_before = db.get_database_stats().unwrap();
        assert_eq!(stats_before.get("scans_count").unwrap(), &1);

        db.compact_database().unwrap();

        let stats_after = db.get_database_stats().unwrap();
        assert_eq!(stats_after.get("scans_count").unwrap(), &1);

        let integrity_issues = db.verify_database_integrity().unwrap();
        assert!(integrity_issues.is_empty());
    }

    #[test]
    fn test_scan_comparison_with_new_fields() {
        let (db, _temp_dir) = create_test_db();
        let now = Utc::now();
        let earlier = now - chrono::Duration::hours(1);

        let mut old_record = create_test_record("https://example.com", earlier);
        old_record.response_time_ms = Some(200);
        old_record.screenshot_path = None;

        let mut new_record = create_test_record("https://example.com", now);
        new_record.response_time_ms = Some(500);
        new_record.screenshot_path = Some("screenshot.png".to_string());

        db.store_scan(&old_record).unwrap();
        db.store_scan(&new_record).unwrap();

        let comparison = db
            .compare_scans("https://example.com", earlier, now)
            .unwrap();

        assert!(!comparison.changes.is_empty());
        assert!(comparison
            .changes
            .iter()
            .any(|c| c.contains("response time")));
        assert!(comparison
            .changes
            .iter()
            .any(|c| c.contains("Screenshot now available")));
    }
}
