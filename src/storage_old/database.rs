// File: database.rs
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023-2025
// - Volker Schwaberow <volker@schwaberow.de>

use crate::storage::errors::{StorageError, StorageResult};
use crate::storage::models::*;
use crate::storage::HistoryStorage;
use chrono::{DateTime, Utc};
use sled::Db;
use std::path::PathBuf;
use std::sync::Arc;

const TREE_SCANS: &str = "scans";
const TREE_RESULTS: &str = "results";
const TREE_HISTORY: &str = "history";
const TREE_CHANGES: &str = "changes";

pub struct HistoryDatabase {
    db: Arc<Db>,
}

impl HistoryDatabase {
    pub fn open<P: Into<PathBuf>>(path: P) -> StorageResult<Self> {
        let path = path.into();
        
        let config = sled::Config::default()
            .path(path)
            .cache_capacity(64 * 1024 * 1024) 
            .flush_every_ms(Some(1000))
            .compression_factor(22)
            .use_compression(true);

        let db = config.open()
            .map_err(|e| StorageError::Database(format!("Failed to open database: {}", e)))?;
        
        Ok(Self { db: Arc::new(db) })
    }

    fn get_scans_tree(&self) -> StorageResult<sled::Tree> {
        self.db.open_tree(TREE_SCANS)
            .map_err(|e| StorageError::Database(format!("Failed to open scans tree: {}", e)))
    }

    fn get_results_tree(&self) -> StorageResult<sled::Tree> {
        self.db.open_tree(TREE_RESULTS)
            .map_err(|e| StorageError::Database(format!("Failed to open results tree: {}", e)))
    }

    fn get_history_tree(&self) -> StorageResult<sled::Tree> {
        self.db.open_tree(TREE_HISTORY)
            .map_err(|e| StorageError::Database(format!("Failed to open history tree: {}", e)))
    }

    fn get_changes_tree(&self) -> StorageResult<sled::Tree> {
        self.db.open_tree(TREE_CHANGES)
            .map_err(|e| StorageError::Database(format!("Failed to open changes tree: {}", e)))
    }

    fn generate_scan_key(scan_id: &str) -> String {
        format!("scan:{}", scan_id)
    }

    fn generate_result_key(scan_id: &str, url_hash: &str) -> String {
        format!("result:{}:{}", scan_id, url_hash)
    }

    fn generate_history_key(url_hash: &str, timestamp: DateTime<Utc>) -> String {
        let timestamp_millis = timestamp.timestamp_millis();
        format!("history:{}:{:016x}", url_hash, timestamp_millis as u64)
    }

    fn generate_change_key(url_hash: &str, timestamp: DateTime<Utc>, change_id: &str) -> String {
        let timestamp_millis = timestamp.timestamp_millis();
        format!("change:{}:{:016x}:{}", url_hash, timestamp_millis as u64, change_id)
    }

    fn hash_url(url: &str) -> String {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(url.as_bytes());
        format!("{:x}", hasher.finalize())[..16].to_string()
    }

    pub fn flush(&self) -> StorageResult<()> {
        self.db.flush()
            .map_err(|e| StorageError::Database(format!("Failed to flush database: {}", e)))?;
        Ok(())
    }

    pub fn get_stats(&self) -> StorageResult<Vec<(String, String)>> {
        let mut stats = Vec::new();
        
        let tree_names = [TREE_SCANS, TREE_RESULTS, TREE_HISTORY, TREE_CHANGES];
        for tree_name in &tree_names {
            if let Ok(tree) = self.db.open_tree(tree_name) {
                let len = tree.len();
                stats.push((format!("{}_keys", tree_name), len.to_string()));
                
                let mut estimated_size = 0u64;
                for result in tree.iter() {
                    if let Ok((key, value)) = result {
                        estimated_size += key.len() as u64 + value.len() as u64;
                    }
                }
                stats.push((format!("{}_estimated_size_bytes", tree_name), estimated_size.to_string()));
            }
        }
        
        Ok(stats)
    }

    pub fn compact(&self) -> StorageResult<()> {
        self.flush()
    }
}

impl HistoryStorage for HistoryDatabase {
    fn store_scan_data(&self, scan_data: &ScanData) -> StorageResult<()> {
        let scans_tree = self.get_scans_tree()?;
        let results_tree = self.get_results_tree()?;
        let history_tree = self.get_history_tree()?;

        let scan_key = Self::generate_scan_key(&scan_data.scan_id);
        let scan_data_bytes = bincode::serialize(scan_data)?;
        scans_tree.insert(scan_key.as_bytes(), scan_data_bytes)
            .map_err(|e| StorageError::Database(format!("Failed to store scan data: {}", e)))?;

        for result in &scan_data.results {
            let url_hash = Self::hash_url(&result.url);
            let result_key = Self::generate_result_key(&scan_data.scan_id, &url_hash);
            let result_bytes = bincode::serialize(result)?;
            results_tree.insert(result_key.as_bytes(), result_bytes)
                .map_err(|e| StorageError::Database(format!("Failed to store result: {}", e)))?;

            let historical_result = HistoricalScanResult {
                url: result.url.clone(),
                scan_id: scan_data.scan_id.clone(),
                timestamp: result.timestamp,
                status_code: result.status_code,
                response_time_ms: result.response_time_ms,
                technology_detections: result
                    .technology_detections
                    .iter()
                    .map(|t| format!("{}: {}", t.plugin_name, t.detection_info))
                    .collect(),
                content_findings_count: result.content_findings.len(),
                critical_findings_count: result
                    .content_findings
                    .iter()
                    .filter(|f| matches!(f.severity, FindingSeverity::Critical))
                    .count(),
                tls_valid_until: result.tls_info.as_ref().map(|tls| tls.valid_to),
                success: result.success,
            };

            let history_key = Self::generate_history_key(&url_hash, result.timestamp);
            let history_bytes = bincode::serialize(&historical_result)?;
            history_tree.insert(history_key.as_bytes(), history_bytes)
                .map_err(|e| StorageError::Database(format!("Failed to store history: {}", e)))?;
        }

        self.flush()?;
        Ok(())
    }

    fn get_scan_data(&self, scan_id: &str) -> StorageResult<Option<ScanData>> {
        let scans_tree = self.get_scans_tree()?;
        let scan_key = Self::generate_scan_key(scan_id);

        match scans_tree.get(scan_key.as_bytes())
            .map_err(|e| StorageError::Database(format!("Failed to get scan data: {}", e)))? {
            Some(data) => {
                let scan_data: ScanData = bincode::deserialize(&data)?;
                Ok(Some(scan_data))
            }
            None => Ok(None),
        }
    }

    fn list_scans(&self, limit: Option<usize>) -> StorageResult<Vec<ScanSummary>> {
        let scans_tree = self.get_scans_tree()?;
        let mut summaries = Vec::new();
        let limit = limit.unwrap_or(usize::MAX);

        for result in scans_tree.iter() {
            if summaries.len() >= limit {
                break;
            }

            let (_, value) = result
                .map_err(|e| StorageError::Database(format!("Failed to iterate scans: {}", e)))?;
            let scan_data: ScanData = bincode::deserialize(&value)?;
            summaries.push(scan_data.summary);
        }

        summaries.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        Ok(summaries)
    }

    fn delete_scan(&self, scan_id: &str) -> StorageResult<()> {
        let scan_data = self.get_scan_data(scan_id)?
            .ok_or_else(|| StorageError::NotFound(format!("Scan with ID '{}'", scan_id)))?;

        let scans_tree = self.get_scans_tree()?;
        let results_tree = self.get_results_tree()?;

        let scan_key = Self::generate_scan_key(scan_id);
        scans_tree.remove(scan_key.as_bytes())
            .map_err(|e| StorageError::Database(format!("Failed to delete scan: {}", e)))?;

        for result in &scan_data.results {
            let url_hash = Self::hash_url(&result.url);
            let result_key = Self::generate_result_key(scan_id, &url_hash);
            results_tree.remove(result_key.as_bytes())
                .map_err(|e| StorageError::Database(format!("Failed to delete result: {}", e)))?;
        }

        self.flush()?;
        Ok(())
    }

    fn get_target_history(&self, url: &str, limit: Option<usize>) -> StorageResult<Vec<HistoricalScanResult>> {
        let history_tree = self.get_history_tree()?;
        let url_hash = Self::hash_url(url);
        let prefix = format!("history:{}:", url_hash);

        let mut results = Vec::new();
        let limit = limit.unwrap_or(usize::MAX);

        for result in history_tree.scan_prefix(prefix.as_bytes()) {
            if results.len() >= limit {
                break;
            }

            let (_, value) = result
                .map_err(|e| StorageError::Database(format!("Failed to scan history: {}", e)))?;
            let historical_result: HistoricalScanResult = bincode::deserialize(&value)?;
            results.push(historical_result);
        }

        results.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        Ok(results)
    }

    fn get_change_events(&self, url: &str, after: Option<DateTime<Utc>>) -> StorageResult<Vec<ChangeEvent>> {
        let changes_tree = self.get_changes_tree()?;
        let url_hash = Self::hash_url(url);
        let prefix = format!("change:{}:", url_hash);

        let mut events = Vec::new();

        for result in changes_tree.scan_prefix(prefix.as_bytes()) {
            let (_, value) = result
                .map_err(|e| StorageError::Database(format!("Failed to scan changes: {}", e)))?;
            let change_event: ChangeEvent = bincode::deserialize(&value)?;
            
            if let Some(after_time) = after {
                if change_event.timestamp <= after_time {
                    continue;
                }
            }
            
            events.push(change_event);
        }

        events.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
        Ok(events)
    }
}

pub struct HistoryDatabaseBuilder {
    path: Option<PathBuf>,
    cache_capacity: Option<u64>,
    flush_every_ms: Option<u64>,
    use_compression: bool,
}

impl HistoryDatabaseBuilder {
    pub fn new() -> Self {
        Self {
            path: None,
            cache_capacity: None,
            flush_every_ms: None,
            use_compression: false,
        }
    }

    pub fn path<P: Into<PathBuf>>(mut self, path: P) -> Self {
        self.path = Some(path.into());
        self
    }

    pub fn enable_compression(mut self) -> Self {
        self.use_compression = true;
        self
    }

    pub fn cache_capacity(mut self, capacity: u64) -> Self {
        self.cache_capacity = Some(capacity);
        self
    }

    pub fn flush_every_ms(mut self, ms: u64) -> Self {
        self.flush_every_ms = Some(ms);
        self
    }

    pub fn max_open_files(self, _max_files: i32) -> Self {
        self
    }

    pub fn write_buffer_size(self, _size: usize) -> Self {
        self
    }

    pub fn build(self) -> StorageResult<HistoryDatabase> {
        let path = self.path
            .ok_or_else(|| StorageError::Configuration("Database path not specified".to_string()))?;

        let mut config = sled::Config::default().path(path);
        
        if let Some(capacity) = self.cache_capacity {
            config = config.cache_capacity(capacity);
        }
        
        if let Some(ms) = self.flush_every_ms {
            config = config.flush_every_ms(Some(ms));
        }
        
        if self.use_compression {
            config = config.use_compression(true).compression_factor(22);
        }

        let db = config.open()
            .map_err(|e| StorageError::Database(format!("Failed to open database: {}", e)))?;
            
        Ok(HistoryDatabase { db: Arc::new(db) })
    }
}

impl Default for HistoryDatabaseBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use std::collections::HashMap;

    fn create_test_database() -> (HistoryDatabase, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let db = HistoryDatabase::open(db_path).unwrap();
        (db, temp_dir)
    }

    fn create_test_scan_data() -> ScanData {
        let config = ScanConfiguration {
            timeout: 10,
            workers: 1,
            rate_limit: 10,
            http_enabled: true,
            https_enabled: true,
            detect_all: true,
            content_analysis: false,
            tls_analysis: false,
            comprehensive_tls: false,
            screenshot: false,
            plugin: None,
        };

        let results = vec![HttpScanResult::new_successful(
            "https://example.com".to_string(),
            200,
            500,
            Some(1024),
            HashMap::new(),
            Some("Example".to_string()),
            Some("nginx".to_string()),
        )];

        let targets = vec!["https://example.com".to_string()];
        ScanData::new(targets, config, results)
    }

    #[test]
    fn test_database_creation() {
        let (db, _temp_dir) = create_test_database();
        assert!(db.get_stats().is_ok());
    }

    #[test]
    fn test_store_and_retrieve_scan_data() {
        let (db, _temp_dir) = create_test_database();
        let scan_data = create_test_scan_data();
        let scan_id = scan_data.scan_id.clone();

        db.store_scan_data(&scan_data).unwrap();
        
        let retrieved = db.get_scan_data(&scan_id).unwrap();
        assert!(retrieved.is_some());
        
        let retrieved_data = retrieved.unwrap();
        assert_eq!(retrieved_data.scan_id, scan_id);
        assert_eq!(retrieved_data.results.len(), 1);
    }

    #[test]
    fn test_list_scans() {
        let (db, _temp_dir) = create_test_database();
        let scan_data1 = create_test_scan_data();
        let scan_data2 = create_test_scan_data();

        db.store_scan_data(&scan_data1).unwrap();
        db.store_scan_data(&scan_data2).unwrap();

        let summaries = db.list_scans(None).unwrap();
        assert_eq!(summaries.len(), 2);
    }

    #[test]
    fn test_delete_scan() {
        let (db, _temp_dir) = create_test_database();
        let scan_data = create_test_scan_data();
        let scan_id = scan_data.scan_id.clone();

        db.store_scan_data(&scan_data).unwrap();
        assert!(db.get_scan_data(&scan_id).unwrap().is_some());

        db.delete_scan(&scan_id).unwrap();
        assert!(db.get_scan_data(&scan_id).unwrap().is_none());
    }

    #[test]
    fn test_get_target_history() {
        let (db, _temp_dir) = create_test_database();
        let scan_data = create_test_scan_data();
        let url = "https://example.com";

        db.store_scan_data(&scan_data).unwrap();
        
        let history = db.get_target_history(url, None).unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].url, url);
    }

    #[test]
    fn test_url_hashing() {
        let hash1 = HistoryDatabase::hash_url("https://example.com");
        let hash2 = HistoryDatabase::hash_url("https://example.com");
        let hash3 = HistoryDatabase::hash_url("https://different.com");

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
        assert_eq!(hash1.len(), 16);
    }

    #[test]
    fn test_database_builder() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("builder_test.db");

        let db = HistoryDatabaseBuilder::new()
            .path(db_path)
            .enable_compression()
            .cache_capacity(32 * 1024 * 1024)
            .flush_every_ms(500)
            .build()
            .unwrap();

        assert!(db.get_stats().is_ok());
    }
}
