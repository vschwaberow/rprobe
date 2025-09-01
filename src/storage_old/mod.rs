// File: mod.rs
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023-2025
// - Volker Schwaberow <volker@schwaberow.de>

pub mod database;
pub mod directory;
pub mod errors;
pub mod models;

pub use database::{HistoryDatabase, HistoryDatabaseBuilder};
pub use directory::DataDirectoryManager;
pub use errors::{StorageError, StorageResult};
pub use models::*;

use std::sync::Arc;

pub trait HistoryStorage: Send + Sync {
    fn store_scan_data(&self, scan_data: &ScanData) -> StorageResult<()>;
    fn get_scan_data(&self, scan_id: &str) -> StorageResult<Option<ScanData>>;
    fn list_scans(&self, limit: Option<usize>) -> StorageResult<Vec<ScanSummary>>;
    fn delete_scan(&self, scan_id: &str) -> StorageResult<()>;
    fn get_target_history(&self, url: &str, limit: Option<usize>) -> StorageResult<Vec<HistoricalScanResult>>;
    fn get_change_events(&self, url: &str, after: Option<chrono::DateTime<chrono::Utc>>) -> StorageResult<Vec<ChangeEvent>>;
}

pub fn create_default_history_database() -> StorageResult<Arc<dyn HistoryStorage>> {
    let dir_manager = DataDirectoryManager::new()?;
    let db_path = dir_manager.get_database_path()?;
    
    let database = HistoryDatabaseBuilder::new()
        .path(db_path)
        .enable_compression()
        .build()?;
    
    Ok(Arc::new(database))
}
