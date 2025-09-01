// File: directory.rs
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023-2025
// - Volker Schwaberow <volker@schwaberow.de>

use std::path::PathBuf;
use std::fs;
use dirs;

#[derive(Debug)]
pub enum DataDirectoryError {
    HomeDirectoryNotFound,
    DirectoryCreation(std::io::Error),
    InvalidPath(String),
}

impl std::fmt::Display for DataDirectoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HomeDirectoryNotFound => write!(f, "Home directory not found"),
            Self::DirectoryCreation(e) => write!(f, "Failed to create directory: {}", e),
            Self::InvalidPath(path) => write!(f, "Invalid path: {}", path),
        }
    }
}

impl std::error::Error for DataDirectoryError {}

impl From<DataDirectoryError> for crate::storage::errors::StorageError {
    fn from(error: DataDirectoryError) -> Self {
        crate::storage::errors::StorageError::DirectoryCreation(error.to_string())
    }
}

#[derive(Debug)]
pub struct DataDirectoryManager {
    base_path: PathBuf,
}

impl DataDirectoryManager {
    pub fn new() -> Result<Self, DataDirectoryError> {
        let base_path = Self::get_default_data_directory()?;
        Self::from_path(base_path)
    }

    pub fn from_path(base_path: PathBuf) -> Result<Self, DataDirectoryError> {
        if !base_path.is_absolute() {
            return Err(DataDirectoryError::InvalidPath(
                "Path must be absolute".to_string(),
            ));
        }

        let manager = Self { base_path };
        manager.ensure_directories_exist()?;
        Ok(manager)
    }

    pub fn get_database_path(&self) -> Result<PathBuf, DataDirectoryError> {
        Ok(self.base_path.join("history.db"))
    }

    pub fn get_reports_directory(&self) -> Result<PathBuf, DataDirectoryError> {
        let path = self.base_path.join("reports");
        self.ensure_directory_exists(&path)?;
        Ok(path)
    }

    pub fn get_screenshots_directory(&self) -> Result<PathBuf, DataDirectoryError> {
        let path = self.base_path.join("screenshots");
        self.ensure_directory_exists(&path)?;
        Ok(path)
    }

    pub fn get_temp_directory(&self) -> Result<PathBuf, DataDirectoryError> {
        let path = self.base_path.join("temp");
        self.ensure_directory_exists(&path)?;
        Ok(path)
    }

    pub fn get_base_path(&self) -> &PathBuf {
        &self.base_path
    }

    fn get_default_data_directory() -> Result<PathBuf, DataDirectoryError> {
        let data_dir = if cfg!(target_os = "windows") {
            dirs::data_dir()
                .ok_or(DataDirectoryError::HomeDirectoryNotFound)?
                .join("rprobe")
        } else if cfg!(target_os = "macos") {
            dirs::data_dir()
                .ok_or(DataDirectoryError::HomeDirectoryNotFound)?
                .join("rprobe")
        } else {
            dirs::data_dir()
                .or_else(|| dirs::home_dir().map(|h| h.join(".local").join("share")))
                .ok_or(DataDirectoryError::HomeDirectoryNotFound)?
                .join("rprobe")
        };

        Ok(data_dir)
    }

    fn ensure_directories_exist(&self) -> Result<(), DataDirectoryError> {
        self.ensure_directory_exists(&self.base_path)?;
        self.get_reports_directory()?;
        self.get_screenshots_directory()?;
        self.get_temp_directory()?;
        Ok(())
    }

    fn ensure_directory_exists(&self, path: &PathBuf) -> Result<(), DataDirectoryError> {
        if !path.exists() {
            fs::create_dir_all(path).map_err(DataDirectoryError::DirectoryCreation)?;
        }
        Ok(())
    }
}

impl Default for DataDirectoryManager {
    fn default() -> Self {
        Self::new().expect("Failed to create default data directory manager")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_directory_manager_creation() {
        let temp_dir = TempDir::new().unwrap();
        let manager = DataDirectoryManager::from_path(temp_dir.path().to_path_buf()).unwrap();
        
        assert!(manager.get_database_path().is_ok());
        assert!(manager.get_reports_directory().unwrap().exists());
        assert!(manager.get_screenshots_directory().unwrap().exists());
        assert!(manager.get_temp_directory().unwrap().exists());
    }

    #[test]
    fn test_invalid_relative_path() {
        let relative_path = PathBuf::from("relative/path");
        let result = DataDirectoryManager::from_path(relative_path);
        assert!(result.is_err());
        matches!(result.unwrap_err(), DataDirectoryError::InvalidPath(_));
    }

    #[test]
    fn test_default_data_directory() {
        let result = DataDirectoryManager::get_default_data_directory();
        assert!(result.is_ok());
        let path = result.unwrap();
        assert!(path.is_absolute());
        assert!(path.file_name().unwrap() == "rprobe");
    }
}
