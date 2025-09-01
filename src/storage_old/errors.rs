// File: errors.rs
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023-2025
// - Volker Schwaberow <volker@schwaberow.de>

use std::fmt;

#[derive(Debug)]
pub enum StorageError {
    Database(String),
    Serialization(bincode::Error),
    Io(std::io::Error),
    InvalidData(String),
    NotFound(String),
    DirectoryCreation(String),
    Configuration(String),
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(e) => write!(f, "Database error: {}", e),
            Self::Serialization(e) => write!(f, "Serialization error: {}", e),
            Self::Io(e) => write!(f, "I/O error: {}", e),
            Self::InvalidData(msg) => write!(f, "Invalid data: {}", msg),
            Self::NotFound(resource) => write!(f, "Resource not found: {}", resource),
            Self::DirectoryCreation(msg) => write!(f, "Directory creation failed: {}", msg),
            Self::Configuration(msg) => write!(f, "Configuration error: {}", msg),
        }
    }
}

impl std::error::Error for StorageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Database(_) => None,
            Self::Serialization(e) => Some(e),
            Self::Io(e) => Some(e),
            Self::InvalidData(_) => None,
            Self::NotFound(_) => None,
            Self::DirectoryCreation(_) => None,
            Self::Configuration(_) => None,
        }
    }
}

impl From<sled::Error> for StorageError {
    fn from(error: sled::Error) -> Self {
        Self::Database(error.to_string())
    }
}

impl From<bincode::Error> for StorageError {
    fn from(error: bincode::Error) -> Self {
        Self::Serialization(error)
    }
}

impl From<std::io::Error> for StorageError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

pub type StorageResult<T> = Result<T, StorageError>;
