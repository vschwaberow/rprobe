// File: models.rs
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023-2025
// - Volker Schwaberow <volker@schwaberow.de>

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanData {
    pub scan_id: String,
    pub timestamp: DateTime<Utc>,
    pub targets: Vec<String>,
    pub configuration: ScanConfiguration,
    pub results: Vec<HttpScanResult>,
    pub summary: ScanSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfiguration {
    pub timeout: u64,
    pub workers: u32,
    pub rate_limit: u32,
    pub http_enabled: bool,
    pub https_enabled: bool,
    pub detect_all: bool,
    pub content_analysis: bool,
    pub tls_analysis: bool,
    pub comprehensive_tls: bool,
    pub screenshot: bool,
    pub plugin: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpScanResult {
    pub url: String,
    pub timestamp: DateTime<Utc>,
    pub status_code: Option<u16>,
    pub response_time_ms: Option<u64>,
    pub content_length: Option<u64>,
    pub headers: HashMap<String, String>,
    pub title: Option<String>,
    pub server: Option<String>,
    pub technology_detections: Vec<PluginResult>,
    pub content_findings: Vec<ContentFinding>,
    pub tls_info: Option<TlsInfo>,
    pub screenshot_path: Option<String>,
    pub error_message: Option<String>,
    pub success: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginResult {
    pub plugin_name: String,
    pub plugin_version: String,
    pub detection_info: String,
    pub confidence: f32,
    pub category: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentFinding {
    pub category: String,
    pub description: String,
    pub severity: FindingSeverity,
    pub matched_text: Option<String>,
    pub context: Option<String>,
    pub location: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FindingSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsInfo {
    pub subject: String,
    pub issuer: String,
    pub valid_from: DateTime<Utc>,
    pub valid_to: DateTime<Utc>,
    pub days_until_expiry: i64,
    pub serial_number: Option<String>,
    pub fingerprint: Option<String>,
    pub certificate_chain: Vec<String>,
    pub cipher_suite: Option<String>,
    pub tls_version: Option<String>,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
    pub comprehensive_data: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub scan_id: String,
    pub timestamp: DateTime<Utc>,
    pub total_targets: usize,
    pub successful_requests: usize,
    pub failed_requests: usize,
    pub total_detections: usize,
    pub critical_findings: usize,
    pub high_findings: usize,
    pub duration_seconds: f64,
    pub tags: Vec<String>,
    pub configuration_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoricalScanResult {
    pub url: String,
    pub scan_id: String,
    pub timestamp: DateTime<Utc>,
    pub status_code: Option<u16>,
    pub response_time_ms: Option<u64>,
    pub technology_detections: Vec<String>,
    pub content_findings_count: usize,
    pub critical_findings_count: usize,
    pub tls_valid_until: Option<DateTime<Utc>>,
    pub success: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeEvent {
    pub id: String,
    pub url: String,
    pub timestamp: DateTime<Utc>,
    pub change_type: ChangeType,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
    pub field_name: String,
    pub severity: ChangeSeverity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChangeType {
    StatusCodeChanged,
    TechnologyAdded,
    TechnologyRemoved,
    CertificateChanged,
    ResponseTimeChange,
    ContentChanged,
    SecurityFindingAdded,
    SecurityFindingResolved,
    SiteDown,
    SiteUp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChangeSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeSet {
    pub scan_id: String,
    pub previous_scan_id: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub changes: Vec<ChangeEvent>,
}

impl ScanData {
    pub fn new(
        targets: Vec<String>,
        configuration: ScanConfiguration,
        results: Vec<HttpScanResult>,
    ) -> Self {
        let scan_id = Uuid::new_v4().to_string();
        let timestamp = Utc::now();
        
        let total_targets = targets.len();
        let successful_requests = results.iter().filter(|r| r.success).count();
        let failed_requests = total_targets - successful_requests;
        let total_detections = results
            .iter()
            .map(|r| r.technology_detections.len())
            .sum();
        let critical_findings = results
            .iter()
            .flat_map(|r| &r.content_findings)
            .filter(|f| matches!(f.severity, FindingSeverity::Critical))
            .count();
        let high_findings = results
            .iter()
            .flat_map(|r| &r.content_findings)
            .filter(|f| matches!(f.severity, FindingSeverity::High))
            .count();

        let configuration_hash = Self::hash_configuration(&configuration);
        
        let summary = ScanSummary {
            scan_id: scan_id.clone(),
            timestamp,
            total_targets,
            successful_requests,
            failed_requests,
            total_detections,
            critical_findings,
            high_findings,
            duration_seconds: 0.0, 
            tags: Vec::new(),
            configuration_hash,
        };

        Self {
            scan_id,
            timestamp,
            targets,
            configuration,
            results,
            summary,
        }
    }

    fn hash_configuration(config: &ScanConfiguration) -> String {
        use sha2::{Sha256, Digest};
        let config_bytes = bincode::serialize(config).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(&config_bytes);
        format!("{:x}", hasher.finalize())
    }

    pub fn set_duration(&mut self, duration_seconds: f64) {
        self.summary.duration_seconds = duration_seconds;
    }

    pub fn add_tags(&mut self, tags: Vec<String>) {
        self.summary.tags.extend(tags);
    }
}

impl HttpScanResult {
    pub fn new_successful(
        url: String,
        status_code: u16,
        response_time_ms: u64,
        content_length: Option<u64>,
        headers: HashMap<String, String>,
        title: Option<String>,
        server: Option<String>,
    ) -> Self {
        Self {
            url,
            timestamp: Utc::now(),
            status_code: Some(status_code),
            response_time_ms: Some(response_time_ms),
            content_length,
            headers,
            title,
            server,
            technology_detections: Vec::new(),
            content_findings: Vec::new(),
            tls_info: None,
            screenshot_path: None,
            error_message: None,
            success: true,
        }
    }

    pub fn new_failed(url: String, error_message: String) -> Self {
        Self {
            url,
            timestamp: Utc::now(),
            status_code: None,
            response_time_ms: None,
            content_length: None,
            headers: HashMap::new(),
            title: None,
            server: None,
            technology_detections: Vec::new(),
            content_findings: Vec::new(),
            tls_info: None,
            screenshot_path: None,
            error_message: Some(error_message),
            success: false,
        }
    }
}

impl ChangeEvent {
    pub fn new(
        url: String,
        change_type: ChangeType,
        field_name: String,
        old_value: Option<String>,
        new_value: Option<String>,
        severity: ChangeSeverity,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            url,
            timestamp: Utc::now(),
            change_type,
            old_value,
            new_value,
            field_name,
            severity,
        }
    }
}

impl std::fmt::Display for FindingSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Critical => write!(f, "Critical"),
            Self::High => write!(f, "High"),
            Self::Medium => write!(f, "Medium"),
            Self::Low => write!(f, "Low"),
            Self::Info => write!(f, "Info"),
        }
    }
}

impl std::fmt::Display for ChangeSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Critical => write!(f, "Critical"),
            Self::High => write!(f, "High"),
            Self::Medium => write!(f, "Medium"),
            Self::Low => write!(f, "Low"),
            Self::Info => write!(f, "Info"),
        }
    }
}

impl std::fmt::Display for ChangeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StatusCodeChanged => write!(f, "Status Code Changed"),
            Self::TechnologyAdded => write!(f, "Technology Added"),
            Self::TechnologyRemoved => write!(f, "Technology Removed"),
            Self::CertificateChanged => write!(f, "Certificate Changed"),
            Self::ResponseTimeChange => write!(f, "Response Time Changed"),
            Self::ContentChanged => write!(f, "Content Changed"),
            Self::SecurityFindingAdded => write!(f, "Security Finding Added"),
            Self::SecurityFindingResolved => write!(f, "Security Finding Resolved"),
            Self::SiteDown => write!(f, "Site Down"),
            Self::SiteUp => write!(f, "Site Up"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_data_creation() {
        let config = ScanConfiguration {
            timeout: 10,
            workers: 5,
            rate_limit: 10,
            http_enabled: true,
            https_enabled: true,
            detect_all: true,
            content_analysis: true,
            tls_analysis: true,
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
        let scan_data = ScanData::new(targets.clone(), config, results);

        assert!(!scan_data.scan_id.is_empty());
        assert_eq!(scan_data.targets, targets);
        assert_eq!(scan_data.summary.total_targets, 1);
        assert_eq!(scan_data.summary.successful_requests, 1);
        assert_eq!(scan_data.summary.failed_requests, 0);
    }

    #[test]
    fn test_serialization_roundtrip() {
        let config = ScanConfiguration {
            timeout: 10,
            workers: 5,
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

        let results = vec![HttpScanResult::new_failed(
            "https://example.com".to_string(),
            "Connection timeout".to_string(),
        )];

        let targets = vec!["https://example.com".to_string()];
        let original = ScanData::new(targets, config, results);

        let serialized = bincode::serialize(&original).unwrap();
        let deserialized: ScanData = bincode::deserialize(&serialized).unwrap();

        assert_eq!(original.scan_id, deserialized.scan_id);
        assert_eq!(original.targets, deserialized.targets);
        assert_eq!(original.results.len(), deserialized.results.len());
    }

    #[test]
    fn test_change_event_creation() {
        let change = ChangeEvent::new(
            "https://example.com".to_string(),
            ChangeType::StatusCodeChanged,
            "status_code".to_string(),
            Some("200".to_string()),
            Some("404".to_string()),
            ChangeSeverity::High,
        );

        assert!(!change.id.is_empty());
        assert_eq!(change.url, "https://example.com");
        assert_eq!(change.old_value, Some("200".to_string()));
        assert_eq!(change.new_value, Some("404".to_string()));
    }
}
