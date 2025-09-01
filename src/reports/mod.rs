// File: mod.rs
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023-2025
// - Volker Schwaberow <volker@schwaberow.de>

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

use crate::content_analyzer::{ContentFinding, FindingSeverity};
use crate::storage::ScanRecord;

pub mod csv;
pub mod html;
pub mod json;
pub mod markdown;
pub mod text;
pub mod xml;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportData {
    pub generated_at: DateTime<Utc>,
    pub title: String,
    pub description: Option<String>,
    pub scans: Vec<ScanRecord>,
    pub summary: ReportSummary,
    pub aggregations: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSummary {
    pub total_scans: usize,
    pub successful_scans: usize,
    pub failed_scans: usize,
    pub unique_urls: usize,
    pub date_range: Option<(DateTime<Utc>, DateTime<Utc>)>,
    pub total_detections: usize,
    pub unique_technologies: Vec<String>,
    pub security_findings: SecuritySummary,
    pub tls_summary: TlsSummary,
    pub status_distribution: HashMap<String, usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecuritySummary {
    pub total_findings: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub info_count: usize,
    pub categories: HashMap<String, usize>,
    pub affected_urls: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsSummary {
    pub total_tls_scans: usize,
    pub certificates_with_warnings: usize,
    pub certificates_with_errors: usize,
    pub expiring_soon: Vec<TlsExpirationInfo>,
    pub common_issues: HashMap<String, usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsExpirationInfo {
    pub url: String,
    pub days_until_expiry: i64,
    pub subject: String,
}

#[derive(Debug, Clone)]
pub struct ReportConfig {
    pub theme: Theme,
    pub include_raw_data: bool,
    pub aggregate_duplicates: bool,
    pub sort_by: SortBy,
    pub group_by: Option<GroupBy>,
    pub filters: ReportFilters,
}

#[derive(Debug, Clone)]
pub enum Theme {
    Light,
    Dark,
    Auto,
}

#[derive(Debug, Clone)]
pub enum SortBy {
    Timestamp,
    Url,
    Status,
    Severity,
    Detections,
}

#[derive(Debug, Clone)]
pub enum GroupBy {
    Url,
    Status,
    Date,
    Technology,
    Severity,
}

#[derive(Debug, Clone, Default)]
pub struct ReportFilters {
    pub min_severity: Option<FindingSeverity>,
    pub status_codes: Option<Vec<String>>,
    pub technologies: Option<Vec<String>>,
    pub date_range: Option<(DateTime<Utc>, DateTime<Utc>)>,
    pub has_security_issues: Option<bool>,
    pub has_tls_issues: Option<bool>,
}

pub trait ReportGenerator {
    fn generate(&self, data: &ReportData, config: &ReportConfig) -> Result<String>;
    fn file_extension(&self) -> &'static str;
    fn content_type(&self) -> &'static str;
    fn supports_themes(&self) -> bool {
        false
    }
    fn supports_interactive(&self) -> bool {
        false
    }
}

pub struct ReportEngine;

impl ReportEngine {
    pub fn new() -> Self {
        Self
    }

    pub fn generate_report<P: AsRef<Path>>(
        &self,
        format: &str,
        data: &ReportData,
        config: &ReportConfig,
        output_path: Option<P>,
    ) -> Result<String> {
        let generator = self.get_generator(format)?;
        let content = generator.generate(data, config)?;

        if let Some(path) = output_path {
            std::fs::write(path, &content)?;
        }

        Ok(content)
    }

    pub fn create_report_data(&self, scans: Vec<ScanRecord>) -> ReportData {
        let summary = self.calculate_summary(&scans);
        let aggregations = self.calculate_aggregations(&scans);

        ReportData {
            generated_at: Utc::now(),
            title: "rprobe Security Scan Report".to_string(),
            description: None,
            scans,
            summary,
            aggregations,
        }
    }

    fn get_generator(&self, format: &str) -> Result<Box<dyn ReportGenerator>> {
        match format.to_lowercase().as_str() {
            "html" => Ok(Box::new(html::HtmlGenerator::new())),
            "json" => Ok(Box::new(json::JsonGenerator::new())),
            "xml" => Ok(Box::new(xml::XmlGenerator::new())),
            "text" | "txt" => Ok(Box::new(text::TextGenerator::new())),
            "markdown" | "md" => Ok(Box::new(markdown::MarkdownGenerator::new())),
            "csv" => Ok(Box::new(csv::CsvGenerator::new())),
            _ => Err(anyhow::anyhow!("Unsupported report format: {}", format)),
        }
    }

    fn calculate_summary(&self, scans: &[ScanRecord]) -> ReportSummary {
        let total_scans = scans.len();
        let successful_scans = scans
            .iter()
            .filter(|s| s.status != "Failed" && s.status != "0")
            .count();
        let failed_scans = total_scans - successful_scans;

        let unique_urls = scans
            .iter()
            .map(|s| s.url.as_str())
            .collect::<std::collections::HashSet<_>>()
            .len();

        let date_range = if !scans.is_empty() {
            let min_date = scans.iter().map(|s| s.timestamp).min().unwrap();
            let max_date = scans.iter().map(|s| s.timestamp).max().unwrap();
            Some((min_date, max_date))
        } else {
            None
        };

        let unique_technologies = scans
            .iter()
            .flat_map(|s| &s.detections)
            .map(|d| {
                if let Some((name, _)) = d.split_once(": ") {
                    name.to_string()
                } else {
                    d.clone()
                }
            })
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();

        let total_detections = scans.iter().map(|s| s.detections.len()).sum();

        let security_findings = self.calculate_security_summary(scans);
        let tls_summary = self.calculate_tls_summary(scans);

        let mut status_distribution = HashMap::new();
        for scan in scans {
            *status_distribution.entry(scan.status.clone()).or_insert(0) += 1;
        }

        ReportSummary {
            total_scans,
            successful_scans,
            failed_scans,
            unique_urls,
            date_range,
            total_detections,
            unique_technologies,
            security_findings,
            tls_summary,
            status_distribution,
        }
    }

    fn calculate_security_summary(&self, scans: &[ScanRecord]) -> SecuritySummary {
        let all_findings: Vec<&ContentFinding> =
            scans.iter().flat_map(|s| &s.content_findings).collect();

        let total_findings = all_findings.len();
        let critical_count = all_findings
            .iter()
            .filter(|f| f.severity == FindingSeverity::Critical)
            .count();
        let high_count = all_findings
            .iter()
            .filter(|f| f.severity == FindingSeverity::High)
            .count();
        let medium_count = all_findings
            .iter()
            .filter(|f| f.severity == FindingSeverity::Medium)
            .count();
        let low_count = all_findings
            .iter()
            .filter(|f| f.severity == FindingSeverity::Low)
            .count();
        let info_count = all_findings
            .iter()
            .filter(|f| f.severity == FindingSeverity::Info)
            .count();

        let mut categories = HashMap::new();
        for finding in &all_findings {
            *categories.entry(finding.category.clone()).or_insert(0) += 1;
        }

        let affected_urls = scans
            .iter()
            .filter(|s| !s.content_findings.is_empty())
            .count();

        SecuritySummary {
            total_findings,
            critical_count,
            high_count,
            medium_count,
            low_count,
            info_count,
            categories,
            affected_urls,
        }
    }

    fn calculate_tls_summary(&self, scans: &[ScanRecord]) -> TlsSummary {
        let tls_scans: Vec<&ScanRecord> = scans.iter().filter(|s| !s.tls_info.is_empty()).collect();

        let total_tls_scans = tls_scans.len();

        let certificates_with_warnings = tls_scans
            .iter()
            .filter(|s| s.tls_info.contains_key("warnings"))
            .count();

        let certificates_with_errors = tls_scans
            .iter()
            .filter(|s| s.tls_info.contains_key("errors"))
            .count();

        let mut expiring_soon = Vec::new();
        for scan in &tls_scans {
            if let Some(days_str) = scan.tls_info.get("days_until_expiry") {
                if let Ok(days) = days_str.parse::<i64>() {
                    if (0..=30).contains(&days) {
                        expiring_soon.push(TlsExpirationInfo {
                            url: scan.url.clone(),
                            days_until_expiry: days,
                            subject: scan.tls_info.get("subject").unwrap_or(&scan.url).clone(),
                        });
                    }
                }
            }
        }

        expiring_soon.sort_by_key(|info| info.days_until_expiry);

        let mut common_issues = HashMap::new();
        for scan in &tls_scans {
            if let Some(warnings) = scan.tls_info.get("warnings") {
                for warning in warnings.split(", ") {
                    *common_issues.entry(warning.to_string()).or_insert(0) += 1;
                }
            }
            if let Some(errors) = scan.tls_info.get("errors") {
                for error in errors.split(", ") {
                    *common_issues.entry(error.to_string()).or_insert(0) += 1;
                }
            }
        }

        TlsSummary {
            total_tls_scans,
            certificates_with_warnings,
            certificates_with_errors,
            expiring_soon,
            common_issues,
        }
    }

    fn calculate_aggregations(&self, scans: &[ScanRecord]) -> HashMap<String, serde_json::Value> {
        let mut aggregations = HashMap::new();

        let technology_counts: HashMap<String, usize> = scans
            .iter()
            .flat_map(|s| &s.detections)
            .fold(HashMap::new(), |mut acc, detection| {
                let tech_name = if let Some((name, _)) = detection.split_once(": ") {
                    name.to_string()
                } else {
                    detection.clone()
                };
                *acc.entry(tech_name).or_insert(0) += 1;
                acc
            });

        aggregations.insert(
            "technology_distribution".to_string(),
            serde_json::to_value(technology_counts).unwrap_or_default(),
        );

        let daily_scan_counts: HashMap<String, usize> =
            scans.iter().fold(HashMap::new(), |mut acc, scan| {
                let date = scan.timestamp.format("%Y-%m-%d").to_string();
                *acc.entry(date).or_insert(0) += 1;
                acc
            });

        aggregations.insert(
            "daily_scan_distribution".to_string(),
            serde_json::to_value(daily_scan_counts).unwrap_or_default(),
        );

        aggregations
    }
}

impl Default for ReportConfig {
    fn default() -> Self {
        Self {
            theme: Theme::Light,
            include_raw_data: false,
            aggregate_duplicates: true,
            sort_by: SortBy::Timestamp,
            group_by: None,
            filters: ReportFilters::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn create_test_scan(url: &str, status: &str) -> ScanRecord {
        ScanRecord {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            url: url.to_string(),
            status: status.to_string(),
            detections: vec!["Nginx: Web Server".to_string()],
            content_findings: vec![],
            tls_info: HashMap::new(),
            response_time_ms: Some(150),
            response_headers: HashMap::new(),
            content_length: Some(1024),
            desync_results: vec![],
            screenshot_path: None,
            robots_txt_content: None,
            scan_config: crate::storage::ScanConfig {
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
    fn test_report_engine_creation() {
        let engine = ReportEngine::new();
        let scans = vec![
            create_test_scan("https://example.com", "200"),
            create_test_scan("https://test.com", "404"),
        ];

        let report_data = engine.create_report_data(scans);
        assert_eq!(report_data.summary.total_scans, 2);
        assert_eq!(report_data.summary.successful_scans, 1);
        assert_eq!(report_data.summary.failed_scans, 1);
    }

    #[test]
    fn test_security_summary_calculation() {
        let engine = ReportEngine::new();
        let mut scan = create_test_scan("https://example.com", "200");

        scan.content_findings = vec![ContentFinding {
            category: "Passwords".to_string(),
            description: "Potential password found".to_string(),
            severity: FindingSeverity::Critical,
            matched_text: Some("password123".to_string()),
            context: None,
        }];

        let report_data = engine.create_report_data(vec![scan]);
        assert_eq!(report_data.summary.security_findings.critical_count, 1);
        assert_eq!(report_data.summary.security_findings.total_findings, 1);
    }
}
