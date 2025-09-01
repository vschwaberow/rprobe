// File: text.rs
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023-2025
// - Volker Schwaberow <volker@schwaberow.de>

use anyhow::Result;

use super::{ReportConfig, ReportData, ReportGenerator};
use crate::content_analyzer::FindingSeverity;

pub struct TextGenerator;

impl TextGenerator {
    pub fn new() -> Self {
        Self
    }

    fn format_severity(&self, severity: &FindingSeverity) -> &str {
        match severity {
            FindingSeverity::Critical => "[CRITICAL]",
            FindingSeverity::High => "[HIGH]    ",
            FindingSeverity::Medium => "[MEDIUM]  ",
            FindingSeverity::Low => "[LOW]     ",
            FindingSeverity::Info => "[INFO]    ",
        }
    }
}

impl ReportGenerator for TextGenerator {
    fn generate(&self, data: &ReportData, _config: &ReportConfig) -> Result<String> {
        let mut output = String::new();

        output.push_str(
            "===============================================================================\n",
        );
        output.push_str(&format!(
            "                          {}\n",
            data.title.to_uppercase()
        ));
        output.push_str(
            "===============================================================================\n",
        );
        output.push_str(&format!(
            "Generated: {}\n",
            data.generated_at.format("%Y-%m-%d %H:%M:%S UTC")
        ));
        output.push_str(&format!("Tool: rprobe v{}\n", env!("CARGO_PKG_VERSION")));
        output.push_str(
            "===============================================================================\n\n",
        );

        output.push_str("EXECUTIVE SUMMARY\n");
        output.push_str("-----------------\n");
        output.push_str(&format!(
            "Total Scans:          {}\n",
            data.summary.total_scans
        ));
        output.push_str(&format!(
            "Successful Scans:     {}\n",
            data.summary.successful_scans
        ));
        output.push_str(&format!(
            "Failed Scans:         {}\n",
            data.summary.failed_scans
        ));
        output.push_str(&format!(
            "Unique URLs:          {}\n",
            data.summary.unique_urls
        ));
        output.push_str(&format!(
            "Total Detections:     {}\n",
            data.summary.total_detections
        ));

        if let Some((start, end)) = data.summary.date_range {
            output.push_str(&format!(
                "Scan Period:          {} to {}\n",
                start.format("%Y-%m-%d"),
                end.format("%Y-%m-%d")
            ));
        }

        output.push_str("\nSECURITY ANALYSIS\n");
        output.push_str("-----------------\n");
        let security = &data.summary.security_findings;

        if security.total_findings == 0 {
            output.push_str("✓ No security issues identified\n");
        } else {
            output.push_str(&format!(
                "Total Security Findings:  {}\n",
                security.total_findings
            ));
            output.push_str(&format!(
                "  Critical Issues:        {}\n",
                security.critical_count
            ));
            output.push_str(&format!(
                "  High Risk Issues:       {}\n",
                security.high_count
            ));
            output.push_str(&format!(
                "  Medium Risk Issues:     {}\n",
                security.medium_count
            ));
            output.push_str(&format!(
                "  Low Risk Issues:        {}\n",
                security.low_count
            ));
            output.push_str(&format!(
                "  Informational:          {}\n",
                security.info_count
            ));
            output.push_str(&format!(
                "Affected URLs:            {}\n",
                security.affected_urls
            ));

            if !security.categories.is_empty() {
                output.push_str("\nFinding Categories:\n");
                let mut categories: Vec<_> = security.categories.iter().collect();
                categories.sort_by(|a, b| b.1.cmp(a.1));
                for (category, count) in categories.iter().take(10) {
                    output.push_str(&format!("  {:<25} {}\n", category, count));
                }
            }
        }

        let tls = &data.summary.tls_summary;
        if tls.total_tls_scans > 0 {
            output.push_str("\nTLS CERTIFICATE ANALYSIS\n");
            output.push_str("------------------------\n");
            output.push_str(&format!(
                "Certificates Analyzed:    {}\n",
                tls.total_tls_scans
            ));
            output.push_str(&format!(
                "Certificates w/ Warnings: {}\n",
                tls.certificates_with_warnings
            ));
            output.push_str(&format!(
                "Certificates w/ Errors:   {}\n",
                tls.certificates_with_errors
            ));

            if !tls.expiring_soon.is_empty() {
                output.push_str("\nCertificates Expiring Soon:\n");
                for cert in &tls.expiring_soon {
                    output.push_str(&format!(
                        "  {} (expires in {} days)\n",
                        cert.url, cert.days_until_expiry
                    ));
                }
            }

            if !tls.common_issues.is_empty() {
                output.push_str("\nCommon TLS Issues:\n");
                let mut issues: Vec<_> = tls.common_issues.iter().collect();
                issues.sort_by(|a, b| b.1.cmp(a.1));
                for (issue, count) in issues.iter().take(5) {
                    output.push_str(&format!("  {:<35} {}\n", issue, count));
                }
            }
        }

        if !data.summary.unique_technologies.is_empty() {
            output.push_str("\nTECHNOLOGY DETECTION\n");
            output.push_str("-------------------\n");
            output.push_str(&format!(
                "Technologies Detected: {}\n",
                data.summary.unique_technologies.len()
            ));

            let mut tech_line = String::new();
            for (i, tech) in data.summary.unique_technologies.iter().enumerate() {
                if i > 0 {
                    tech_line.push_str(", ");
                }
                tech_line.push_str(tech);

                if tech_line.len() > 70 {
                    output.push_str(&format!("  {}\n", tech_line));
                    tech_line.clear();
                }
            }
            if !tech_line.is_empty() {
                output.push_str(&format!("  {}\n", tech_line));
            }
        }

        output.push_str("\nSTATUS CODE DISTRIBUTION\n");
        output.push_str("------------------------\n");
        let mut status_codes: Vec<_> = data.summary.status_distribution.iter().collect();
        status_codes.sort_by(|a, b| b.1.cmp(a.1));
        for (status, count) in status_codes {
            let status_name = match status.as_str() {
                "0" | "Failed" => "Failed/Timeout",
                s if s.starts_with("2") => "Success (2xx)",
                s if s.starts_with("3") => "Redirect (3xx)",
                s if s.starts_with("4") => "Client Error (4xx)",
                s if s.starts_with("5") => "Server Error (5xx)",
                _ => "Other",
            };
            output.push_str(&format!("  {:15} {:>6}\n", status_name, count));
        }

        output.push('\n');
        output.push_str(
            "===============================================================================\n",
        );
        output.push_str("DETAILED SCAN RESULTS\n");
        output.push_str(
            "===============================================================================\n\n",
        );

        for (i, scan) in data.scans.iter().enumerate() {
            output.push_str(&format!("{}. {}\n", i + 1, scan.url));
            output.push_str(&format!("   Status: {}\n", scan.status));
            output.push_str(&format!(
                "   Timestamp: {}\n",
                scan.timestamp.format("%Y-%m-%d %H:%M:%S UTC")
            ));

            if let Some(response_time) = scan.response_time_ms {
                output.push_str(&format!("   Response Time: {}ms\n", response_time));
            }

            if !scan.detections.is_empty() {
                output.push_str("   Technologies:\n");
                for detection in &scan.detections {
                    output.push_str(&format!("     - {}\n", detection));
                }
            }

            if !scan.content_findings.is_empty() {
                output.push_str("   Security Findings:\n");
                for finding in &scan.content_findings {
                    output.push_str(&format!(
                        "     {} {}: {}\n",
                        self.format_severity(&finding.severity),
                        finding.category,
                        finding.description
                    ));
                    if let Some(ref matched) = finding.matched_text {
                        output.push_str(&format!("       Matched: {}\n", matched));
                    }
                }
            }

            if !scan.tls_info.is_empty() {
                output.push_str("   TLS Information:\n");
                for (key, value) in &scan.tls_info {
                    if key == "subject"
                        || key == "issuer"
                        || key == "valid_to"
                        || key == "days_until_expiry"
                    {
                        output.push_str(&format!(
                            "     {}: {}\n",
                            key.replace("_", " ").to_uppercase(),
                            value
                        ));
                    }
                }

                if let Some(warnings) = scan.tls_info.get("warnings") {
                    output.push_str(&format!("     WARNINGS: {}\n", warnings));
                }

                if let Some(errors) = scan.tls_info.get("errors") {
                    output.push_str(&format!("     ERRORS: {}\n", errors));
                }
            }

            output.push('\n');
        }

        output.push_str(
            "===============================================================================\n",
        );
        output.push_str("End of Report\n");
        output.push_str(
            "===============================================================================\n",
        );

        Ok(output)
    }

    fn file_extension(&self) -> &'static str {
        "txt"
    }

    fn content_type(&self) -> &'static str {
        "text/plain"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reports::ReportEngine;
    use crate::storage::ScanRecord;
    use std::collections::HashMap;
    use uuid::Uuid;

    fn create_test_scan() -> ScanRecord {
        ScanRecord {
            id: Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now(),
            url: "https://example.com".to_string(),
            status: "200".to_string(),
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
    fn test_text_generation() {
        let generator = TextGenerator::new();
        let engine = ReportEngine::new();
        let data = engine.create_report_data(vec![create_test_scan()]);
        let config = super::ReportConfig::default();

        let result = generator.generate(&data, &config);
        assert!(result.is_ok());

        let text = result.unwrap();
        assert!(text.contains("RPROBE SECURITY SCAN REPORT"));
        assert!(text.contains("EXECUTIVE SUMMARY"));
        assert!(text.contains("https://example.com"));
        assert!(text.contains("Status: 200"));
    }
}
