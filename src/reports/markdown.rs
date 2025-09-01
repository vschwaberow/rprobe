// File: markdown.rs
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023-2025
// - Volker Schwaberow <volker@schwaberow.de>

use anyhow::Result;

use super::{ReportConfig, ReportData, ReportGenerator};
use crate::content_analyzer::FindingSeverity;

pub struct MarkdownGenerator;

impl MarkdownGenerator {
    pub fn new() -> Self {
        Self
    }

    fn severity_badge(&self, severity: &FindingSeverity) -> &str {
        match severity {
            FindingSeverity::Critical => {
                "![Critical](https://img.shields.io/badge/CRITICAL-red?style=flat-square)"
            }
            FindingSeverity::High => {
                "![High](https://img.shields.io/badge/HIGH-orange?style=flat-square)"
            }
            FindingSeverity::Medium => {
                "![Medium](https://img.shields.io/badge/MEDIUM-yellow?style=flat-square)"
            }
            FindingSeverity::Low => {
                "![Low](https://img.shields.io/badge/LOW-blue?style=flat-square)"
            }
            FindingSeverity::Info => {
                "![Info](https://img.shields.io/badge/INFO-lightgrey?style=flat-square)"
            }
        }
    }

    fn escape_markdown(&self, text: &str) -> String {
        text.replace("|", "\\|")
            .replace("*", "\\*")
            .replace("_", "\\_")
            .replace("`", "\\`")
            .replace("#", "\\#")
            .replace("[", "\\[")
            .replace("]", "\\]")
    }
}

impl ReportGenerator for MarkdownGenerator {
    fn generate(&self, data: &ReportData, _config: &ReportConfig) -> Result<String> {
        let mut md = String::new();

        md.push_str(&format!("# {}\n\n", data.title));

        md.push_str(&format!(
            "**Generated:** {} | **Tool:** rprobe v{}\n\n",
            data.generated_at.format("%Y-%m-%d %H:%M:%S UTC"),
            env!("CARGO_PKG_VERSION")
        ));

        md.push_str("---\n\n");

        md.push_str("## Executive Summary\n\n");

        md.push_str("| Metric | Value |\n");
        md.push_str("|--------|-------|\n");
        md.push_str(&format!("| Total Scans | {} |\n", data.summary.total_scans));
        md.push_str(&format!(
            "| Successful Scans | {} |\n",
            data.summary.successful_scans
        ));
        md.push_str(&format!(
            "| Failed Scans | {} |\n",
            data.summary.failed_scans
        ));
        md.push_str(&format!("| Unique URLs | {} |\n", data.summary.unique_urls));
        md.push_str(&format!(
            "| Total Detections | {} |\n",
            data.summary.total_detections
        ));

        if let Some((start, end)) = data.summary.date_range {
            md.push_str(&format!(
                "| Scan Period | {} to {} |\n",
                start.format("%Y-%m-%d"),
                end.format("%Y-%m-%d")
            ));
        }

        md.push('\n');

        let security = &data.summary.security_findings;
        md.push_str("## Security Analysis\n\n");

        if security.total_findings == 0 {
            md.push_str("✅ **No security issues identified**\n\n");
        } else {
            md.push_str("### Findings Summary\n\n");
            md.push_str("| Severity | Count |\n");
            md.push_str("|----------|-------|\n");
            md.push_str(&format!(
                "| {} Critical | {} |\n",
                self.severity_badge(&FindingSeverity::Critical),
                security.critical_count
            ));
            md.push_str(&format!(
                "| {} High | {} |\n",
                self.severity_badge(&FindingSeverity::High),
                security.high_count
            ));
            md.push_str(&format!(
                "| {} Medium | {} |\n",
                self.severity_badge(&FindingSeverity::Medium),
                security.medium_count
            ));
            md.push_str(&format!(
                "| {} Low | {} |\n",
                self.severity_badge(&FindingSeverity::Low),
                security.low_count
            ));
            md.push_str(&format!(
                "| {} Info | {} |\n",
                self.severity_badge(&FindingSeverity::Info),
                security.info_count
            ));

            md.push_str(&format!(
                "\n**Total:** {} findings across {} URLs\n\n",
                security.total_findings, security.affected_urls
            ));

            if !security.categories.is_empty() {
                md.push_str("### Finding Categories\n\n");
                let mut categories: Vec<_> = security.categories.iter().collect();
                categories.sort_by(|a, b| b.1.cmp(a.1));

                for (category, count) in categories.iter().take(10) {
                    let percentage =
                        (**count as f32 / security.total_findings as f32 * 100.0) as u8;
                    md.push_str(&format!(
                        "- **{}:** {} occurrences ({}%)\n",
                        self.escape_markdown(category),
                        count,
                        percentage
                    ));
                }
                md.push('\n');
            }
        }

        let tls = &data.summary.tls_summary;
        if tls.total_tls_scans > 0 {
            md.push_str("## TLS Certificate Analysis\n\n");

            md.push_str("| Metric | Value |\n");
            md.push_str("|--------|-------|\n");
            md.push_str(&format!(
                "| Certificates Analyzed | {} |\n",
                tls.total_tls_scans
            ));
            md.push_str(&format!(
                "| Certificates with Warnings | {} |\n",
                tls.certificates_with_warnings
            ));
            md.push_str(&format!(
                "| Certificates with Errors | {} |\n",
                tls.certificates_with_errors
            ));

            if !tls.expiring_soon.is_empty() {
                md.push_str("\n### ⚠️ Certificates Expiring Soon\n\n");
                md.push_str("| URL | Days Until Expiry | Subject |\n");
                md.push_str("|-----|-------------------|----------|\n");

                for cert in &tls.expiring_soon {
                    let urgency = if cert.days_until_expiry <= 7 {
                        "🔴"
                    } else if cert.days_until_expiry <= 14 {
                        "🟡"
                    } else {
                        "🟢"
                    };

                    md.push_str(&format!(
                        "| {} {} | {} {} | {} |\n",
                        urgency,
                        self.escape_markdown(&cert.url),
                        cert.days_until_expiry,
                        urgency,
                        self.escape_markdown(&cert.subject)
                    ));
                }
                md.push('\n');
            }

            if !tls.common_issues.is_empty() {
                md.push_str("### Common TLS Issues\n\n");
                let mut issues: Vec<_> = tls.common_issues.iter().collect();
                issues.sort_by(|a, b| b.1.cmp(a.1));

                for (issue, count) in issues.iter().take(5) {
                    md.push_str(&format!(
                        "- **{}:** {} occurrences\n",
                        self.escape_markdown(issue),
                        count
                    ));
                }
                md.push('\n');
            }
        }

        if !data.summary.unique_technologies.is_empty() {
            md.push_str("## Technology Detection\n\n");
            md.push_str(&format!(
                "**{} unique technologies detected:**\n\n",
                data.summary.unique_technologies.len()
            ));

            for tech in &data.summary.unique_technologies {
                md.push_str(&format!("- {}\n", self.escape_markdown(tech)));
            }
            md.push('\n');
        }

        md.push_str("## Status Code Distribution\n\n");
        let mut status_codes: Vec<_> = data.summary.status_distribution.iter().collect();
        status_codes.sort_by(|a, b| b.1.cmp(a.1));

        md.push_str("| Status Code | Count | Description |\n");
        md.push_str("|-------------|-------|-------------|\n");

        for (status, count) in status_codes {
            let description = match status.as_str() {
                "0" | "Failed" => "Failed/Timeout",
                s if s.starts_with("2") => "Success",
                s if s.starts_with("3") => "Redirect",
                s if s.starts_with("4") => "Client Error",
                s if s.starts_with("5") => "Server Error",
                _ => "Other",
            };

            let status_emoji = match status.as_str() {
                "0" | "Failed" => "❌",
                s if s.starts_with("2") => "✅",
                s if s.starts_with("3") => "↩️",
                s if s.starts_with("4") => "⚠️",
                s if s.starts_with("5") => "🚨",
                _ => "❓",
            };

            md.push_str(&format!(
                "| {} {} | {} | {} |\n",
                status_emoji, status, count, description
            ));
        }

        md.push_str("\n---\n\n");

        md.push_str("## Detailed Scan Results\n\n");

        for scan in &data.scans {
            md.push_str(&format!("### {}\n\n", self.escape_markdown(&scan.url)));

            let status_emoji = if scan.status == "0" || scan.status == "Failed" {
                "❌"
            } else if scan.status.starts_with("2") {
                "✅"
            } else if scan.status.starts_with("3") {
                "↩️"
            } else if scan.status.starts_with("4") {
                "⚠️"
            } else if scan.status.starts_with("5") {
                "🚨"
            } else {
                "❓"
            };

            md.push_str(&format!("**Status:** {} {}\n\n", status_emoji, scan.status));
            md.push_str(&format!(
                "**Timestamp:** {}\n\n",
                scan.timestamp.format("%Y-%m-%d %H:%M:%S UTC")
            ));

            if let Some(response_time) = scan.response_time_ms {
                md.push_str(&format!("**Response Time:** {}ms\n\n", response_time));
            }

            if !scan.detections.is_empty() {
                md.push_str("#### 🔍 Technologies Detected\n\n");
                for detection in &scan.detections {
                    md.push_str(&format!("- {}\n", self.escape_markdown(detection)));
                }
                md.push('\n');
            }

            if !scan.content_findings.is_empty() {
                md.push_str("#### 🛡️ Security Findings\n\n");
                for finding in &scan.content_findings {
                    md.push_str(&format!(
                        "**{}** {} **{}**\n\n",
                        self.severity_badge(&finding.severity),
                        self.escape_markdown(&finding.category),
                        self.escape_markdown(&finding.description)
                    ));

                    if let Some(ref matched) = finding.matched_text {
                        md.push_str(&format!("```\n{}\n```\n\n", matched));
                    }

                    if let Some(ref context) = finding.context {
                        md.push_str(&format!("*Context:* {}\n\n", self.escape_markdown(context)));
                    }
                }
            }

            if !scan.tls_info.is_empty() {
                md.push_str("#### 🔒 TLS Information\n\n");

                if let Some(subject) = scan.tls_info.get("subject") {
                    md.push_str(&format!(
                        "**Subject:** {}\n\n",
                        self.escape_markdown(subject)
                    ));
                }

                if let Some(issuer) = scan.tls_info.get("issuer") {
                    md.push_str(&format!("**Issuer:** {}\n\n", self.escape_markdown(issuer)));
                }

                if let Some(valid_to) = scan.tls_info.get("valid_to") {
                    md.push_str(&format!(
                        "**Valid Until:** {}\n\n",
                        self.escape_markdown(valid_to)
                    ));
                }

                if let Some(days) = scan.tls_info.get("days_until_expiry") {
                    let days_num: i32 = days.parse().unwrap_or(0);
                    let urgency = if days_num <= 7 {
                        "🔴 **URGENT**"
                    } else if days_num <= 30 {
                        "🟡 **WARNING**"
                    } else {
                        "🟢"
                    };
                    md.push_str(&format!(
                        "**Days Until Expiry:** {} {} days\n\n",
                        urgency, days
                    ));
                }

                if let Some(warnings) = scan.tls_info.get("warnings") {
                    md.push_str(&format!(
                        "⚠️ **Warnings:** {}\n\n",
                        self.escape_markdown(warnings)
                    ));
                }

                if let Some(errors) = scan.tls_info.get("errors") {
                    md.push_str(&format!(
                        "🚨 **Errors:** {}\n\n",
                        self.escape_markdown(errors)
                    ));
                }
            }

            md.push_str("---\n\n");
        }

        md.push_str(&format!(
            "*Report generated by rprobe v{} on {}*\n",
            env!("CARGO_PKG_VERSION"),
            data.generated_at.format("%Y-%m-%d %H:%M:%S UTC")
        ));

        Ok(md)
    }

    fn file_extension(&self) -> &'static str {
        "md"
    }

    fn content_type(&self) -> &'static str {
        "text/markdown"
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
    fn test_markdown_generation() {
        let generator = MarkdownGenerator::new();
        let engine = ReportEngine::new();
        let data = engine.create_report_data(vec![create_test_scan()]);
        let config = super::ReportConfig::default();

        let result = generator.generate(&data, &config);
        assert!(result.is_ok());

        let md = result.unwrap();
        assert!(md.contains("# rprobe Security Scan Report"));
        assert!(md.contains("## Executive Summary"));
        assert!(md.contains("### https://example.com"));
        assert!(md.contains("**Status:** ✅ 200"));
    }
}
