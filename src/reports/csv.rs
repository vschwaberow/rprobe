// File: csv.rs
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023-2025
// - Volker Schwaberow <volker@schwaberow.de>

use anyhow::Result;

use super::{ReportConfig, ReportData, ReportGenerator};

pub struct CsvGenerator;

impl CsvGenerator {
    pub fn new() -> Self {
        Self
    }

    fn escape_csv(&self, field: &str) -> String {
        if field.contains(',') || field.contains('"') || field.contains('\n') {
            format!("\"{}\"", field.replace("\"", "\"\""))
        } else {
            field.to_string()
        }
    }
}

impl ReportGenerator for CsvGenerator {
    fn generate(&self, data: &ReportData, _config: &ReportConfig) -> Result<String> {
        let mut csv = String::new();

        csv.push_str("URL,Status,Timestamp,Response_Time_MS,Content_Length,Technologies,");
        csv.push_str(
            "Security_Findings_Count,Critical_Count,High_Count,Medium_Count,Low_Count,Info_Count,",
        );
        csv.push_str(
            "TLS_Subject,TLS_Issuer,TLS_Valid_To,TLS_Days_Until_Expiry,TLS_Warnings,TLS_Errors\n",
        );

        for scan in &data.scans {
            let technologies = scan.detections.join("; ");

            let security_counts =
                scan.content_findings
                    .iter()
                    .fold((0, 0, 0, 0, 0), |acc, finding| match finding.severity {
                        crate::content_analyzer::FindingSeverity::Critical => {
                            (acc.0 + 1, acc.1, acc.2, acc.3, acc.4)
                        }
                        crate::content_analyzer::FindingSeverity::High => {
                            (acc.0, acc.1 + 1, acc.2, acc.3, acc.4)
                        }
                        crate::content_analyzer::FindingSeverity::Medium => {
                            (acc.0, acc.1, acc.2 + 1, acc.3, acc.4)
                        }
                        crate::content_analyzer::FindingSeverity::Low => {
                            (acc.0, acc.1, acc.2, acc.3 + 1, acc.4)
                        }
                        crate::content_analyzer::FindingSeverity::Info => {
                            (acc.0, acc.1, acc.2, acc.3, acc.4 + 1)
                        }
                    });

            let empty_string = String::new();
            let tls_subject = scan.tls_info.get("subject").unwrap_or(&empty_string);
            let tls_issuer = scan.tls_info.get("issuer").unwrap_or(&empty_string);
            let tls_valid_to = scan.tls_info.get("valid_to").unwrap_or(&empty_string);
            let tls_days_until_expiry = scan
                .tls_info
                .get("days_until_expiry")
                .unwrap_or(&empty_string);
            let tls_warnings = scan.tls_info.get("warnings").unwrap_or(&empty_string);
            let tls_errors = scan.tls_info.get("errors").unwrap_or(&empty_string);

            csv.push_str(&format!(
                "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
                self.escape_csv(&scan.url),
                self.escape_csv(&scan.status),
                scan.timestamp.format("%Y-%m-%d %H:%M:%S"),
                scan.response_time_ms.unwrap_or(0),
                scan.content_length.unwrap_or(0),
                self.escape_csv(&technologies),
                scan.content_findings.len(),
                security_counts.0,
                security_counts.1,
                security_counts.2,
                security_counts.3,
                security_counts.4,
                self.escape_csv(tls_subject),
                self.escape_csv(tls_issuer),
                self.escape_csv(tls_valid_to),
                self.escape_csv(tls_days_until_expiry),
                self.escape_csv(tls_warnings),
                self.escape_csv(tls_errors),
            ));
        }

        Ok(csv)
    }

    fn file_extension(&self) -> &'static str {
        "csv"
    }

    fn content_type(&self) -> &'static str {
        "text/csv"
    }
}
