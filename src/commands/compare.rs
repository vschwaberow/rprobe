// File: compare.rs
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023-2025
// - Volker Schwaberow <volker@schwaberow.de>

use anyhow::Result;
use colored::*;
use std::path::PathBuf;

use super::{print_error, print_info, print_success, print_warning};
use crate::cli::CompareArgs;
use crate::storage::{ComparisonResult, HistoryDatabase, ScanRecord};

pub async fn execute(args: &CompareArgs, db: &HistoryDatabase) -> Result<()> {
    let old_date = args.parse_old_date().ok_or_else(|| {
        anyhow::anyhow!("Invalid old date format. Use YYYY-MM-DD or YYYY-MM-DD HH:MM:SS")
    })?;

    let new_date = args.parse_new_date().ok_or_else(|| {
        anyhow::anyhow!("Invalid new date format. Use YYYY-MM-DD or YYYY-MM-DD HH:MM:SS")
    })?;

    print_info(&format!("Comparing scans for {}", args.url));
    print_info(&format!(
        "Old scan: {}",
        old_date.format("%Y-%m-%d %H:%M:%S UTC")
    ));
    print_info(&format!(
        "New scan: {}",
        new_date.format("%Y-%m-%d %H:%M:%S UTC")
    ));

    let comparison = db.compare_scans(&args.url, old_date, new_date)?;

    match args.format.to_lowercase().as_str() {
        "table" => display_comparison_table(&comparison, args.detailed),
        "json" => display_comparison_json(&comparison)?,
        "diff" => display_comparison_diff(&comparison),
        _ => {
            print_error(&format!("Unsupported format: {}", args.format));
            return Ok(());
        }
    }

    if let Some(ref output_path) = args.output {
        save_comparison_output(&comparison, output_path, &args.format)?;
        print_success(&format!("Comparison saved to: {}", output_path.display()));
    }

    Ok(())
}

fn display_comparison_table(comparison: &ComparisonResult, detailed: bool) {
    println!();
    println!("{}", "═".repeat(80).bright_black());
    println!("{:^80}", "SCAN COMPARISON RESULTS".bold().bright_white());
    println!("{}", "═".repeat(80).bright_black());

    println!("URL: {}", comparison.url.bold().cyan());

    match (&comparison.old_record, &comparison.new_record) {
        (Some(old), Some(new)) => {
            println!();
            println!("{}", "BASIC COMPARISON".bold().white());
            println!("{}", "─".repeat(50).bright_black());

            display_scan_summary("Old Scan", old);
            display_scan_summary("New Scan", new);

            if !comparison.changes.is_empty() {
                println!();
                println!("{}", "DETECTED CHANGES".bold().yellow());
                println!("{}", "─".repeat(50).bright_black());

                for change in &comparison.changes {
                    let change_icon: &str =
                        if change.contains("Critical") || change.contains("Error") {
                            "🔴"
                        } else if change.contains("Warning") || change.contains("High") {
                            "🟡"
                        } else if change.contains("resolved") || change.contains("New") {
                            "🟢"
                        } else {
                            "ℹ️"
                        };

                    println!("  {} {}", change_icon, change);
                }
            } else {
                println!();
                println!("{}: No significant changes detected", "✓".green().bold());
            }

            if detailed {
                display_detailed_comparison(old, new);
            }
        }
        (Some(old), None) => {
            println!();
            print_warning("New scan not found - showing old scan only");
            display_scan_summary("Old Scan", old);
        }
        (None, Some(new)) => {
            println!();
            print_warning("Old scan not found - showing new scan only");
            display_scan_summary("New Scan", new);
        }
        (None, None) => {
            print_error("Neither old nor new scan found for the specified dates");
        }
    }

    println!("{}", "═".repeat(80).bright_black());
}

fn display_scan_summary(label: &str, scan: &ScanRecord) {
    println!();
    println!("{}", label.bold().bright_blue());
    println!(
        "  Timestamp: {}",
        scan.timestamp.format("%Y-%m-%d %H:%M:%S UTC")
    );

    let status_colored = match scan.status.parse::<u16>() {
        Ok(200..=299) => scan.status.green(),
        Ok(300..=399) => scan.status.yellow(),
        Ok(400..=499) => scan.status.red(),
        Ok(500..=599) => scan.status.bright_red(),
        _ => scan.status.white(),
    };
    println!("  Status: {}", status_colored);

    if let Some(response_time) = scan.response_time_ms {
        println!("  Response Time: {}ms", response_time);
    }

    if !scan.detections.is_empty() {
        println!("  Technologies: {}", scan.detections.len());
        for detection in &scan.detections {
            println!("    • {}", detection.cyan());
        }
    } else {
        println!("  Technologies: None detected");
    }

    if !scan.content_findings.is_empty() {
        let critical = scan
            .content_findings
            .iter()
            .filter(|f| {
                matches!(
                    f.severity,
                    crate::content_analyzer::FindingSeverity::Critical
                )
            })
            .count();
        let high = scan
            .content_findings
            .iter()
            .filter(|f| matches!(f.severity, crate::content_analyzer::FindingSeverity::High))
            .count();

        println!("  Security Findings: {} total", scan.content_findings.len());
        if critical > 0 {
            println!("    Critical: {}", critical.to_string().red());
        }
        if high > 0 {
            println!("    High: {}", high.to_string().yellow());
        }
    } else {
        println!("  Security Findings: {}", "None".green());
    }

    if !scan.tls_info.is_empty() {
        if let Some(subject) = scan.tls_info.get("subject") {
            println!("  TLS Subject: {}", subject);
        }
        if scan.tls_info.contains_key("warnings") || scan.tls_info.contains_key("errors") {
            println!("  TLS Status: {}", "Issues Detected".red());
        } else {
            println!("  TLS Status: {}", "OK".green());
        }
    }
}

fn display_detailed_comparison(old: &ScanRecord, new: &ScanRecord) {
    println!();
    println!("{}", "DETAILED ANALYSIS".bold().white());
    println!("{}", "─".repeat(50).bright_black());

    let old_techs: std::collections::HashSet<_> = old.detections.iter().collect();
    let new_techs: std::collections::HashSet<_> = new.detections.iter().collect();

    let added_techs: Vec<_> = new_techs.difference(&old_techs).collect();
    let removed_techs: Vec<_> = old_techs.difference(&new_techs).collect();

    if !added_techs.is_empty() || !removed_techs.is_empty() {
        println!("\n{}", "Technology Changes:".bold());
        for tech in added_techs {
            println!("  {} {}", "+".green(), tech);
        }
        for tech in removed_techs {
            println!("  {} {}", "-".red(), tech);
        }
    }

    if let (Some(old_time), Some(new_time)) = (old.response_time_ms, new.response_time_ms) {
        let diff = new_time as i64 - old_time as i64;
        if diff.abs() > 100 {
            let change_type = if diff > 0 { "slower" } else { "faster" };
            let color = if diff > 0 { "red" } else { "green" };
            println!(
                "\n{}: {}ms -> {}ms ({} {}ms)",
                "Response Time Change".bold(),
                old_time,
                new_time,
                change_type,
                diff.abs().to_string().color(color)
            );
        }
    }

    let old_critical = old
        .content_findings
        .iter()
        .filter(|f| {
            matches!(
                f.severity,
                crate::content_analyzer::FindingSeverity::Critical
            )
        })
        .count();
    let new_critical = new
        .content_findings
        .iter()
        .filter(|f| {
            matches!(
                f.severity,
                crate::content_analyzer::FindingSeverity::Critical
            )
        })
        .count();

    if old_critical != new_critical {
        let diff = new_critical as i32 - old_critical as i32;
        let indicator = if diff > 0 {
            format!("🔴 +{} critical findings", diff)
        } else {
            format!("🟢 {} critical findings resolved", diff.abs())
        };
        println!("\n{}: {}", "Security Change".bold(), indicator);
    }

    let old_tls_issues =
        old.tls_info.contains_key("warnings") || old.tls_info.contains_key("errors");
    let new_tls_issues =
        new.tls_info.contains_key("warnings") || new.tls_info.contains_key("errors");

    if old_tls_issues != new_tls_issues {
        if new_tls_issues && !old_tls_issues {
            println!("\n{}: 🔴 New TLS issues detected", "TLS Change".bold());
        } else if !new_tls_issues && old_tls_issues {
            println!("\n{}: 🟢 TLS issues resolved", "TLS Change".bold());
        }
    }
}

fn display_comparison_json(comparison: &ComparisonResult) -> Result<()> {
    let json = serde_json::to_string_pretty(comparison)?;
    println!("{}", json);
    Ok(())
}

fn display_comparison_diff(comparison: &ComparisonResult) {
    println!();
    println!("{}", "DIFF VIEW".bold().bright_white());
    println!("{}", "═".repeat(60).bright_black());

    if let (Some(old), Some(new)) = (&comparison.old_record, &comparison.new_record) {
        println!(
            "--- {} ({})",
            comparison.url,
            old.timestamp.format("%Y-%m-%d %H:%M:%S")
        );
        println!(
            "+++ {} ({})",
            comparison.url,
            new.timestamp.format("%Y-%m-%d %H:%M:%S")
        );
        println!();

        if old.status != new.status {
            println!("{} Status: {}", "-".red(), old.status.red());
            println!("{} Status: {}", "+".green(), new.status.green());
            println!();
        }

        let old_techs: std::collections::HashSet<_> = old.detections.iter().collect();
        let new_techs: std::collections::HashSet<_> = new.detections.iter().collect();

        let removed: Vec<_> = old_techs.difference(&new_techs).collect();
        let added: Vec<_> = new_techs.difference(&old_techs).collect();

        if !removed.is_empty() || !added.is_empty() {
            println!("{}", "Technologies:".bold());
            for tech in removed {
                println!("{} {}", "-".red(), tech.red());
            }
            for tech in added {
                println!("{} {}", "+".green(), tech.green());
            }
            println!();
        }

        let old_findings_count = old.content_findings.len();
        let new_findings_count = new.content_findings.len();

        if old_findings_count != new_findings_count {
            println!("{}", "Security Findings:".bold());
            println!(
                "{} {} findings",
                "-".red(),
                old_findings_count.to_string().red()
            );
            println!(
                "{} {} findings",
                "+".green(),
                new_findings_count.to_string().green()
            );
            println!();
        }

        let old_tls_status = get_tls_status(&old.tls_info);
        let new_tls_status = get_tls_status(&new.tls_info);

        if old_tls_status != new_tls_status {
            println!("{}", "TLS Status:".bold());
            println!("{} {}", "-".red(), old_tls_status.red());
            println!("{} {}", "+".green(), new_tls_status.green());
        }
    }

    if !comparison.changes.is_empty() {
        println!();
        println!("{}", "Summary of Changes:".bold().bright_cyan());
        for change in &comparison.changes {
            println!("  • {}", change);
        }
    }
}

fn get_tls_status(tls_info: &std::collections::HashMap<String, String>) -> String {
    if tls_info.is_empty() {
        "No TLS data".to_string()
    } else if tls_info.contains_key("errors") {
        "TLS Errors".to_string()
    } else if tls_info.contains_key("warnings") {
        "TLS Warnings".to_string()
    } else {
        "TLS OK".to_string()
    }
}

fn save_comparison_output(
    comparison: &ComparisonResult,
    path: &PathBuf,
    format: &str,
) -> Result<()> {
    let content = match format.to_lowercase().as_str() {
        "json" => serde_json::to_string_pretty(comparison)?,
        _ => {
            let mut output = String::new();
            output.push_str(&format!("Comparison Report for {}\n", comparison.url));
            output.push_str(&format!(
                "Generated: {}\n\n",
                chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
            ));

            if let (Some(old), Some(new)) = (&comparison.old_record, &comparison.new_record) {
                output.push_str(&format!(
                    "Old Scan: {} (Status: {})\n",
                    old.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
                    old.status
                ));
                output.push_str(&format!(
                    "New Scan: {} (Status: {})\n\n",
                    new.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
                    new.status
                ));
            }

            if !comparison.changes.is_empty() {
                output.push_str("Changes Detected:\n");
                for change in &comparison.changes {
                    output.push_str(&format!("  - {}\n", change));
                }
            } else {
                output.push_str("No significant changes detected.\n");
            }

            output
        }
    };

    std::fs::write(path, content)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{HistoryDatabase, ScanConfig, ScanRecord};
    use chrono::Utc;
    use std::collections::HashMap;
    use tempfile::TempDir;
    use uuid::Uuid;

    fn create_test_db() -> (HistoryDatabase, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let db = HistoryDatabase::new(Some(temp_dir.path().to_path_buf())).unwrap();
        (db, temp_dir)
    }

    fn create_test_scan(url: &str, status: &str, timestamp: chrono::DateTime<Utc>) -> ScanRecord {
        ScanRecord {
            id: Uuid::new_v4().to_string(),
            timestamp,
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
    fn test_get_tls_status() {
        let mut tls_info = HashMap::new();
        assert_eq!(get_tls_status(&tls_info), "No TLS data");

        tls_info.insert("errors".to_string(), "Certificate expired".to_string());
        assert_eq!(get_tls_status(&tls_info), "TLS Errors");

        tls_info.clear();
        tls_info.insert("warnings".to_string(), "Weak cipher".to_string());
        assert_eq!(get_tls_status(&tls_info), "TLS Warnings");

        tls_info.clear();
        tls_info.insert("subject".to_string(), "CN=example.com".to_string());
        assert_eq!(get_tls_status(&tls_info), "TLS OK");
    }

    #[tokio::test]
    async fn test_save_comparison_output() {
        let comparison = ComparisonResult {
            url: "https://example.com".to_string(),
            old_record: None,
            new_record: None,
            changes: vec!["Status changed: 200 -> 404".to_string()],
        };

        let temp_file = tempfile::NamedTempFile::new().unwrap();
        let path = temp_file.path().to_path_buf();

        save_comparison_output(&comparison, &path, "text").unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("https://example.com"));
        assert!(content.contains("Status changed: 200 -> 404"));
    }
}
