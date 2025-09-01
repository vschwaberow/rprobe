// File: history.rs
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023-2025
// - Volker Schwaberow <volker@schwaberow.de>

use anyhow::Result;
use colored::*;
use std::collections::HashMap;

use super::{print_error, print_info, print_success, print_warning};
use crate::cli::HistoryArgs;
use crate::content_analyzer::FindingSeverity;
use crate::storage::{HistoryDatabase, HistoryQuery, ScanRecord};

pub async fn execute(args: &HistoryArgs, db: &HistoryDatabase) -> Result<()> {
    if let Some(ref url) = args.url {
        show_url_history(url, args, db).await
    } else {
        show_general_history(args, db).await
    }
}

async fn show_url_history(url: &str, args: &HistoryArgs, db: &HistoryDatabase) -> Result<()> {
    print_info(&format!("Retrieving history for: {}", url));

    let history = db.get_url_history(url, Some(args.limit))?;

    if history.is_empty() {
        print_warning(&format!("No scan history found for: {}", url));
        return Ok(());
    }

    print_success(&format!("Found {} scan records", history.len()));

    match args.format.to_lowercase().as_str() {
        "table" => display_history_table(&history, args.show_changes),
        "json" => display_history_json(&history)?,
        "timeline" => display_history_timeline(&history),
        _ => {
            print_error(&format!("Unsupported format: {}", args.format));
            return Ok(());
        }
    }

    if args.show_changes && history.len() > 1 {
        print_info("\nAnalyzing changes between scans...");
        analyze_changes(&history)?;
    }

    Ok(())
}

async fn show_general_history(args: &HistoryArgs, db: &HistoryDatabase) -> Result<()> {
    print_info("Retrieving general scan history");

    let query = HistoryQuery {
        start_date: args.parse_start_date(),
        end_date: args.parse_end_date(),
        limit: Some(args.limit),
        ..Default::default()
    };

    let scans = db.query_scans(&query)?;

    if scans.is_empty() {
        print_warning("No scan history found matching the criteria");
        return Ok(());
    }

    print_success(&format!("Found {} scan records", scans.len()));

    if let Some(ref group_by) = args.group_by {
        display_grouped_history(&scans, group_by)?;
    } else {
        match args.format.to_lowercase().as_str() {
            "table" => display_history_table(&scans, args.show_changes),
            "json" => display_history_json(&scans)?,
            "timeline" => display_history_timeline(&scans),
            _ => {
                print_error(&format!("Unsupported format: {}", args.format));
                return Ok(());
            }
        }
    }

    Ok(())
}

fn display_history_table(scans: &[ScanRecord], show_changes: bool) {
    println!();
    println!("{}", "═".repeat(120).bright_black());
    println!("{:^120}", "SCAN HISTORY".bold().bright_white());
    println!("{}", "═".repeat(120).bright_black());

    println!(
        "{:<50} {:<8} {:<20} {:<10} {:<15} {}",
        "URL".bold(),
        "Status".bold(),
        "Timestamp".bold(),
        "Tech".bold(),
        "Security".bold(),
        "Notes".bold()
    );
    println!("{}", "─".repeat(120).bright_black());

    let mut prev_scan: Option<&ScanRecord> = None;

    for scan in scans {
        let url_display = if scan.url.len() > 47 {
            format!("{}...", &scan.url[..44])
        } else {
            scan.url.clone()
        };

        let status_colored = match scan.status.parse::<u16>() {
            Ok(code) => match code {
                200..=299 => scan.status.green(),
                300..=399 => scan.status.yellow(),
                400..=499 => scan.status.red(),
                500..=599 => scan.status.bright_red(),
                _ => scan.status.white(),
            },
            Err(_) => {
                if scan.status == "Failed" || scan.status == "0" {
                    scan.status.red()
                } else {
                    scan.status.white()
                }
            }
        };

        let tech_count = scan.detections.len();
        let tech_display = if tech_count > 0 {
            format!("{}", tech_count).cyan()
        } else {
            "0".dimmed()
        };

        let security_summary = get_security_summary(&scan.content_findings);
        let security_display = if security_summary.is_empty() {
            "Clean".green()
        } else {
            security_summary.yellow()
        };

        let mut notes = Vec::new();

        if !scan.tls_info.is_empty()
            && (scan.tls_info.contains_key("warnings") || scan.tls_info.contains_key("errors"))
        {
            notes.push("TLS Issues".red().to_string());
        }

        if show_changes {
            let changes = if let Some(prev) = prev_scan {
                detect_changes(prev, scan)
            } else {
                Vec::new()
            };
            if !changes.is_empty() {
                notes.push(format!("{}Δ", changes.len()).bright_blue().to_string());
            }
        }

        let notes_display = if notes.is_empty() {
            "-".dimmed().to_string()
        } else {
            notes.join(", ")
        };

        println!(
            "{:<50} {:<8} {:<20} {:<10} {:<15} {}",
            url_display,
            status_colored,
            scan.timestamp.format("%m/%d %H:%M:%S"),
            tech_display,
            security_display,
            notes_display
        );

        prev_scan = Some(scan);
    }

    println!("{}", "═".repeat(120).bright_black());
}

fn display_history_json(scans: &[ScanRecord]) -> Result<()> {
    let json = serde_json::to_string_pretty(scans)?;
    println!("{}", json);
    Ok(())
}

fn display_history_timeline(scans: &[ScanRecord]) {
    println!();
    println!("{}", "SCAN TIMELINE".bold().bright_white());
    println!("{}", "─".repeat(80).bright_black());

    let mut grouped_by_day: HashMap<String, Vec<&ScanRecord>> = HashMap::new();

    for scan in scans {
        let day = scan.timestamp.format("%Y-%m-%d").to_string();
        grouped_by_day.entry(day).or_default().push(scan);
    }

    let mut days: Vec<_> = grouped_by_day.keys().collect();
    days.sort();
    days.reverse();

    for day in days {
        let day_scans = &grouped_by_day[day];
        println!("\n{} ({} scans)", day.bold().cyan(), day_scans.len());

        for scan in day_scans.iter().take(10) {
            let time = scan.timestamp.format("%H:%M:%S");
            let status_icon = match scan.status.parse::<u16>() {
                Ok(200..=299) => "✓".green(),
                Ok(300..=399) => "↻".yellow(),
                Ok(400..=499) => "⚠".red(),
                Ok(500..=599) => "✗".bright_red(),
                _ => "?".white(),
            };

            let url_short = if scan.url.len() > 60 {
                format!("{}...", &scan.url[..57])
            } else {
                scan.url.clone()
            };

            println!(
                "  {} {} {} {}",
                format!("{}", time).dimmed(),
                status_icon,
                scan.status,
                url_short
            );

            if !scan.content_findings.is_empty() {
                let critical = scan
                    .content_findings
                    .iter()
                    .filter(|f| f.severity == FindingSeverity::Critical)
                    .count();
                let high = scan
                    .content_findings
                    .iter()
                    .filter(|f| f.severity == FindingSeverity::High)
                    .count();

                if critical > 0 || high > 0 {
                    println!(
                        "    🔴 Critical: {}, High: {}",
                        critical.to_string().red(),
                        high.to_string().yellow()
                    );
                }
            }
        }

        if day_scans.len() > 10 {
            println!("    ... and {} more scans", day_scans.len() - 10);
        }
    }
}

fn display_grouped_history(scans: &[ScanRecord], group_by: &str) -> Result<()> {
    match group_by.to_lowercase().as_str() {
        "url" => group_by_url(scans),
        "status" => group_by_status(scans),
        "date" => group_by_date(scans),
        _ => {
            print_error(&format!("Unsupported group_by value: {}", group_by));
            return Ok(());
        }
    }
    Ok(())
}

fn group_by_url(scans: &[ScanRecord]) {
    let mut grouped: HashMap<String, Vec<&ScanRecord>> = HashMap::new();

    for scan in scans {
        grouped.entry(scan.url.clone()).or_default().push(scan);
    }

    println!("\n{}", "SCANS GROUPED BY URL".bold().bright_white());
    println!("{}", "═".repeat(80).bright_black());

    let mut urls: Vec<_> = grouped.keys().collect();
    urls.sort();

    for url in urls {
        let url_scans = &grouped[url];
        println!("\n{} ({} scans)", url.bold().cyan(), url_scans.len());

        let statuses: HashMap<String, usize> =
            url_scans.iter().fold(HashMap::new(), |mut acc, scan| {
                *acc.entry(scan.status.clone()).or_insert(0) += 1;
                acc
            });

        for (status, count) in statuses {
            let status_colored = match status.parse::<u16>() {
                Ok(200..=299) => status.green(),
                Ok(400..=499) => status.red(),
                _ => status.white(),
            };
            println!("  {} {}: {} times", "•".dimmed(), status_colored, count);
        }

        let latest_scan = url_scans.iter().max_by_key(|s| s.timestamp).unwrap();
        println!(
            "  Last scanned: {}",
            format!("{}", latest_scan.timestamp.format("%Y-%m-%d %H:%M:%S UTC")).dimmed()
        );
    }
}

fn group_by_status(scans: &[ScanRecord]) {
    let mut grouped: HashMap<String, Vec<&ScanRecord>> = HashMap::new();

    for scan in scans {
        grouped.entry(scan.status.clone()).or_default().push(scan);
    }

    println!("\n{}", "SCANS GROUPED BY STATUS".bold().bright_white());
    println!("{}", "═".repeat(80).bright_black());

    let mut statuses: Vec<_> = grouped.keys().collect();
    statuses.sort();

    for status in statuses {
        let status_scans = &grouped[status];
        let status_colored = match status.parse::<u16>() {
            Ok(200..=299) => status.green(),
            Ok(300..=399) => status.yellow(),
            Ok(400..=499) => status.red(),
            Ok(500..=599) => status.bright_red(),
            _ => status.white(),
        };

        println!("\n{} ({} scans)", status_colored.bold(), status_scans.len());

        let unique_urls: std::collections::HashSet<&String> =
            status_scans.iter().map(|s| &s.url).collect();

        println!("  Unique URLs: {}", unique_urls.len());

        for url in unique_urls.iter().take(5) {
            println!("  • {}", url.dimmed());
        }

        if unique_urls.len() > 5 {
            println!("  • ... and {} more URLs", unique_urls.len() - 5);
        }
    }
}

fn group_by_date(scans: &[ScanRecord]) {
    let mut grouped: HashMap<String, Vec<&ScanRecord>> = HashMap::new();

    for scan in scans {
        let date = scan.timestamp.format("%Y-%m-%d").to_string();
        grouped.entry(date).or_default().push(scan);
    }

    println!("\n{}", "SCANS GROUPED BY DATE".bold().bright_white());
    println!("{}", "═".repeat(80).bright_black());

    let mut dates: Vec<_> = grouped.keys().collect();
    dates.sort();
    dates.reverse();

    for date in dates {
        let date_scans = &grouped[date];
        println!("\n{} ({} scans)", date.bold().cyan(), date_scans.len());

        let unique_urls = date_scans
            .iter()
            .map(|s| &s.url)
            .collect::<std::collections::HashSet<_>>()
            .len();
        let successful = date_scans
            .iter()
            .filter(|s| matches!(s.status.parse::<u16>(), Ok(200..=299)))
            .count();

        println!(
            "  Unique URLs: {} | Successful: {}/{}",
            unique_urls,
            successful.to_string().green(),
            date_scans.len()
        );

        let tech_counts: HashMap<String, usize> = date_scans
            .iter()
            .flat_map(|s| &s.detections)
            .fold(HashMap::new(), |mut acc, tech| {
                let tech_name = tech.split(": ").next().unwrap_or(tech);
                *acc.entry(tech_name.to_string()).or_insert(0) += 1;
                acc
            });

        if !tech_counts.is_empty() {
            let mut top_techs: Vec<_> = tech_counts.iter().collect();
            top_techs.sort_by(|a, b| b.1.cmp(a.1));

            print!("  Top technologies: ");
            for (i, (tech, count)) in top_techs.iter().take(3).enumerate() {
                if i > 0 {
                    print!(", ");
                }
                print!("{} ({})", tech.cyan(), count);
            }
            println!();
        }
    }
}

fn get_security_summary(findings: &[crate::content_analyzer::ContentFinding]) -> String {
    if findings.is_empty() {
        return String::new();
    }

    let critical = findings
        .iter()
        .filter(|f| f.severity == FindingSeverity::Critical)
        .count();
    let high = findings
        .iter()
        .filter(|f| f.severity == FindingSeverity::High)
        .count();

    if critical > 0 {
        format!("C:{}", critical)
    } else if high > 0 {
        format!("H:{}", high)
    } else {
        format!("{} issues", findings.len())
    }
}

fn detect_changes(old_scan: &ScanRecord, new_scan: &ScanRecord) -> Vec<String> {
    let mut changes = Vec::new();

    if old_scan.status != new_scan.status {
        changes.push("Status".to_string());
    }

    let old_techs: std::collections::HashSet<_> = old_scan.detections.iter().collect();
    let new_techs: std::collections::HashSet<_> = new_scan.detections.iter().collect();
    if old_techs != new_techs {
        changes.push("Tech".to_string());
    }

    let old_critical = old_scan
        .content_findings
        .iter()
        .filter(|f| f.severity == FindingSeverity::Critical)
        .count();
    let new_critical = new_scan
        .content_findings
        .iter()
        .filter(|f| f.severity == FindingSeverity::Critical)
        .count();
    if old_critical != new_critical {
        changes.push("Security".to_string());
    }

    changes
}

fn analyze_changes(history: &[ScanRecord]) -> Result<()> {
    if history.len() < 2 {
        return Ok(());
    }

    println!("\n{}", "CHANGE ANALYSIS".bold().bright_white());
    println!("{}", "─".repeat(60).bright_black());

    let mut status_changes = 0;
    let mut tech_changes = 0;
    let mut security_changes = 0;

    for i in 1..history.len() {
        let changes = detect_changes(&history[i - 1], &history[i]);

        if changes.contains(&"Status".to_string()) {
            status_changes += 1;
        }
        if changes.contains(&"Tech".to_string()) {
            tech_changes += 1;
        }
        if changes.contains(&"Security".to_string()) {
            security_changes += 1;
        }
    }

    println!(
        "Status changes:    {}",
        if status_changes > 0 {
            status_changes.to_string().yellow()
        } else {
            status_changes.to_string().green()
        }
    );
    println!(
        "Technology changes: {}",
        if tech_changes > 0 {
            tech_changes.to_string().cyan()
        } else {
            tech_changes.to_string().dimmed()
        }
    );
    println!(
        "Security changes:   {}",
        if security_changes > 0 {
            security_changes.to_string().red()
        } else {
            security_changes.to_string().green()
        }
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{HistoryDatabase, ScanConfig};
    use chrono::Utc;
    use std::collections::HashMap;
    use tempfile::TempDir;
    use uuid::Uuid;

    fn create_test_db() -> (HistoryDatabase, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let db = HistoryDatabase::new(Some(temp_dir.path().to_path_buf())).unwrap();
        (db, temp_dir)
    }

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
    fn test_get_security_summary() {
        let findings = vec![];
        assert_eq!(get_security_summary(&findings), "");
    }

    #[test]
    fn test_detect_changes() {
        let scan1 = create_test_scan("https://example.com", "200");
        let mut scan2 = create_test_scan("https://example.com", "404");
        scan2.detections = vec!["Apache: Web Server".to_string()];

        let changes = detect_changes(&scan1, &scan2);
        assert!(changes.contains(&"Status".to_string()));
        assert!(changes.contains(&"Tech".to_string()));
    }
}
