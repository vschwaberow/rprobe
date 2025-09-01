// File: clean.rs
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023-2025
// - Volker Schwaberow <volker@schwaberow.de>

use anyhow::Result;
use chrono::{DateTime, Utc};
use colored::*;
use std::io::{self, Write};

use super::{format_file_size, print_info, print_success, print_warning};
use crate::cli::CleanArgs;
use crate::storage::HistoryDatabase;

pub async fn execute(args: &CleanArgs, db: &HistoryDatabase) -> Result<()> {
    let cutoff_date = args.calculate_cutoff_date().ok_or_else(|| {
        anyhow::anyhow!("No cutoff date specified. Use --before YYYY-MM-DD or --days N")
    })?;

    print_info(&format!(
        "Preparing to clean data before: {}",
        cutoff_date.format("%Y-%m-%d %H:%M:%S UTC")
    ));

    if args.dry_run {
        print_info("Running in dry-run mode - no data will be deleted");
        perform_dry_run(db, cutoff_date).await?;
        return Ok(());
    }

    let stats_before = db.get_database_stats()?;
    print_info(&format!(
        "Database size before cleanup: {}",
        format_file_size(*stats_before.get("size_bytes").unwrap_or(&0))
    ));

    if !args.confirm && !confirm_deletion(cutoff_date)? {
        print_warning("Operation cancelled by user");
        return Ok(());
    }

    print_info("Starting cleanup operation...");
    let deleted_count = db.clean_old_data(cutoff_date)?;

    if deleted_count > 0 {
        print_success(&format!(
            "Successfully deleted {} old scan records",
            deleted_count
        ));
    } else {
        print_info("No old records found to delete");
    }

    if args.compact {
        print_info("Compacting database...");
        db.compact_database()?;
        print_success("Database compaction completed");
    }

    let stats_after = db.get_database_stats()?;
    let size_before = stats_before.get("size_bytes").unwrap_or(&0);
    let size_after = stats_after.get("size_bytes").unwrap_or(&0);

    if size_before > size_after {
        let savings = size_before - size_after;
        let percentage = (savings as f64 / *size_before as f64 * 100.0) as u8;
        print_success(&format!(
            "Space saved: {} ({:.1}%)",
            format_file_size(savings),
            percentage
        ));
    }

    print_info(&format!(
        "Final database size: {}",
        format_file_size(*size_after)
    ));

    Ok(())
}

async fn perform_dry_run(db: &HistoryDatabase, cutoff_date: DateTime<Utc>) -> Result<()> {
    print_info("Analyzing data to be deleted...");

    let all_scans = db.query_scans(&crate::storage::HistoryQuery {
        end_date: Some(cutoff_date),
        limit: None,
        ..Default::default()
    })?;

    if all_scans.is_empty() {
        print_info("No records found before the cutoff date");
        return Ok(());
    }

    println!();
    println!("{}", "DRY RUN ANALYSIS".bold().bright_white());
    println!("{}", "═".repeat(60).bright_black());

    print_summary_stats(&all_scans, cutoff_date);
    print_url_breakdown(&all_scans);
    print_date_breakdown(&all_scans);

    println!("{}", "═".repeat(60).bright_black());
    print_warning(&format!(
        "Would delete {} records in actual run",
        all_scans.len()
    ));

    Ok(())
}

fn print_summary_stats(scans: &[crate::storage::ScanRecord], cutoff_date: DateTime<Utc>) {
    let total_records = scans.len();
    let unique_urls = scans
        .iter()
        .map(|s| s.url.as_str())
        .collect::<std::collections::HashSet<_>>()
        .len();

    let date_range = if !scans.is_empty() {
        let oldest = scans.iter().map(|s| s.timestamp).min().unwrap();
        let newest = scans.iter().map(|s| s.timestamp).max().unwrap();
        format!(
            "{} to {}",
            oldest.format("%Y-%m-%d"),
            newest.format("%Y-%m-%d")
        )
    } else {
        "N/A".to_string()
    };

    println!(
        "Records to delete:    {}",
        total_records.to_string().red().bold()
    );
    println!("Unique URLs affected: {}", unique_urls.to_string().yellow());
    println!("Date range:           {}", date_range);
    println!(
        "Cutoff date:          {}",
        format!("{}", cutoff_date.format("%Y-%m-%d %H:%M:%S UTC")).cyan()
    );
}

fn print_url_breakdown(scans: &[crate::storage::ScanRecord]) {
    let mut url_counts = std::collections::HashMap::new();
    for scan in scans {
        *url_counts.entry(scan.url.clone()).or_insert(0) += 1;
    }

    if url_counts.is_empty() {
        return;
    }

    println!();
    println!("{}", "URL BREAKDOWN (Top 10):".bold());
    let mut sorted_urls: Vec<_> = url_counts.iter().collect();
    sorted_urls.sort_by(|a, b| b.1.cmp(a.1));

    for (i, (url, count)) in sorted_urls.iter().take(10).enumerate() {
        let url_display = if url.len() > 50 {
            format!("{}...", &url[..47])
        } else {
            url.to_string()
        };

        println!(
            "  {:<2} {:<50} {}",
            format!("{}.", i + 1).dimmed(),
            url_display,
            count.to_string().cyan()
        );
    }

    if sorted_urls.len() > 10 {
        println!("  ... and {} more URLs", sorted_urls.len() - 10);
    }
}

fn print_date_breakdown(scans: &[crate::storage::ScanRecord]) {
    let mut date_counts = std::collections::HashMap::new();
    for scan in scans {
        let date = scan.timestamp.format("%Y-%m").to_string();
        *date_counts.entry(date).or_insert(0) += 1;
    }

    if date_counts.is_empty() {
        return;
    }

    println!();
    println!("{}", "DATE BREAKDOWN (by month):".bold());
    let mut sorted_dates: Vec<_> = date_counts.iter().collect();
    sorted_dates.sort_by(|a, b| a.0.cmp(b.0));

    for (date, count) in sorted_dates {
        println!("  {}: {} records", date.cyan(), count.to_string().yellow());
    }
}

fn confirm_deletion(cutoff_date: DateTime<Utc>) -> Result<bool> {
    println!();
    print_warning("This operation will permanently delete scan data!");
    println!(
        "Data before {} will be removed",
        format!("{}", cutoff_date.format("%Y-%m-%d %H:%M:%S UTC")).red()
    );
    println!();

    loop {
        print!("Are you sure you want to continue? [y/N]: ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        match input.trim().to_lowercase().as_str() {
            "y" | "yes" => return Ok(true),
            "n" | "no" | "" => return Ok(false),
            _ => {
                println!("Please enter 'y' for yes or 'n' for no");
                continue;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{HistoryDatabase, ScanConfig, ScanRecord};
    use std::collections::HashMap;
    use tempfile::TempDir;
    use uuid::Uuid;

    fn create_test_db() -> (HistoryDatabase, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let db = HistoryDatabase::new(Some(temp_dir.path().to_path_buf())).unwrap();
        (db, temp_dir)
    }

    fn create_test_scan(url: &str, timestamp: DateTime<Utc>) -> ScanRecord {
        ScanRecord {
            id: Uuid::new_v4().to_string(),
            timestamp,
            url: url.to_string(),
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

    #[tokio::test]
    async fn test_dry_run_analysis() {
        let (db, _temp_dir) = create_test_db();
        let now = Utc::now();

        let old_scan = create_test_scan("https://old.com", now - chrono::Duration::days(10));
        let new_scan = create_test_scan("https://new.com", now);

        db.store_scan(&old_scan).unwrap();
        db.store_scan(&new_scan).unwrap();

        let cutoff = now - chrono::Duration::days(5);
        let result = perform_dry_run(&db, cutoff).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_print_summary_stats() {
        let now = Utc::now();
        let scans = vec![
            create_test_scan("https://example1.com", now - chrono::Duration::days(10)),
            create_test_scan("https://example2.com", now - chrono::Duration::days(8)),
            create_test_scan("https://example1.com", now - chrono::Duration::days(6)),
        ];

        print_summary_stats(&scans, now - chrono::Duration::days(5));
    }
}
