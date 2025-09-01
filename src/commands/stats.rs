// File: stats.rs
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023-2025
// - Volker Schwaberow <volker@schwaberow.de>

use anyhow::Result;
use chrono::{DateTime, Duration, Timelike, Utc};
use colored::*;
use std::collections::HashMap;
use std::path::PathBuf;

use super::{format_duration, format_file_size, print_error, print_info, print_success};
use crate::cli::StatsArgs;
use crate::storage::{HistoryDatabase, HistoryQuery};

pub async fn execute(args: &StatsArgs, db: &HistoryDatabase) -> Result<()> {
    print_info("Generating database statistics...");

    let time_range = parse_time_range(&args.time_range);
    let stats = generate_statistics(db, time_range, args.detailed).await?;

    match args.format.to_lowercase().as_str() {
        "table" => display_stats_table(&stats, args.top_n),
        "json" => display_stats_json(&stats)?,
        "csv" => display_stats_csv(&stats),
        _ => {
            print_error(&format!("Unsupported format: {}", args.format));
            return Ok(());
        }
    }

    if let Some(ref output_path) = args.output {
        save_stats_output(&stats, output_path, &args.format)?;
        print_success(&format!("Statistics saved to: {}", output_path.display()));
    }

    Ok(())
}

#[derive(Debug, Clone)]
struct DatabaseStats {
    database_info: HashMap<String, u64>,
    scan_summary: ScanSummary,
    url_stats: UrlStats,
    technology_stats: TechnologyStats,
    security_stats: SecurityStats,
    temporal_stats: TemporalStats,
    performance_stats: PerformanceStats,
    tls_stats: TlsStats,
}

#[derive(Debug, Clone)]
struct ScanSummary {
    total_scans: usize,
    successful_scans: usize,
    failed_scans: usize,
    unique_urls: usize,
    date_range: Option<(DateTime<Utc>, DateTime<Utc>)>,
}

#[derive(Debug, Clone)]
struct UrlStats {
    most_scanned_urls: Vec<(String, usize)>,
    unique_domains: usize,
    url_status_distribution: HashMap<String, HashMap<String, usize>>,
}

#[derive(Debug, Clone)]
struct TechnologyStats {
    total_detections: usize,
    unique_technologies: usize,
    technology_frequency: Vec<(String, usize)>,
    technology_by_domain: HashMap<String, Vec<String>>,
}

#[derive(Debug, Clone)]
struct SecurityStats {
    total_findings: usize,
    findings_by_severity: HashMap<String, usize>,
    findings_by_category: HashMap<String, usize>,
    urls_with_critical_issues: usize,
    most_vulnerable_urls: Vec<(String, usize)>,
}

#[derive(Debug, Clone)]
struct TemporalStats {
    scans_by_day: HashMap<String, usize>,
    scans_by_hour: HashMap<u32, usize>,
    average_scans_per_day: f64,
    busiest_day: Option<(String, usize)>,
    busiest_hour: Option<(u32, usize)>,
}

#[derive(Debug, Clone)]
struct PerformanceStats {
    average_response_time: f64,
    median_response_time: f64,
    slowest_responses: Vec<(String, u64)>,
    response_time_distribution: HashMap<String, usize>,
}

#[derive(Debug, Clone)]
struct TlsStats {
    total_tls_scans: usize,
    certificates_with_issues: usize,
    expiring_certificates: Vec<(String, i64)>,
    common_tls_issues: HashMap<String, usize>,
}

async fn generate_statistics(
    db: &HistoryDatabase,
    time_range: Option<(DateTime<Utc>, DateTime<Utc>)>,
    _detailed: bool,
) -> Result<DatabaseStats> {
    let database_info = db.get_database_stats()?;

    let mut query = HistoryQuery {
        limit: None,
        ..Default::default()
    };
    if let Some((start, end)) = time_range {
        query.start_date = Some(start);
        query.end_date = Some(end);
    }

    let scans = db.query_scans(&query)?;

    let scan_summary = calculate_scan_summary(&scans);
    let url_stats = calculate_url_stats(&scans);
    let technology_stats = calculate_technology_stats(&scans);
    let security_stats = calculate_security_stats(&scans);
    let temporal_stats = calculate_temporal_stats(&scans);
    let performance_stats = calculate_performance_stats(&scans);
    let tls_stats = calculate_tls_stats(&scans);

    Ok(DatabaseStats {
        database_info,
        scan_summary,
        url_stats,
        technology_stats,
        security_stats,
        temporal_stats,
        performance_stats,
        tls_stats,
    })
}

fn parse_time_range(range: &Option<String>) -> Option<(DateTime<Utc>, DateTime<Utc>)> {
    let range_str = range.as_ref()?;
    let now = Utc::now();

    match range_str.to_lowercase().as_str() {
        "7d" => Some((now - Duration::days(7), now)),
        "30d" => Some((now - Duration::days(30), now)),
        "90d" => Some((now - Duration::days(90), now)),
        "1y" => Some((now - Duration::days(365), now)),
        "all" => None,
        _ => None,
    }
}

fn calculate_scan_summary(scans: &[crate::storage::ScanRecord]) -> ScanSummary {
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

    ScanSummary {
        total_scans,
        successful_scans,
        failed_scans,
        unique_urls,
        date_range,
    }
}

fn calculate_url_stats(scans: &[crate::storage::ScanRecord]) -> UrlStats {
    let mut url_counts = HashMap::new();
    let mut status_by_url = HashMap::new();
    let mut domains = std::collections::HashSet::new();

    for scan in scans {
        *url_counts.entry(scan.url.clone()).or_insert(0) += 1;

        status_by_url
            .entry(scan.url.clone())
            .or_insert_with(HashMap::new)
            .entry(scan.status.clone())
            .and_modify(|e| *e += 1)
            .or_insert(1);

        if let Ok(parsed_url) = url::Url::parse(&scan.url) {
            if let Some(domain) = parsed_url.domain() {
                domains.insert(domain.to_string());
            }
        }
    }

    let mut most_scanned_urls: Vec<_> = url_counts.into_iter().collect();
    most_scanned_urls.sort_by(|a, b| b.1.cmp(&a.1));
    most_scanned_urls.truncate(20);

    UrlStats {
        most_scanned_urls,
        unique_domains: domains.len(),
        url_status_distribution: status_by_url,
    }
}

fn calculate_technology_stats(scans: &[crate::storage::ScanRecord]) -> TechnologyStats {
    let mut tech_counts = HashMap::new();
    let mut domain_techs = HashMap::new();
    let mut total_detections = 0;

    for scan in scans {
        total_detections += scan.detections.len();

        for detection in &scan.detections {
            let tech_name = if let Some((name, _)) = detection.split_once(": ") {
                name.to_string()
            } else {
                detection.clone()
            };

            *tech_counts.entry(tech_name.clone()).or_insert(0) += 1;

            if let Ok(parsed_url) = url::Url::parse(&scan.url) {
                if let Some(domain) = parsed_url.domain() {
                    domain_techs
                        .entry(domain.to_string())
                        .or_insert_with(Vec::new)
                        .push(tech_name);
                }
            }
        }
    }

    let mut technology_frequency: Vec<_> = tech_counts.into_iter().collect();
    technology_frequency.sort_by(|a, b| b.1.cmp(&a.1));

    let unique_technologies = technology_frequency.len();

    for techs in domain_techs.values_mut() {
        techs.sort();
        techs.dedup();
    }

    TechnologyStats {
        total_detections,
        unique_technologies,
        technology_frequency,
        technology_by_domain: domain_techs,
    }
}

fn calculate_security_stats(scans: &[crate::storage::ScanRecord]) -> SecurityStats {
    let mut total_findings = 0;
    let mut findings_by_severity = HashMap::new();
    let mut findings_by_category = HashMap::new();
    let mut url_vulnerability_counts = HashMap::new();
    let mut urls_with_critical = 0;

    for scan in scans {
        total_findings += scan.content_findings.len();
        let mut has_critical = false;

        for finding in &scan.content_findings {
            let severity_str = format!("{:?}", finding.severity);
            *findings_by_severity.entry(severity_str).or_insert(0) += 1;
            *findings_by_category
                .entry(finding.category.clone())
                .or_insert(0) += 1;

            if matches!(
                finding.severity,
                crate::content_analyzer::FindingSeverity::Critical
            ) {
                has_critical = true;
            }
        }

        if has_critical {
            urls_with_critical += 1;
        }

        *url_vulnerability_counts
            .entry(scan.url.clone())
            .or_insert(0) += scan.content_findings.len();
    }

    let mut most_vulnerable_urls: Vec<_> = url_vulnerability_counts.into_iter().collect();
    most_vulnerable_urls.sort_by(|a, b| b.1.cmp(&a.1));
    most_vulnerable_urls.truncate(10);

    SecurityStats {
        total_findings,
        findings_by_severity,
        findings_by_category,
        urls_with_critical_issues: urls_with_critical,
        most_vulnerable_urls,
    }
}

fn calculate_temporal_stats(scans: &[crate::storage::ScanRecord]) -> TemporalStats {
    let mut scans_by_day = HashMap::new();
    let mut scans_by_hour = HashMap::new();

    for scan in scans {
        let day = scan.timestamp.format("%Y-%m-%d").to_string();
        *scans_by_day.entry(day).or_insert(0) += 1;

        let hour = scan.timestamp.hour();
        *scans_by_hour.entry(hour).or_insert(0) += 1;
    }

    let average_scans_per_day = if scans_by_day.is_empty() {
        0.0
    } else {
        scans.len() as f64 / scans_by_day.len() as f64
    };

    let busiest_day = scans_by_day
        .iter()
        .max_by_key(|(_, &count)| count)
        .map(|(day, &count)| (day.clone(), count));

    let busiest_hour = scans_by_hour
        .iter()
        .max_by_key(|(_, &count)| count)
        .map(|(&hour, &count)| (hour, count));

    TemporalStats {
        scans_by_day,
        scans_by_hour,
        average_scans_per_day,
        busiest_day,
        busiest_hour,
    }
}

fn calculate_performance_stats(scans: &[crate::storage::ScanRecord]) -> PerformanceStats {
    let response_times: Vec<u64> = scans.iter().filter_map(|s| s.response_time_ms).collect();

    let average_response_time = if response_times.is_empty() {
        0.0
    } else {
        response_times.iter().sum::<u64>() as f64 / response_times.len() as f64
    };

    let median_response_time = if response_times.is_empty() {
        0.0
    } else {
        let mut sorted_times = response_times.clone();
        sorted_times.sort();
        let mid = sorted_times.len() / 2;
        if sorted_times.len() % 2 == 0 {
            (sorted_times[mid - 1] + sorted_times[mid]) as f64 / 2.0
        } else {
            sorted_times[mid] as f64
        }
    };

    let mut slowest_responses: Vec<_> = scans
        .iter()
        .filter_map(|s| s.response_time_ms.map(|time| (s.url.clone(), time)))
        .collect();
    slowest_responses.sort_by(|a, b| b.1.cmp(&a.1));
    slowest_responses.truncate(10);

    let mut response_time_distribution = HashMap::new();
    for &time in &response_times {
        let bucket = match time {
            0..=100 => "0-100ms",
            101..=500 => "101-500ms",
            501..=1000 => "501-1000ms",
            1001..=5000 => "1-5s",
            _ => ">5s",
        };
        *response_time_distribution
            .entry(bucket.to_string())
            .or_insert(0) += 1;
    }

    PerformanceStats {
        average_response_time,
        median_response_time,
        slowest_responses,
        response_time_distribution,
    }
}

fn calculate_tls_stats(scans: &[crate::storage::ScanRecord]) -> TlsStats {
    let tls_scans: Vec<_> = scans.iter().filter(|s| !s.tls_info.is_empty()).collect();

    let total_tls_scans = tls_scans.len();

    let certificates_with_issues = tls_scans
        .iter()
        .filter(|s| s.tls_info.contains_key("warnings") || s.tls_info.contains_key("errors"))
        .count();

    let mut expiring_certificates = Vec::new();
    let mut common_tls_issues = HashMap::new();

    for scan in tls_scans {
        if let Some(days_str) = scan.tls_info.get("days_until_expiry") {
            if let Ok(days) = days_str.parse::<i64>() {
                if days <= 90 {
                    expiring_certificates.push((scan.url.clone(), days));
                }
            }
        }

        for (key, value) in &scan.tls_info {
            if key == "warnings" || key == "errors" {
                for issue in value.split(", ") {
                    *common_tls_issues.entry(issue.to_string()).or_insert(0) += 1;
                }
            }
        }
    }

    expiring_certificates.sort_by_key(|&(_, days)| days);

    TlsStats {
        total_tls_scans,
        certificates_with_issues,
        expiring_certificates,
        common_tls_issues,
    }
}

fn display_stats_table(stats: &DatabaseStats, top_n: usize) {
    println!();
    println!("{}", "═".repeat(100).bright_black());
    println!("{:^100}", "DATABASE STATISTICS".bold().bright_white());
    println!("{}", "═".repeat(100).bright_black());

    println!("\n{}", "DATABASE INFORMATION".bold().cyan());
    println!("{}", "─".repeat(40).bright_black());
    println!(
        "Database Size:     {}",
        format_file_size(*stats.database_info.get("size_bytes").unwrap_or(&0)).bold()
    );
    println!(
        "Total Scans:       {}",
        stats
            .database_info
            .get("scans_count")
            .unwrap_or(&0)
            .to_string()
            .bold()
            .green()
    );
    println!(
        "Total Sessions:    {}",
        stats
            .database_info
            .get("sessions_count")
            .unwrap_or(&0)
            .to_string()
            .bold()
            .blue()
    );

    println!("\n{}", "SCAN SUMMARY".bold().cyan());
    println!("{}", "─".repeat(40).bright_black());
    println!(
        "Total Scans:       {}",
        stats.scan_summary.total_scans.to_string().bold()
    );
    println!(
        "Successful:        {} ({:.1}%)",
        stats.scan_summary.successful_scans.to_string().green(),
        stats.scan_summary.successful_scans as f64 / stats.scan_summary.total_scans as f64 * 100.0
    );
    println!(
        "Failed:            {} ({:.1}%)",
        stats.scan_summary.failed_scans.to_string().red(),
        stats.scan_summary.failed_scans as f64 / stats.scan_summary.total_scans as f64 * 100.0
    );
    println!(
        "Unique URLs:       {}",
        stats.scan_summary.unique_urls.to_string().bold()
    );

    if let Some((start, end)) = stats.scan_summary.date_range {
        println!(
            "Date Range:        {} to {}",
            start.format("%Y-%m-%d").to_string().dimmed(),
            end.format("%Y-%m-%d").to_string().dimmed()
        );
    }

    println!("\n{}", "TOP SCANNED URLS".bold().cyan());
    println!("{}", "─".repeat(70).bright_black());
    for (i, (url, count)) in stats
        .url_stats
        .most_scanned_urls
        .iter()
        .take(top_n)
        .enumerate()
    {
        let url_display = if url.len() > 50 {
            format!("{}...", &url[..47])
        } else {
            url.clone()
        };
        println!(
            "{:>2}. {:<50} {}",
            (i + 1).to_string().dimmed(),
            url_display,
            count.to_string().cyan().bold()
        );
    }

    if !stats.technology_stats.technology_frequency.is_empty() {
        println!("\n{}", "TECHNOLOGY DETECTION".bold().cyan());
        println!("{}", "─".repeat(50).bright_black());
        println!(
            "Total Detections:  {}",
            stats.technology_stats.total_detections.to_string().bold()
        );
        println!(
            "Unique Technologies: {}",
            stats
                .technology_stats
                .unique_technologies
                .to_string()
                .bold()
        );
        println!("\nTop Technologies:");

        for (i, (tech, count)) in stats
            .technology_stats
            .technology_frequency
            .iter()
            .take(top_n)
            .enumerate()
        {
            let percentage = *count as f64 / stats.technology_stats.total_detections as f64 * 100.0;
            println!(
                "{:>2}. {:<25} {} ({:.1}%)",
                (i + 1).to_string().dimmed(),
                tech,
                count.to_string().cyan().bold(),
                percentage
            );
        }
    }

    if stats.security_stats.total_findings > 0 {
        println!("\n{}", "SECURITY ANALYSIS".bold().red());
        println!("{}", "─".repeat(50).bright_black());
        println!(
            "Total Findings:    {}",
            stats.security_stats.total_findings.to_string().bold()
        );
        println!(
            "URLs with Critical: {}",
            stats
                .security_stats
                .urls_with_critical_issues
                .to_string()
                .red()
                .bold()
        );

        println!("\nFindings by Severity:");
        for (severity, count) in &stats.security_stats.findings_by_severity {
            let color = match severity.as_str() {
                "Critical" => count.to_string().red(),
                "High" => count.to_string().yellow(),
                _ => count.to_string().blue(),
            };
            println!("  {:<10} {}", severity, color.bold());
        }
    }

    println!("\n{}", "PERFORMANCE METRICS".bold().cyan());
    println!("{}", "─".repeat(50).bright_black());
    println!(
        "Avg Response Time: {}",
        format_duration(stats.performance_stats.average_response_time as u64).bold()
    );
    println!(
        "Median Response:   {}",
        format_duration(stats.performance_stats.median_response_time as u64).bold()
    );

    if !stats.performance_stats.slowest_responses.is_empty() {
        println!("\nSlowest Responses:");
        for (i, (url, time)) in stats
            .performance_stats
            .slowest_responses
            .iter()
            .take(5)
            .enumerate()
        {
            let url_display = if url.len() > 40 {
                format!("{}...", &url[..37])
            } else {
                url.clone()
            };
            println!(
                "{:>2}. {:<40} {}",
                (i + 1).to_string().dimmed(),
                url_display,
                format_duration(*time).red()
            );
        }
    }

    if let Some((day, count)) = &stats.temporal_stats.busiest_day {
        println!("\n{}", "TEMPORAL ANALYSIS".bold().cyan());
        println!("{}", "─".repeat(40).bright_black());
        println!(
            "Avg Scans/Day:     {:.1}",
            stats.temporal_stats.average_scans_per_day
        );
        println!(
            "Busiest Day:       {} ({} scans)",
            day.bold(),
            count.to_string().cyan()
        );

        if let Some((hour, count)) = &stats.temporal_stats.busiest_hour {
            println!(
                "Busiest Hour:      {:02}:00 ({} scans)",
                hour,
                count.to_string().cyan()
            );
        }
    }

    if stats.tls_stats.total_tls_scans > 0 {
        println!("\n{}", "TLS CERTIFICATE ANALYSIS".bold().cyan());
        println!("{}", "─".repeat(50).bright_black());
        println!(
            "TLS Scans:         {}",
            stats.tls_stats.total_tls_scans.to_string().bold()
        );
        println!(
            "Certs with Issues: {} ({:.1}%)",
            stats
                .tls_stats
                .certificates_with_issues
                .to_string()
                .yellow(),
            stats.tls_stats.certificates_with_issues as f64
                / stats.tls_stats.total_tls_scans as f64
                * 100.0
        );

        if !stats.tls_stats.expiring_certificates.is_empty() {
            println!(
                "Expiring Soon:     {}",
                stats
                    .tls_stats
                    .expiring_certificates
                    .len()
                    .to_string()
                    .red()
            );
        }
    }

    println!("{}", "═".repeat(100).bright_black());
}

fn display_stats_json(stats: &DatabaseStats) -> Result<()> {
    let json = serde_json::to_string_pretty(stats)?;
    println!("{}", json);
    Ok(())
}

fn display_stats_csv(_stats: &DatabaseStats) {
    println!("metric,value");
    println!("total_scans,{}", _stats.scan_summary.total_scans);
    println!("successful_scans,{}", _stats.scan_summary.successful_scans);
    println!("failed_scans,{}", _stats.scan_summary.failed_scans);
    println!("unique_urls,{}", _stats.scan_summary.unique_urls);
    println!(
        "total_security_findings,{}",
        _stats.security_stats.total_findings
    );
    println!(
        "urls_with_critical_issues,{}",
        _stats.security_stats.urls_with_critical_issues
    );
    println!(
        "average_response_time_ms,{:.2}",
        _stats.performance_stats.average_response_time
    );
    println!("total_tls_scans,{}", _stats.tls_stats.total_tls_scans);
    println!(
        "certificates_with_issues,{}",
        _stats.tls_stats.certificates_with_issues
    );
}

fn save_stats_output(stats: &DatabaseStats, path: &PathBuf, format: &str) -> Result<()> {
    let content = match format.to_lowercase().as_str() {
        "json" => serde_json::to_string_pretty(stats)?,
        "csv" => {
            let mut csv = String::from("metric,value\n");
            csv.push_str(&format!("total_scans,{}\n", stats.scan_summary.total_scans));
            csv.push_str(&format!(
                "successful_scans,{}\n",
                stats.scan_summary.successful_scans
            ));
            csv.push_str(&format!(
                "failed_scans,{}\n",
                stats.scan_summary.failed_scans
            ));
            csv.push_str(&format!("unique_urls,{}\n", stats.scan_summary.unique_urls));
            csv
        }
        _ => {
            format!("Database Statistics Report\nGenerated: {}\n\nTotal Scans: {}\nSuccessful: {}\nFailed: {}\nUnique URLs: {}\n",
                Utc::now().format("%Y-%m-%d %H:%M:%S UTC"),
                stats.scan_summary.total_scans,
                stats.scan_summary.successful_scans,
                stats.scan_summary.failed_scans,
                stats.scan_summary.unique_urls
            )
        }
    };

    std::fs::write(path, content)?;
    Ok(())
}

use serde::Serialize;

#[derive(Serialize)]
struct SerializableStats {
    database_info: HashMap<String, u64>,
    scan_summary: SerializableScanSummary,
    url_stats: SerializableUrlStats,
    technology_stats: SerializableTechnologyStats,
    security_stats: SerializableSecurityStats,
    temporal_stats: SerializableTemporalStats,
    performance_stats: SerializablePerformanceStats,
    tls_stats: SerializableTlsStats,
}

#[derive(Serialize)]
struct SerializableScanSummary {
    total_scans: usize,
    successful_scans: usize,
    failed_scans: usize,
    unique_urls: usize,
    date_range: Option<(String, String)>,
}

#[derive(Serialize)]
struct SerializableUrlStats {
    most_scanned_urls: Vec<(String, usize)>,
    unique_domains: usize,
}

#[derive(Serialize)]
struct SerializableTechnologyStats {
    total_detections: usize,
    unique_technologies: usize,
    technology_frequency: Vec<(String, usize)>,
}

#[derive(Serialize)]
struct SerializableSecurityStats {
    total_findings: usize,
    findings_by_severity: HashMap<String, usize>,
    findings_by_category: HashMap<String, usize>,
    urls_with_critical_issues: usize,
    most_vulnerable_urls: Vec<(String, usize)>,
}

#[derive(Serialize)]
struct SerializableTemporalStats {
    scans_by_day: HashMap<String, usize>,
    scans_by_hour: HashMap<u32, usize>,
    average_scans_per_day: f64,
    busiest_day: Option<(String, usize)>,
    busiest_hour: Option<(u32, usize)>,
}

#[derive(Serialize)]
struct SerializablePerformanceStats {
    average_response_time: f64,
    median_response_time: f64,
    slowest_responses: Vec<(String, u64)>,
    response_time_distribution: HashMap<String, usize>,
}

#[derive(Serialize)]
struct SerializableTlsStats {
    total_tls_scans: usize,
    certificates_with_issues: usize,
    expiring_certificates: Vec<(String, i64)>,
    common_tls_issues: HashMap<String, usize>,
}

impl serde::Serialize for DatabaseStats {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let serializable = SerializableStats {
            database_info: self.database_info.clone(),
            scan_summary: SerializableScanSummary {
                total_scans: self.scan_summary.total_scans,
                successful_scans: self.scan_summary.successful_scans,
                failed_scans: self.scan_summary.failed_scans,
                unique_urls: self.scan_summary.unique_urls,
                date_range: self
                    .scan_summary
                    .date_range
                    .map(|(start, end)| (start.to_rfc3339(), end.to_rfc3339())),
            },
            url_stats: SerializableUrlStats {
                most_scanned_urls: self.url_stats.most_scanned_urls.clone(),
                unique_domains: self.url_stats.unique_domains,
            },
            technology_stats: SerializableTechnologyStats {
                total_detections: self.technology_stats.total_detections,
                unique_technologies: self.technology_stats.unique_technologies,
                technology_frequency: self.technology_stats.technology_frequency.clone(),
            },
            security_stats: SerializableSecurityStats {
                total_findings: self.security_stats.total_findings,
                findings_by_severity: self.security_stats.findings_by_severity.clone(),
                findings_by_category: self.security_stats.findings_by_category.clone(),
                urls_with_critical_issues: self.security_stats.urls_with_critical_issues,
                most_vulnerable_urls: self.security_stats.most_vulnerable_urls.clone(),
            },
            temporal_stats: SerializableTemporalStats {
                scans_by_day: self.temporal_stats.scans_by_day.clone(),
                scans_by_hour: self.temporal_stats.scans_by_hour.clone(),
                average_scans_per_day: self.temporal_stats.average_scans_per_day,
                busiest_day: self.temporal_stats.busiest_day.clone(),
                busiest_hour: self.temporal_stats.busiest_hour,
            },
            performance_stats: SerializablePerformanceStats {
                average_response_time: self.performance_stats.average_response_time,
                median_response_time: self.performance_stats.median_response_time,
                slowest_responses: self.performance_stats.slowest_responses.clone(),
                response_time_distribution: self
                    .performance_stats
                    .response_time_distribution
                    .clone(),
            },
            tls_stats: SerializableTlsStats {
                total_tls_scans: self.tls_stats.total_tls_scans,
                certificates_with_issues: self.tls_stats.certificates_with_issues,
                expiring_certificates: self.tls_stats.expiring_certificates.clone(),
                common_tls_issues: self.tls_stats.common_tls_issues.clone(),
            },
        };

        serializable.serialize(serializer)
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

    fn create_test_scan() -> ScanRecord {
        ScanRecord {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
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
    fn test_parse_time_range() {
        assert!(parse_time_range(&Some("7d".to_string())).is_some());
        assert!(parse_time_range(&Some("30d".to_string())).is_some());
        assert!(parse_time_range(&Some("all".to_string())).is_none());
        assert!(parse_time_range(&None).is_none());
    }

    #[test]
    fn test_calculate_scan_summary() {
        let scans = vec![create_test_scan(), {
            let mut scan = create_test_scan();
            scan.status = "Failed".to_string();
            scan
        }];

        let summary = calculate_scan_summary(&scans);
        assert_eq!(summary.total_scans, 2);
        assert_eq!(summary.successful_scans, 1);
        assert_eq!(summary.failed_scans, 1);
    }
}
