// File: output.rs
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023-2025
// - Volker Schwaberow <volker@schwaberow.de>

use anyhow::Result;
use std::path::PathBuf;

use super::{print_error, print_info, print_success};
use crate::cli::OutputArgs;
use crate::reports::{ReportConfig, ReportEngine, Theme};
use crate::storage::{HistoryDatabase, HistoryQuery};

pub async fn execute(args: &OutputArgs, db: &HistoryDatabase) -> Result<()> {
    print_info(&format!(
        "Generating {} report with {} theme",
        args.format, args.theme
    ));

    let query = build_query(args)?;
    let scans = db.query_scans(&query)?;

    if scans.is_empty() {
        print_error("No scan data found matching the specified criteria");
        return Ok(());
    }

    print_info(&format!(
        "Found {} scan records to include in report",
        scans.len()
    ));

    let engine = ReportEngine::new();
    let mut report_data = engine.create_report_data(scans);

    if let Some(ref pattern) = args.url_pattern {
        report_data.title = format!("Security Scan Report - {}", pattern);
    }

    if args.aggregate {
        report_data.title = format!("{} (Aggregated)", report_data.title);
        report_data.description =
            Some("This report contains aggregated data from multiple scans".to_string());
    }

    let theme = match args.theme.to_lowercase().as_str() {
        "dark" => Theme::Dark,
        "light" => Theme::Light,
        "auto" => Theme::Auto,
        _ => Theme::Light,
    };

    let config = ReportConfig {
        theme,
        include_raw_data: true,
        aggregate_duplicates: args.aggregate,
        sort_by: crate::reports::SortBy::Timestamp,
        group_by: None,
        filters: crate::reports::ReportFilters::default(),
    };

    let output_path = determine_output_path(args, &args.format)?;
    let content =
        engine.generate_report(&args.format, &report_data, &config, Some(&output_path))?;

    let file_size = content.len();
    print_success(&format!(
        "Report generated successfully: {} ({} bytes)",
        output_path.display(),
        file_size
    ));

    if args.format.to_lowercase() == "html" {
        print_info("Open the HTML file in a web browser to view the interactive report");
        print_info("The report includes theme switching and responsive design");
    }

    Ok(())
}

fn build_query(args: &OutputArgs) -> Result<HistoryQuery> {
    let mut query = HistoryQuery::default();

    if let Some(ref pattern) = args.url_pattern {
        query.url_pattern = Some(pattern.clone());
    }

    query.start_date = args.parse_start_date();
    query.end_date = args.parse_end_date();
    query.min_severity = args.parse_min_severity();
    query.has_detections = args.has_detections;
    query.has_tls_issues = args.has_tls_issues;
    query.has_desync_findings = args.has_desync_findings;
    query.status_codes = args.parse_status_codes();
    query.limit = Some(args.limit);

    Ok(query)
}

fn determine_output_path(args: &OutputArgs, format: &str) -> Result<PathBuf> {
    if let Some(ref path) = args.output {
        return Ok(path.clone());
    }

    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
    let extension = match format.to_lowercase().as_str() {
        "html" => "html",
        "json" => "json",
        "xml" => "xml",
        "text" | "txt" => "txt",
        "markdown" | "md" => "md",
        "csv" => "csv",
        _ => "txt",
    };

    let filename = if let Some(ref pattern) = args.url_pattern {
        let safe_pattern = pattern.replace(['/', ':', '?', '&'], "_");
        format!(
            "rprobe_report_{}_{}_{}.{}",
            safe_pattern, format, timestamp, extension
        )
    } else {
        format!("rprobe_report_{}_{}.{}", format, timestamp, extension)
    };

    Ok(PathBuf::from(filename))
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

    #[tokio::test]
    async fn test_build_query() {
        let args = OutputArgs {
            format: "html".to_string(),
            output: None,
            theme: "light".to_string(),
            url_pattern: Some("example.com".to_string()),
            start_date: Some("2024-01-01".to_string()),
            end_date: None,
            min_severity: Some("high".to_string()),
            has_detections: Some(true),
            has_tls_issues: None,
            has_desync_findings: None,
            status_codes: Some("200,404".to_string()),
            limit: 100,
            aggregate: false,
            template: None,
        };

        let query = build_query(&args).unwrap();
        assert_eq!(query.url_pattern, Some("example.com".to_string()));
        assert!(query.start_date.is_some());
        assert_eq!(query.has_detections, Some(true));
        assert_eq!(
            query.status_codes,
            Some(vec!["200".to_string(), "404".to_string()])
        );
    }

    #[test]
    fn test_determine_output_path() {
        let args = OutputArgs {
            format: "html".to_string(),
            output: Some(PathBuf::from("custom_report.html")),
            theme: "light".to_string(),
            url_pattern: None,
            start_date: None,
            end_date: None,
            min_severity: None,
            has_detections: None,
            has_tls_issues: None,
            has_desync_findings: None,
            status_codes: None,
            limit: 100,
            aggregate: false,
            template: None,
        };

        let path = determine_output_path(&args, "html").unwrap();
        assert_eq!(path, PathBuf::from("custom_report.html"));

        let args_auto = OutputArgs {
            format: "json".to_string(),
            output: None,
            theme: "light".to_string(),
            url_pattern: Some("https://example.com".to_string()),
            start_date: None,
            end_date: None,
            min_severity: None,
            has_detections: None,
            has_tls_issues: None,
            has_desync_findings: None,
            status_codes: None,
            limit: 100,
            aggregate: false,
            template: None,
        };

        let path_auto = determine_output_path(&args_auto, "json").unwrap();
        let path_str = path_auto.to_string_lossy();
        assert!(path_str.contains("https___example.com"));
        assert!(path_str.ends_with(".json"));
    }
}
