// File: main.rs
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023-2025
// - Volker Schwaberow <volker@schwaberow.de>

#![allow(clippy::uninlined_format_args)]
#![allow(clippy::module_inception)]
#![allow(clippy::bool_assert_comparison)]
#![allow(clippy::useless_vec)]
#![allow(dead_code)]

mod cli;
mod commands;
mod config;
mod content_analyzer;
mod desync_cli;
mod desync_scanner;
mod getstate;
mod http;
mod httpinner;
mod plugins;
mod report;
mod reports;
mod screenshot;
mod storage;
mod tls_analyzer;

use chrono::{DateTime, TimeZone, Utc};
use clap::Parser;
use colored::*;
use config::ConfigParameter;
use content_analyzer::{ContentAnalyzer, ContentFinding, FindingSeverity};
use getstate::GetState;
use http::Http;
use log::{error, info, LevelFilter};
use report::ReportEntry;
use std::collections::HashMap;
use std::env;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, IsTerminal, Write};
use std::num::NonZeroU32;
use std::path::Path;
use std::sync::Arc;
use tls_analyzer::TlsAnalyzer;
use uuid::Uuid;

use cli::{is_legacy_mode, merge_legacy_args, Cli, Commands};
use commands::{
    handle_clean_command, handle_compare_command, handle_history_command, handle_output_command,
    handle_stats_command,
};
use storage::{HistoryDatabase, ScanRecord, ScanSession};

#[derive(Debug, Clone)]
struct EnhancedReportEntry {
    url: String,
    status: String,
    detections: Vec<String>,
    content_findings: Vec<ContentFinding>,
    tls_info: HashMap<String, String>,
}

impl From<EnhancedReportEntry> for ReportEntry {
    fn from(entry: EnhancedReportEntry) -> Self {
        ReportEntry {
            url: entry.url,
            status: entry.status,
            detections: entry.detections,
        }
    }
}

fn get_human_readable_time(time: u64) -> DateTime<Utc> {
    match Utc.timestamp_opt((time / 1000) as i64, 0) {
        chrono::LocalResult::Single(dt) => dt,
        _ => panic!("Invalid timestamp"),
    }
}

fn get_targets(input_file: Option<String>) -> Arc<Vec<String>> {
    match input_file {
        Some(filename) => {
            let file = File::open(&filename).unwrap_or_else(|e| {
                eprintln!("Error opening input file {}: {}", filename, e);
                std::process::exit(1);
            });
            let reader = BufReader::new(file);
            let lines: Vec<String> = reader.lines().map_while(Result::ok).collect();
            Arc::new(lines)
        }
        None => {
            let stdin = io::stdin();
            let lines: Vec<String> = stdin.lock().lines().map_while(Result::ok).collect();
            Arc::new(lines)
        }
    }
}

fn check_for_input(input_file: Option<&String>) {
    if input_file.is_none() && io::stdin().is_terminal() {
        println!("No input detected. Please provide URLs via stdin or use --input-file.");
        std::process::exit(1);
    }
}

fn get_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn configure_logging(level: &str, verbose: bool, quiet: bool) -> Result<(), log::SetLoggerError> {
    let level = if quiet {
        LevelFilter::Error
    } else if verbose {
        LevelFilter::Info
    } else {
        match level.to_lowercase().as_str() {
            "error" => LevelFilter::Error,
            "warn" => LevelFilter::Warn,
            "info" => LevelFilter::Info,
            "debug" => LevelFilter::Debug,
            "trace" => LevelFilter::Trace,
            _ => LevelFilter::Warn,
        }
    };

    simple_logger::SimpleLogger::new().with_level(level).init()
}

fn load_state(resume_file: &str) -> Option<(Vec<String>, Vec<String>)> {
    match fs::read_to_string(resume_file) {
        Ok(content) => {
            let lines: Vec<&str> = content.lines().collect();
            if lines.len() >= 2 {
                let completed: Vec<String> = lines[0].split(',').map(String::from).collect();
                let pending: Vec<String> = lines[1].split(',').map(String::from).collect();
                Some((completed, pending))
            } else {
                None
            }
        }
        Err(_) => None,
    }
}

fn save_state(resume_file: &str, completed: &[String], pending: &[String]) -> io::Result<()> {
    let mut file = File::create(resume_file)?;
    writeln!(file, "{}", completed.join(","))?;
    writeln!(file, "{}", pending.join(","))?;
    Ok(())
}

fn print_prg_info() {
    let prg_info = format!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
    let prg_authors = format!("(c) 2022-2025 by {}", env!("CARGO_PKG_AUTHORS"));
    let prg_description = env!("CARGO_PKG_DESCRIPTION").to_string();
    println!("{} {}", prg_info, prg_authors);
    println!("{}", prg_description);
    println!();
}

fn should_show_summary(short: bool, target_count: usize) -> bool {
    if short {
        target_count > 1
    } else {
        true
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cli = Cli::parse();

    if let Err(e) = configure_logging(&cli.log_level, cli.verbose, cli.quiet) {
        eprintln!("Failed to configure logging: {}", e);
    }

    let db = if !cli.no_store_history || !is_legacy_mode(&cli) {
        Some(HistoryDatabase::new(cli.data_dir.clone())?)
    } else {
        None
    };

    match &cli.command {
        Some(Commands::Scan(args)) => {
            check_for_input(cli.input_file.as_ref());
            return run_scan_command(&cli, args, db.as_ref()).await;
        }
        Some(Commands::Output(args)) => {
            let database =
                db.ok_or_else(|| anyhow::anyhow!("Database not initialized for output command"))?;
            return handle_output_command(args, &database)
                .await
                .map_err(Into::into);
        }
        Some(Commands::History(args)) => {
            let database =
                db.ok_or_else(|| anyhow::anyhow!("Database not initialized for history command"))?;
            return handle_history_command(args, &database)
                .await
                .map_err(Into::into);
        }
        Some(Commands::Compare(args)) => {
            let database =
                db.ok_or_else(|| anyhow::anyhow!("Database not initialized for compare command"))?;
            return handle_compare_command(args, &database)
                .await
                .map_err(Into::into);
        }
        Some(Commands::Clean(args)) => {
            let database =
                db.ok_or_else(|| anyhow::anyhow!("Database not initialized for clean command"))?;
            return handle_clean_command(args, &database)
                .await
                .map_err(Into::into);
        }
        Some(Commands::Stats(args)) => {
            let database =
                db.ok_or_else(|| anyhow::anyhow!("Database not initialized for stats command"))?;
            return handle_stats_command(args, &database)
                .await
                .map_err(Into::into);
        }
        None => {
            check_for_input(cli.input_file.as_ref());
            let legacy_args = merge_legacy_args(&cli);
            return run_scan_command(&cli, &legacy_args, db.as_ref()).await;
        }
    }
}

async fn run_scan_command(
    cli: &Cli,
    scan_args: &cli::ScanArgs,
    db: Option<&HistoryDatabase>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let session_id = Uuid::new_v4().to_string();
    let session_start_time = Utc::now();

    let state = Arc::new(GetState::new());
    let mut config_state = ConfigParameter::new();

    config_state.set_timeout(cli.timeout);
    config_state.set_http(!cli.nohttp);
    config_state.set_https(!cli.nohttps);
    config_state.set_print_failed(cli.show_unresponsive);
    config_state.set_suppress_stats(cli.suppress_stats);
    config_state.set_detect_all(scan_args.detect_all);
    config_state.set_download_robots(scan_args.download_robots);
    config_state.set_screenshot(scan_args.screenshot);
    config_state.set_workers(cli.workers);
    config_state.set_output_dir(cli.output_dir.clone());

    if let Err(err) = fs::create_dir_all(&cli.output_dir) {
        error!(
            "Failed to create output directory {}: {}",
            cli.output_dir, err
        );
        std::process::exit(1);
    }

    if scan_args.list_plugins {
        let plugins = plugins::PluginHandler::new();
        let plugin_list = plugins.list_detailed();
        println!("Available plugins:");
        for plugin_meta in plugin_list {
            println!(
                "  {} (v{}) - {} [{:?}]",
                plugin_meta.name,
                plugin_meta.version,
                plugin_meta.description,
                plugin_meta.category
            );
        }
        std::process::exit(0);
    }

    if scan_args.desync {
        use desync_cli::{run_desync_scan, DesyncArgs};

        println!(
            "{}",
            "DEF CON HTTP-Must-Die Desync Scanner Mode"
                .bright_red()
                .bold()
        );

        let desync_args = DesyncArgs {
            input_file: cli.input_file.clone(),
            target_url: scan_args.desync_target.clone(),
            output_dir: format!("{}/desync", cli.output_dir),
            output_format: "jsonl".to_string(),
            safe_mode: scan_args.desync_safe_mode,
            connect_timeout: cli.timeout * 100,
            read_timeout: (cli.timeout + 5) * 100,
            concurrency: cli.workers.min(8) as usize,
            rate_limit: cli.rate_limit.min(60),
            canary_prefix: "rpd".to_string(),
            collaborator_url: None,
            max_targets: 1000,
            verbose: false,
            min_severity: "low".to_string(),
            skip_tests: None,
            skip_authorization_check: scan_args.i_have_authorization,
            enable_timing_analysis: false,
            timing_samples: 3,
            timing_threshold_ms: 500,
            enable_advanced_chunking: false,
            enable_h2_downgrade_tests: false,
            enable_cache_probing: false,
            max_connections_per_host: 3,
        };

        run_desync_scan(desync_args).await?;

        if let Some(_database) = db {
            println!("{}", "💾 Storing desync scan results...".blue());
        }

        return Ok(());
    }

    if !config_state.http() && !config_state.https() {
        println!("Error: You can't use -n and -N at the same time");
        println!();
        print_prg_info();
        std::process::exit(1);
    }

    let rate_limit =
        NonZeroU32::new(cli.rate_limit).unwrap_or_else(|| NonZeroU32::new(10).unwrap());

    state.set_start_time(get_now());

    let (completed_targets, mut targets_to_scan) = if let Some(resume_path) = &scan_args.resume_file
    {
        if Path::new(resume_path).exists() {
            if let Some((completed, pending)) = load_state(resume_path) {
                info!(
                    "Resuming scan: {} completed targets, {} pending targets",
                    completed.len(),
                    pending.len()
                );
                (completed, pending)
            } else {
                (Vec::new(), get_targets(cli.input_file.clone()).to_vec())
            }
        } else {
            (Vec::new(), get_targets(cli.input_file.clone()).to_vec())
        }
    } else {
        (Vec::new(), get_targets(cli.input_file.clone()).to_vec())
    };

    state.set_total_requests(targets_to_scan.len() as u64);

    let mut http = Http::new(Arc::clone(&state), config_state.clone(), rate_limit);
    let results = http.work(Arc::new(targets_to_scan.clone())).await;

    let mut new_completed = completed_targets.clone();
    for result in &results {
        if result.success() {
            new_completed.push(result.url().to_string());
        }
    }
    targets_to_scan.retain(|target| !new_completed.contains(target));

    if let Some(resume_path) = &scan_args.resume_file {
        if let Err(e) = save_state(resume_path, &new_completed, &targets_to_scan) {
            error!("Failed to save scan state: {}", e);
        } else {
            info!("Scan state saved to {}", resume_path);
        }
    }

    state.set_end_time(get_now());

    let mut enhanced_report_entries: Vec<EnhancedReportEntry> = Vec::new();
    let mut scan_records_batch: Vec<storage::ScanRecord> = Vec::new();

    for r in &results {
        let url = r.url().to_string();
        let detections = if r.success() {
            let mut plugins = plugins::PluginHandler::new();
            if config_state.detect_all() {
                let plugin_results = plugins.run(r);
                plugin_results
                    .into_iter()
                    .map(|result| format!("{}: {}", result.plugin_name, result.detection_info))
                    .collect::<Vec<_>>()
            } else if let Some(plugin_name) = &scan_args.plugin {
                if let Some(result) = plugins.run_plugin(plugin_name, r) {
                    vec![format!("{}: {}", result.plugin_name, result.detection_info)]
                } else {
                    vec![]
                }
            } else {
                vec![]
            }
        } else {
            vec![]
        };

        let content_findings = if scan_args.content_analysis && r.success() {
            let mut findings = ContentAnalyzer::analyze(r);
            findings.extend(ContentAnalyzer::analyze_forms(r));
            findings.extend(ContentAnalyzer::analyze_javascript(r));
            findings
        } else {
            Vec::new()
        };

        let tls_info = if (scan_args.tls_analysis || scan_args.comprehensive_tls)
            && r.success()
            && r.url().starts_with("https://")
        {
            if scan_args.comprehensive_tls {
                match TlsAnalyzer::comprehensive_assessment(r.url()).await {
                    Ok(info) => info,
                    Err(e) => {
                        let mut error_map = HashMap::new();
                        error_map.insert("error".to_string(), e.to_string());
                        error_map
                    }
                }
            } else {
                match TlsAnalyzer::analyze(r.url()).await {
                    Ok(cert) => {
                        let mut map = HashMap::new();
                        map.insert("subject".to_string(), cert.subject);
                        map.insert("issuer".to_string(), cert.issuer);
                        map.insert("valid_from".to_string(), cert.valid_from.to_string());
                        map.insert("valid_to".to_string(), cert.valid_to.to_string());
                        map.insert(
                            "days_until_expiry".to_string(),
                            cert.days_until_expiry.to_string(),
                        );

                        if !cert.warnings.is_empty() {
                            map.insert("warnings".to_string(), cert.warnings.join(", "));
                        }

                        if !cert.errors.is_empty() {
                            map.insert("errors".to_string(), cert.errors.join(", "));
                        }

                        map
                    }
                    Err(e) => {
                        let mut error_map = HashMap::new();
                        error_map.insert("error".to_string(), e.to_string());
                        error_map
                    }
                }
            }
        } else {
            HashMap::new()
        };

        let enhanced_entry = EnhancedReportEntry {
            url: url.clone(),
            status: r.status().to_string(),
            detections: detections.clone(),
            content_findings: content_findings.clone(),
            tls_info: tls_info.clone(),
        };

        enhanced_report_entries.push(enhanced_entry.clone());

        if let Some(_database) = db {
            if !cli.no_store_history || scan_args.force_store {
                let scan_record = ScanRecord {
                    id: Uuid::new_v4().to_string(),
                    timestamp: Utc::now(),
                    url: url.clone(),
                    status: r.status().to_string(),
                    detections: detections.clone(),
                    content_findings: content_findings.clone(),
                    tls_info: tls_info.clone(),
                    response_time_ms: r.response_time_ms(),
                    response_headers: r
                        .headers()
                        .iter()
                        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                        .collect(),
                    content_length: Some(r.body().len() as u64),
                    desync_results: vec![],
                    screenshot_path: r.screenshot_path().cloned(),
                    robots_txt_content: None,
                    scan_config: storage::ScanConfig {
                        timeout: cli.timeout,
                        http: !cli.nohttp,
                        https: !cli.nohttps,
                        detect_all: scan_args.detect_all,
                        content_analysis: scan_args.content_analysis,
                        tls_analysis: scan_args.tls_analysis,
                        comprehensive_tls: scan_args.comprehensive_tls,
                        screenshot: scan_args.screenshot,
                        download_robots: scan_args.download_robots,
                        desync: scan_args.desync,
                        plugin_name: scan_args.plugin.clone(),
                    },
                };
                scan_records_batch.push(scan_record);
            }
        }
    }

    enhanced_report_entries.sort_by(|a, b| a.url.cmp(&b.url));

    if let Some(database) = db {
        if ((!cli.no_store_history) || scan_args.force_store) && !scan_records_batch.is_empty() {
            println!(
                "{} {} scan records...",
                "💾 Storing".blue(),
                scan_records_batch.len().to_string().bold()
            );
            if let Err(e) = database.store_scans_batch(&scan_records_batch) {
                error!("Failed to store scan batch: {}", e);
            } else {
                println!("{} Scan records stored successfully", "✓".green());
            }
        }
    }

    let use_compact_mode = scan_args.short || scan_args.compact;

    for entry in &enhanced_report_entries {
        if entry.status != "Failed" {
            if use_compact_mode {
                let status_colored = match entry.status.parse::<u16>() {
                    Ok(code) => match code {
                        200..=299 => format!("[OK] {}", entry.status).green().bold(),
                        300..=399 => format!("[>>] {}", entry.status).yellow().bold(),
                        400..=499 => format!("[ERR] {}", entry.status).red().bold(),
                        500..=599 => format!("[!] {}", entry.status).red().bold(),
                        _ => format!("? {}", entry.status).white(),
                    },
                    Err(_) => format!("? {}", entry.status).white(),
                };

                let tech_list = if !entry.detections.is_empty() {
                    format!(" [{}]", entry.detections.join(", "))
                } else {
                    String::new()
                };

                println!(
                    "{} {}{}",
                    entry.url.cyan(),
                    status_colored,
                    tech_list.bright_blue()
                );
            } else {
                println!();
                println!("{}", "─".repeat(80).bright_black());
                println!("{}", entry.url.bold().cyan());

                let status_colored = match entry.status.parse::<u16>() {
                    Ok(code) => match code {
                        200..=299 => format!("[OK] {}", entry.status).green().bold(),
                        300..=399 => format!("[>>] {}", entry.status).yellow().bold(),
                        400..=499 => format!("[ERR] {}", entry.status).red().bold(),
                        500..=599 => format!("[!] {}", entry.status).red().bold(),
                        _ => format!("? {}", entry.status).white(),
                    },
                    Err(_) => format!("? {}", entry.status).white(),
                };
                println!("Status: {}", status_colored);

                if !entry.detections.is_empty() {
                    println!("Technologies:");
                    for detection in &entry.detections {
                        if let Some((name, description)) = detection.split_once(": ") {
                            println!("  {} {}", ">".bright_blue(), name.bold());
                            println!("    {}", description.dimmed());
                        } else {
                            println!("  {} {}", ">".bright_blue(), detection.bold());
                        }
                    }
                }

                if scan_args.content_analysis && !entry.content_findings.is_empty() {
                    let important_findings: Vec<&ContentFinding> = entry
                        .content_findings
                        .iter()
                        .filter(|f| {
                            f.severity == FindingSeverity::High
                                || f.severity == FindingSeverity::Critical
                        })
                        .collect();

                    if !important_findings.is_empty() {
                        println!("Security Findings:");
                        for finding in &important_findings {
                            let (severity_icon, severity_str) = match finding.severity {
                                FindingSeverity::Critical => ("[!]", "CRITICAL".red().bold()),
                                FindingSeverity::High => ("[!]", "HIGH".yellow().bold()),
                                _ => ("[i]", "INFO".blue()),
                            };

                            println!(
                                "  {} {} {}: {}",
                                severity_icon,
                                severity_str,
                                finding.category.bold(),
                                finding.description
                            );
                        }
                    }
                }

                if (scan_args.tls_analysis || scan_args.comprehensive_tls)
                    && !entry.tls_info.is_empty()
                {
                    if let Some(warnings) = entry.tls_info.get("warnings") {
                        println!("TLS Warnings:");
                        println!("  {} {}", "[!]".yellow(), warnings.yellow());
                    }

                    if let Some(errors) = entry.tls_info.get("errors") {
                        println!("TLS Errors:");
                        println!("  {} {}", "[X]".red(), errors.red().bold());
                    }
                }
            }
        } else if config_state.print_failed() {
            if use_compact_mode {
                println!(
                    "{} {}",
                    entry.url.red(),
                    "[X] Failed to connect".red().bold()
                );
            } else {
                println!();
                println!("{}", "─".repeat(80).bright_black());
                println!("{}", entry.url.red());
                println!("Status: {}", "[X] Failed to connect".red().bold());
            }
        }
    }

    let target_count = state.total_requests() as usize;
    let display_summary =
        should_show_summary(scan_args.short, target_count) && !config_state.suppress_stats();

    if display_summary {
        println!();
        println!("{}", "═".repeat(80).bright_black());
        println!("{}", "SCAN SUMMARY".bold().bright_white());
        println!("{}", "═".repeat(80).bright_black());

        let duration_ms = state.end_time() - state.start_time();
        let duration_formatted = if duration_ms >= 60000 {
            format!(
                "{:.1}m {:.1}s",
                duration_ms as f64 / 60000.0,
                (duration_ms % 60000) as f64 / 1000.0
            )
        } else if duration_ms >= 1000 {
            format!("{:.2}s", duration_ms as f64 / 1000.0)
        } else {
            format!("{}ms", duration_ms)
        };

        println!(
            "[*] Requests:     {} total",
            state.total_requests().to_string().bold()
        );
        println!(
            "[+] Successful:   {}",
            state.successful_requests().to_string().green().bold()
        );
        println!(
            "[-] Failed:       {}",
            state.failed_requests().to_string().red().bold()
        );
        println!("[T] Duration:     {}", duration_formatted.bold());
        println!(
            "[S] Started:      {}",
            get_human_readable_time(state.start_time()).format("%Y-%m-%d %H:%M:%S UTC")
        );
        println!(
            "[E] Ended:        {}",
            get_human_readable_time(state.end_time()).format("%Y-%m-%d %H:%M:%S UTC")
        );

        if scan_args.content_analysis {
            let total_findings: usize = enhanced_report_entries
                .iter()
                .map(|e| e.content_findings.len())
                .sum();

            let critical_findings: usize = enhanced_report_entries
                .iter()
                .flat_map(|e| &e.content_findings)
                .filter(|f| f.severity == FindingSeverity::Critical)
                .count();

            let high_findings: usize = enhanced_report_entries
                .iter()
                .flat_map(|e| &e.content_findings)
                .filter(|f| f.severity == FindingSeverity::High)
                .count();

            println!();
            println!("[?] Content Analysis:");
            println!("   Total findings: {}", total_findings.to_string().bold());
            if critical_findings > 0 {
                println!(
                    "   Critical:       {}",
                    critical_findings.to_string().red().bold()
                );
            }
            if high_findings > 0 {
                println!(
                    "   High severity:  {}",
                    high_findings.to_string().yellow().bold()
                );
            }
        }

        if scan_args.tls_analysis || scan_args.comprehensive_tls {
            let filtered_entries: Vec<_> = enhanced_report_entries
                .iter()
                .filter(|e| {
                    e.tls_info.contains_key("warnings") || e.tls_info.contains_key("errors")
                })
                .collect();
            let sites_with_tls_issues = filtered_entries.len();

            println!();
            println!("[TLS] TLS Analysis:");
            if sites_with_tls_issues > 0 {
                println!(
                    "   Sites with issues: {}",
                    sites_with_tls_issues.to_string().yellow().bold()
                );
            } else {
                println!("   No certificate issues found");
            }
        }

        let all_technologies: std::collections::BTreeSet<String> = enhanced_report_entries
            .iter()
            .flat_map(|entry| &entry.detections)
            .map(|detection| {
                if let Some((name, _)) = detection.split_once(": ") {
                    name.to_string()
                } else {
                    detection.clone()
                }
            })
            .collect();

        if !all_technologies.is_empty() && state.successful_requests() > 0 {
            println!();
            println!("[TECH] Comprehensive Detection Summary:");
            println!(
                "       {} unique technologies detected: {}",
                all_technologies.len().to_string().bold(),
                all_technologies
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
                    .bright_cyan()
            );
        }

        println!("{}", "═".repeat(80).bright_black());
    }

    if let Some(database) = db {
        if !cli.no_store_history || scan_args.force_store {
            println!("{}", "📊 Storing scan session summary...".green());
            let session_end_time = Utc::now();
            let session = ScanSession {
                id: session_id,
                timestamp: session_start_time,
                total_urls: results.len(),
                successful_scans: results.iter().filter(|r| r.success()).count(),
                failed_scans: results.iter().filter(|r| !r.success()).count(),
                duration_ms: (session_end_time - session_start_time).num_milliseconds() as u64,
                config: storage::ScanConfig {
                    timeout: cli.timeout,
                    http: !cli.nohttp,
                    https: !cli.nohttps,
                    detect_all: scan_args.detect_all,
                    content_analysis: scan_args.content_analysis,
                    tls_analysis: scan_args.tls_analysis,
                    comprehensive_tls: scan_args.comprehensive_tls,
                    screenshot: scan_args.screenshot,
                    download_robots: scan_args.download_robots,
                    desync: scan_args.desync,
                    plugin_name: scan_args.plugin.clone(),
                },
            };

            if let Err(e) = database.store_session(&session) {
                error!("Failed to store scan session: {}", e);
            } else {
                println!(
                    "{} Session stored with ID: {}",
                    "✓".green(),
                    session.id.bright_cyan()
                );
            }
        }
    }

    Ok(())
}

fn generate_content_analysis_report(
    entries: &[EnhancedReportEntry],
    output_dir: &str,
) -> io::Result<()> {
    let content_dir = format!("{}/content_analysis", output_dir);
    fs::create_dir_all(&content_dir)?;

    let html_path = format!("{}/content_findings.html", content_dir);
    let mut file = File::create(&html_path)?;

    writeln!(file, "<!DOCTYPE html>")?;
    writeln!(file, "<html lang=\"en\">")?;
    writeln!(file, "<head>")?;
    writeln!(file, "  <meta charset=\"UTF-8\">")?;
    writeln!(
        file,
        "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">"
    )?;
    writeln!(file, "  <title>Content Analysis Report</title>")?;
    writeln!(file, "  <style>")?;
    writeln!(
        file,
        "    body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; }}"
    )?;
    writeln!(
        file,
        "    .container {{ max-width: 1200px; margin: 0 auto; }}"
    )?;
    writeln!(file, "    h1, h2, h3 {{ color: #333; }}")?;
    writeln!(file, "    .summary {{ background-color: #f5f5f5; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}")?;
    writeln!(file, "    .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; }}")?;
    writeln!(file, "    .summary-item {{ background-color: #fff; padding: 10px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}")?;
    writeln!(
        file,
        "    .stat-number {{ font-size: 24px; font-weight: bold; }}"
    )?;
    writeln!(file, "    .stat-label {{ color: #666; }}")?;
    writeln!(file, "    .site {{ margin-bottom: 30px; border: 1px solid #ddd; border-radius: 5px; padding: 15px; }}")?;
    writeln!(file, "    .site h3 {{ margin-top: 0; }}")?;
    writeln!(
        file,
        "    .finding {{ margin-bottom: 15px; padding: 10px; border-left: 5px solid #ddd; }}"
    )?;
    writeln!(
        file,
        "    .critical {{ border-color: #dc3545; background-color: #f8d7da; }}"
    )?;
    writeln!(
        file,
        "    .high {{ border-color: #fd7e14; background-color: #fff3cd; }}"
    )?;
    writeln!(
        file,
        "    .medium {{ border-color: #ffc107; background-color: #fff3cd; }}"
    )?;
    writeln!(
        file,
        "    .low {{ border-color: #0dcaf0; background-color: #d1ecf1; }}"
    )?;
    writeln!(
        file,
        "    .info {{ border-color: #6c757d; background-color: #e2e3e5; }}"
    )?;
    writeln!(
        file,
        "    .finding-header {{ display: flex; justify-content: space-between; }}"
    )?;
    writeln!(file, "    .severity {{ font-weight: bold; }}")?;
    writeln!(file, "    .severity.critical {{ color: #dc3545; }}")?;
    writeln!(file, "    .severity.high {{ color: #fd7e14; }}")?;
    writeln!(file, "    .severity.medium {{ color: #ffc107; }}")?;
    writeln!(file, "    .severity.low {{ color: #0dcaf0; }}")?;
    writeln!(file, "    .severity.info {{ color: #6c757d; }}")?;
    writeln!(file, "    .context {{ background-color: #f8f9fa; padding: 10px; border-radius: 3px; font-family: monospace; margin-top: 10px; }}")?;
    writeln!(file, "  </style>")?;
    writeln!(file, "</head>")?;
    writeln!(file, "<body>")?;
    writeln!(file, "  <div class=\"container\">")?;
    writeln!(file, "    <h1>Content Analysis Report</h1>")?;
    writeln!(
        file,
        "    <p>Report generated on: {}</p>",
        chrono::Local::now().format("%Y-%m-%d %H:%M:%S")
    )?;

    let total_sites = entries.len();
    let sites_with_findings = entries
        .iter()
        .filter(|e| !e.content_findings.is_empty())
        .count();

    let total_findings: usize = entries.iter().map(|e| e.content_findings.len()).sum();

    let critical_findings: usize = entries
        .iter()
        .flat_map(|e| &e.content_findings)
        .filter(|f| f.severity == FindingSeverity::Critical)
        .count();

    let high_findings: usize = entries
        .iter()
        .flat_map(|e| &e.content_findings)
        .filter(|f| f.severity == FindingSeverity::High)
        .count();

    let medium_findings: usize = entries
        .iter()
        .flat_map(|e| &e.content_findings)
        .filter(|f| f.severity == FindingSeverity::Medium)
        .count();

    let low_findings: usize = entries
        .iter()
        .flat_map(|e| &e.content_findings)
        .filter(|f| f.severity == FindingSeverity::Low)
        .count();

    let info_findings: usize = entries
        .iter()
        .flat_map(|e| &e.content_findings)
        .filter(|f| f.severity == FindingSeverity::Info)
        .count();

    writeln!(file, "    <div class=\"summary\">")?;
    writeln!(file, "      <h2>Summary</h2>")?;
    writeln!(file, "      <div class=\"summary-grid\">")?;
    writeln!(file, "        <div class=\"summary-item\">")?;
    writeln!(
        file,
        "          <div class=\"stat-number\">{}</div>",
        total_sites
    )?;
    writeln!(
        file,
        "          <div class=\"stat-label\">Total Sites</div>"
    )?;
    writeln!(file, "        </div>")?;
    writeln!(file, "        <div class=\"summary-item\">")?;
    writeln!(
        file,
        "          <div class=\"stat-number\">{}</div>",
        sites_with_findings
    )?;
    writeln!(
        file,
        "          <div class=\"stat-label\">Sites with Findings</div>"
    )?;
    writeln!(file, "        </div>")?;
    writeln!(file, "        <div class=\"summary-item\">")?;
    writeln!(
        file,
        "          <div class=\"stat-number\">{}</div>",
        total_findings
    )?;
    writeln!(
        file,
        "          <div class=\"stat-label\">Total Findings</div>"
    )?;
    writeln!(file, "        </div>")?;
    writeln!(file, "        <div class=\"summary-item\">")?;
    writeln!(
        file,
        "          <div class=\"stat-number\" style=\"color: #dc3545;\">{}</div>",
        critical_findings
    )?;
    writeln!(file, "          <div class=\"stat-label\">Critical</div>")?;
    writeln!(file, "        </div>")?;
    writeln!(file, "        <div class=\"summary-item\">")?;
    writeln!(
        file,
        "          <div class=\"stat-number\" style=\"color: #fd7e14;\">{}</div>",
        high_findings
    )?;
    writeln!(file, "          <div class=\"stat-label\">High</div>")?;
    writeln!(file, "        </div>")?;
    writeln!(file, "        <div class=\"summary-item\">")?;
    writeln!(
        file,
        "          <div class=\"stat-number\" style=\"color: #ffc107;\">{}</div>",
        medium_findings
    )?;
    writeln!(file, "          <div class=\"stat-label\">Medium</div>")?;
    writeln!(file, "        </div>")?;
    writeln!(file, "        <div class=\"summary-item\">")?;
    writeln!(
        file,
        "          <div class=\"stat-number\" style=\"color: #0dcaf0;\">{}</div>",
        low_findings
    )?;
    writeln!(file, "          <div class=\"stat-label\">Low</div>")?;
    writeln!(file, "        </div>")?;
    writeln!(file, "        <div class=\"summary-item\">")?;
    writeln!(
        file,
        "          <div class=\"stat-number\" style=\"color: #6c757d;\">{}</div>",
        info_findings
    )?;
    writeln!(file, "          <div class=\"stat-label\">Info</div>")?;
    writeln!(file, "        </div>")?;
    writeln!(file, "      </div>")?;
    writeln!(file, "    </div>")?;

    writeln!(file, "    <h2>Findings by Site</h2>")?;

    let mut sorted_entries = entries.to_vec();
    sorted_entries.sort_by(|a, b| b.content_findings.len().cmp(&a.content_findings.len()));

    for entry in sorted_entries
        .iter()
        .filter(|e| !e.content_findings.is_empty())
    {
        writeln!(file, "    <div class=\"site\">")?;
        writeln!(file, "      <h3>{}</h3>", entry.url)?;

        let mut critical = Vec::new();
        let mut high = Vec::new();
        let mut medium = Vec::new();
        let mut low = Vec::new();
        let mut info = Vec::new();

        for finding in &entry.content_findings {
            match finding.severity {
                FindingSeverity::Critical => critical.push(finding),
                FindingSeverity::High => high.push(finding),
                FindingSeverity::Medium => medium.push(finding),
                FindingSeverity::Low => low.push(finding),
                FindingSeverity::Info => info.push(finding),
            }
        }

        if !critical.is_empty() {
            write_findings(&mut file, "Critical", "critical", &critical)?;
        }

        if !high.is_empty() {
            write_findings(&mut file, "High", "high", &high)?;
        }

        if !medium.is_empty() {
            write_findings(&mut file, "Medium", "medium", &medium)?;
        }

        if !low.is_empty() {
            write_findings(&mut file, "Low", "low", &low)?;
        }

        if !info.is_empty() {
            write_findings(&mut file, "Info", "info", &info)?;
        }

        writeln!(file, "    </div>")?;
    }

    writeln!(file, "  </div>")?;
    writeln!(file, "</body>")?;
    writeln!(file, "</html>")?;

    let csv_path = format!("{}/content_findings.csv", content_dir);
    let mut csv_file = File::create(&csv_path)?;

    writeln!(
        csv_file,
        "URL,Category,Description,Severity,Matched Text,Context"
    )?;

    for entry in entries {
        for finding in &entry.content_findings {
            let url = entry.url.replace("\"", "\"\"");
            let category = finding.category.replace("\"", "\"\"");
            let description = finding.description.replace("\"", "\"\"");
            let severity = format!("{}", finding.severity);
            let matched_text = finding
                .matched_text
                .as_ref()
                .unwrap_or(&String::new())
                .replace("\"", "\"\"");
            let context = finding
                .context
                .as_ref()
                .unwrap_or(&String::new())
                .replace("\"", "\"\"");

            writeln!(
                csv_file,
                "\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"",
                url, category, description, severity, matched_text, context
            )?;
        }
    }

    Ok(())
}

fn write_findings(
    file: &mut File,
    title: &str,
    class: &str,
    findings: &[&ContentFinding],
) -> io::Result<()> {
    writeln!(
        file,
        "      <h4>{} Severity Findings ({})</h4>",
        title,
        findings.len()
    )?;

    for finding in findings {
        writeln!(file, "      <div class=\"finding {}\">", class)?;
        writeln!(file, "        <div class=\"finding-header\">")?;
        writeln!(
            file,
            "          <div><strong>{}</strong>: {}</div>",
            finding.category, finding.description
        )?;
        writeln!(
            file,
            "          <div class=\"severity {}\">{}!</div>",
            class, title
        )?;
        writeln!(file, "        </div>")?;

        if let Some(matched_text) = &finding.matched_text {
            writeln!(
                file,
                "        <div><strong>Matched:</strong> {}</div>",
                html_escape(matched_text)
            )?;
        }

        if let Some(context) = &finding.context {
            writeln!(
                file,
                "        <div class=\"context\">{}</div>",
                html_escape(context)
            )?;
        }

        writeln!(file, "      </div>")?;
    }

    Ok(())
}

fn html_escape(s: &str) -> String {
    s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\"", "&quot;")
        .replace("'", "&#39;")
}

fn generate_tls_analysis_report(
    entries: &[EnhancedReportEntry],
    output_dir: &str,
    comprehensive: bool,
) -> io::Result<()> {
    let tls_dir = format!("{}/tls_analysis", output_dir);
    fs::create_dir_all(&tls_dir)?;

    let html_path = format!("{}/certificate_analysis.html", tls_dir);
    let mut file = File::create(&html_path)?;

    writeln!(file, "<!DOCTYPE html>")?;
    writeln!(file, "<html lang=\"en\">")?;
    writeln!(file, "<head>")?;
    writeln!(file, "  <meta charset=\"UTF-8\">")?;
    writeln!(
        file,
        "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">"
    )?;
    writeln!(file, "  <title>TLS Certificate Analysis Report</title>")?;
    writeln!(file, "  <style>")?;
    writeln!(
        file,
        "    body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; }}"
    )?;
    writeln!(
        file,
        "    .container {{ max-width: 1200px; margin: 0 auto; }}"
    )?;
    writeln!(file, "    h1, h2, h3 {{ color: #333; }}")?;
    writeln!(file, "    .site {{ margin-bottom: 30px; border: 1px solid #ddd; border-radius: 5px; padding: 15px; }}")?;
    writeln!(file, "    .site h3 {{ margin-top: 0; }}")?;
    writeln!(
        file,
        "    table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; }}"
    )?;
    writeln!(
        file,
        "    th {{ background-color: #f5f5f5; text-align: left; padding: 8px; }}"
    )?;
    writeln!(
        file,
        "    td {{ border-bottom: 1px solid #ddd; padding: 8px; }}"
    )?;
    writeln!(file, "    .error {{ color: #dc3545; font-weight: bold; }}")?;
    writeln!(file, "    .warning {{ color: #fd7e14; }}")?;
    writeln!(file, "  </style>")?;
    writeln!(file, "</head>")?;
    writeln!(file, "<body>")?;
    writeln!(file, "  <div class=\"container\">")?;
    writeln!(file, "    <h1>TLS Certificate Analysis Report</h1>")?;
    writeln!(
        file,
        "    <p>Report generated on: {}</p>",
        chrono::Local::now().format("%Y-%m-%d %H:%M:%S")
    )?;

    let tls_entries: Vec<&EnhancedReportEntry> =
        entries.iter().filter(|e| !e.tls_info.is_empty()).collect();

    writeln!(
        file,
        "    <h2>Certificate Analysis Results ({} sites)</h2>",
        tls_entries.len()
    )?;

    for entry in &tls_entries {
        writeln!(file, "    <div class=\"site\">")?;
        writeln!(file, "      <h3>{}</h3>", entry.url)?;
        if let Some(error_msg) = entry.tls_info.get("error") {
            writeln!(file, "      <p class=\"error\">Error: {}</p>", error_msg)?;
            writeln!(file, "    </div>")?;
            continue;
        }

        writeln!(file, "      <table>")?;
        if let Some(subject) = entry.tls_info.get("subject") {
            writeln!(
                file,
                "        <tr><th>Subject</th><td>{}</td></tr>",
                subject
            )?;
        }
        if let Some(issuer) = entry.tls_info.get("issuer") {
            writeln!(file, "        <tr><th>Issuer</th><td>{}</td></tr>", issuer)?;
        }
        if let Some(valid_from) = entry.tls_info.get("valid_from") {
            writeln!(
                file,
                "        <tr><th>Valid From</th><td>{}</td></tr>",
                valid_from
            )?;
        }
        if let Some(valid_to) = entry.tls_info.get("valid_to") {
            writeln!(
                file,
                "        <tr><th>Valid To</th><td>{}</td></tr>",
                valid_to
            )?;
        }
        if let Some(days) = entry.tls_info.get("days_until_expiry") {
            writeln!(
                file,
                "        <tr><th>Days Until Expiry</th><td>{}</td></tr>",
                days
            )?;
        }
        if let Some(tls_version) = entry.tls_info.get("cert_tls_version") {
            writeln!(
                file,
                "        <tr><th>TLS Version</th><td>{}</td></tr>",
                tls_version
            )?;
        }
        if let Some(cipher) = entry.tls_info.get("cert_cipher") {
            writeln!(
                file,
                "        <tr><th>Cipher Suite</th><td>{}</td></tr>",
                cipher
            )?;
        }

        if let Some(warnings) = entry.tls_info.get("warnings") {
            writeln!(
                file,
                "        <tr><th>Warnings</th><td class=\"warning\">{}</td></tr>",
                warnings
            )?;
        }

        if let Some(errors) = entry.tls_info.get("errors") {
            writeln!(
                file,
                "        <tr><th>Errors</th><td class=\"error\">{}</td></tr>",
                errors
            )?;
        }

        if comprehensive {
            for (key, value) in entry.tls_info.iter() {
                if key.starts_with("testssl_") || key.starts_with("nmap_") {
                    writeln!(
                        file,
                        "        <tr><th>{}</th><td><pre>{}</pre></td></tr>",
                        key.replace("testssl_", "TestSSL: ")
                            .replace("nmap_", "Nmap: "),
                        value
                    )?;
                }
            }
        }

        writeln!(file, "      </table>")?;
        writeln!(file, "    </div>")?;
    }

    writeln!(file, "  </div>")?;
    writeln!(file, "</body>")?;
    writeln!(file, "</html>")?;

    let csv_path = format!("{}/certificate_analysis.csv", tls_dir);
    let mut csv_file = File::create(&csv_path)?;

    writeln!(
        csv_file,
        "URL,Subject,Issuer,Valid From,Valid To,Days Until Expiry,Warnings,Errors"
    )?;

    for entry in &tls_entries {
        let url = entry.url.replace("\"", "\"\"");
        let subject = entry
            .tls_info
            .get("subject")
            .unwrap_or(&String::new())
            .replace("\"", "\"\"");
        let issuer = entry
            .tls_info
            .get("issuer")
            .unwrap_or(&String::new())
            .replace("\"", "\"\"");
        let valid_from = entry
            .tls_info
            .get("valid_from")
            .unwrap_or(&String::new())
            .replace("\"", "\"\"");
        let valid_to = entry
            .tls_info
            .get("valid_to")
            .unwrap_or(&String::new())
            .replace("\"", "\"\"");
        let days = entry
            .tls_info
            .get("days_until_expiry")
            .unwrap_or(&String::new())
            .replace("\"", "\"\"");
        let warnings = entry
            .tls_info
            .get("warnings")
            .unwrap_or(&String::new())
            .replace("\"", "\"\"");
        let errors = entry
            .tls_info
            .get("errors")
            .unwrap_or(&String::new())
            .replace("\"", "\"\"");

        writeln!(
            csv_file,
            "\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"",
            url, subject, issuer, valid_from, valid_to, days, warnings, errors
        )?;
    }

    Ok(())
}
