// File: cli.rs
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023-2025
// - Volker Schwaberow <volker@schwaberow.de>

use chrono::{DateTime, NaiveDateTime, Utc};
use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

use crate::content_analyzer::FindingSeverity;

#[derive(Parser, Debug)]
#[command(
    name = env!("CARGO_PKG_NAME"),
    version = env!("CARGO_PKG_VERSION"),
    author = env!("CARGO_PKG_AUTHORS"),
    about = env!("CARGO_PKG_DESCRIPTION"),
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    #[arg(long, global = true)]
    pub data_dir: Option<PathBuf>,

    #[arg(long = "log-level", default_value = "warn", global = true)]
    pub log_level: String,

    #[arg(
        short = 'v',
        long = "verbose",
        help = "Enable verbose output",
        global = true
    )]
    pub verbose: bool,

    #[arg(
        short = 'q',
        long = "quiet",
        help = "Reduce output verbosity",
        global = true
    )]
    pub quiet: bool,

    #[arg(long = "no-color", help = "Disable colored output", global = true)]
    pub no_color: bool,

    #[arg(
        short = 't',
        long = "timeout",
        default_value_t = 10,
        help = "HTTP request timeout in seconds"
    )]
    pub timeout: u64,

    #[arg(short = 'n', long = "nohttp", help = "Disable HTTP scanning")]
    pub nohttp: bool,

    #[arg(short = 'N', long = "nohttps", help = "Disable HTTPS scanning")]
    pub nohttps: bool,

    #[arg(
        short = 'S',
        long = "show-unresponsive",
        help = "Show failed/unresponsive targets in output"
    )]
    pub show_unresponsive: bool,

    #[arg(
        short = 's',
        long = "suppress-stats",
        help = "Suppress scan summary and statistics"
    )]
    pub suppress_stats: bool,

    #[arg(short = 'r', long = "rate-limit", default_value_t = 10)]
    pub rate_limit: u32,

    #[arg(short = 'w', long = "workers", default_value_t = 10)]
    pub workers: u32,

    #[arg(short = 'o', long = "output-dir", default_value = "scan")]
    pub output_dir: String,

    #[arg(
        long = "no-store-history",
        help = "Do not store scan results in history (opt-out)"
    )]
    pub no_store_history: bool,

    #[arg(short = 'i', long = "input-file")]
    pub input_file: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    Scan(ScanArgs),
    Output(OutputArgs),
    History(HistoryArgs),
    Compare(CompareArgs),
    Clean(CleanArgs),
    Stats(StatsArgs),
}

#[derive(Args, Debug)]
pub struct ScanArgs {
    #[arg(short = 'd', long = "detect-all")]
    pub detect_all: bool,

    #[arg(short = 'p', long = "plugins")]
    pub list_plugins: bool,

    #[arg(long = "plugin")]
    pub plugin: Option<String>,

    #[arg(long)]
    pub download_robots: bool,

    #[arg(
        short = 'c',
        long = "short",
        help = "Use compact one-line output format"
    )]
    pub short: bool,

    #[arg(long = "compact", help = "Legacy compact output format")]
    pub compact: bool,

    #[arg(long = "screenshot")]
    pub screenshot: bool,

    #[arg(long = "resume-file")]
    pub resume_file: Option<String>,

    #[arg(long = "content-analysis")]
    pub content_analysis: bool,

    #[arg(long = "tls-analysis")]
    pub tls_analysis: bool,

    #[arg(long = "comprehensive-tls")]
    pub comprehensive_tls: bool,

    #[arg(long = "desync")]
    pub desync: bool,

    #[arg(long = "desync-safe-mode")]
    pub desync_safe_mode: bool,

    #[arg(long = "desync-target")]
    pub desync_target: Option<String>,

    #[arg(
        long = "i-have-authorization",
        help = "Skip authorization prompt (requires explicit written permission)"
    )]
    pub i_have_authorization: bool,

    #[arg(
        long = "force-store",
        help = "Force storage even if --store-history is not set"
    )]
    pub force_store: bool,

    #[arg(long = "session-name", help = "Optional name for the scan session")]
    pub session_name: Option<String>,

    #[arg(long = "tags", help = "Comma-separated tags for organizing scans")]
    pub tags: Option<String>,
}

#[derive(Args, Debug)]
pub struct OutputArgs {
    #[arg(short = 'f', long = "format", default_value = "html")]
    pub format: String,

    #[arg(short = 'o', long = "output")]
    pub output: Option<PathBuf>,

    #[arg(long = "theme", default_value = "light")]
    pub theme: String,

    #[arg(long = "url-pattern")]
    pub url_pattern: Option<String>,

    #[arg(
        long = "start-date",
        help = "Start date (YYYY-MM-DD or YYYY-MM-DD HH:MM:SS)"
    )]
    pub start_date: Option<String>,

    #[arg(
        long = "end-date",
        help = "End date (YYYY-MM-DD or YYYY-MM-DD HH:MM:SS)"
    )]
    pub end_date: Option<String>,

    #[arg(long = "min-severity")]
    pub min_severity: Option<String>,

    #[arg(long = "has-detections")]
    pub has_detections: Option<bool>,

    #[arg(long = "has-tls-issues")]
    pub has_tls_issues: Option<bool>,

    #[arg(long = "has-desync-findings")]
    pub has_desync_findings: Option<bool>,

    #[arg(long = "status-codes", help = "Comma-separated list of status codes")]
    pub status_codes: Option<String>,

    #[arg(long = "limit", default_value_t = 1000)]
    pub limit: usize,

    #[arg(long = "aggregate", help = "Generate aggregated summary report")]
    pub aggregate: bool,

    #[arg(long = "template", help = "Custom template file path")]
    pub template: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct HistoryArgs {
    #[arg(help = "URL to show history for")]
    pub url: Option<String>,

    #[arg(short = 'l', long = "limit", default_value_t = 20)]
    pub limit: usize,

    #[arg(
        long = "start-date",
        help = "Start date (YYYY-MM-DD or YYYY-MM-DD HH:MM:SS)"
    )]
    pub start_date: Option<String>,

    #[arg(
        long = "end-date",
        help = "End date (YYYY-MM-DD or YYYY-MM-DD HH:MM:SS)"
    )]
    pub end_date: Option<String>,

    #[arg(long = "format", default_value = "table")]
    pub format: String,

    #[arg(long = "show-changes")]
    pub show_changes: bool,

    #[arg(long = "group-by", help = "Group results by: url, date, status")]
    pub group_by: Option<String>,
}

#[derive(Args, Debug)]
pub struct CompareArgs {
    #[arg(help = "URL to compare")]
    pub url: String,

    #[arg(
        long = "old-date",
        help = "Old scan date (YYYY-MM-DD or YYYY-MM-DD HH:MM:SS)"
    )]
    pub old_date: String,

    #[arg(
        long = "new-date",
        help = "New scan date (YYYY-MM-DD or YYYY-MM-DD HH:MM:SS)"
    )]
    pub new_date: String,

    #[arg(long = "format", default_value = "table")]
    pub format: String,

    #[arg(long = "output")]
    pub output: Option<PathBuf>,

    #[arg(long = "detailed", help = "Show detailed diff analysis")]
    pub detailed: bool,
}

#[derive(Args, Debug)]
pub struct CleanArgs {
    #[arg(long = "before", help = "Delete data before this date (YYYY-MM-DD)")]
    pub before: Option<String>,

    #[arg(long = "days", help = "Delete data older than N days")]
    pub days: Option<u32>,

    #[arg(
        long = "dry-run",
        help = "Show what would be deleted without actually deleting"
    )]
    pub dry_run: bool,

    #[arg(long = "confirm", help = "Confirm deletion without interactive prompt")]
    pub confirm: bool,

    #[arg(long = "compact", help = "Compact database after cleanup")]
    pub compact: bool,
}

#[derive(Args, Debug)]
pub struct StatsArgs {
    #[arg(long = "format", default_value = "table")]
    pub format: String,

    #[arg(long = "output")]
    pub output: Option<PathBuf>,

    #[arg(long = "detailed", help = "Show detailed statistics")]
    pub detailed: bool,

    #[arg(
        long = "time-range",
        help = "Time range for statistics (7d, 30d, 90d, all)"
    )]
    pub time_range: Option<String>,

    #[arg(long = "top-n", default_value_t = 10)]
    pub top_n: usize,
}

impl OutputArgs {
    pub fn parse_start_date(&self) -> Option<DateTime<Utc>> {
        self.start_date.as_ref().and_then(|s| parse_date_string(s))
    }

    pub fn parse_end_date(&self) -> Option<DateTime<Utc>> {
        self.end_date.as_ref().and_then(|s| parse_date_string(s))
    }

    pub fn parse_min_severity(&self) -> Option<FindingSeverity> {
        self.min_severity
            .as_ref()
            .and_then(|s| match s.to_lowercase().as_str() {
                "critical" => Some(FindingSeverity::Critical),
                "high" => Some(FindingSeverity::High),
                "medium" => Some(FindingSeverity::Medium),
                "low" => Some(FindingSeverity::Low),
                "info" => Some(FindingSeverity::Info),
                _ => None,
            })
    }

    pub fn parse_status_codes(&self) -> Option<Vec<String>> {
        self.status_codes
            .as_ref()
            .map(|s| s.split(',').map(|code| code.trim().to_string()).collect())
    }
}

impl HistoryArgs {
    pub fn parse_start_date(&self) -> Option<DateTime<Utc>> {
        self.start_date.as_ref().and_then(|s| parse_date_string(s))
    }

    pub fn parse_end_date(&self) -> Option<DateTime<Utc>> {
        self.end_date.as_ref().and_then(|s| parse_date_string(s))
    }
}

impl CompareArgs {
    pub fn parse_old_date(&self) -> Option<DateTime<Utc>> {
        parse_date_string(&self.old_date)
    }

    pub fn parse_new_date(&self) -> Option<DateTime<Utc>> {
        parse_date_string(&self.new_date)
    }
}

impl CleanArgs {
    pub fn parse_before_date(&self) -> Option<DateTime<Utc>> {
        self.before.as_ref().and_then(|s| parse_date_string(s))
    }

    pub fn calculate_cutoff_date(&self) -> Option<DateTime<Utc>> {
        if let Some(date) = self.parse_before_date() {
            return Some(date);
        }

        if let Some(days) = self.days {
            let cutoff = Utc::now() - chrono::Duration::days(days as i64);
            return Some(cutoff);
        }

        None
    }
}

fn parse_date_string(date_str: &str) -> Option<DateTime<Utc>> {
    if let Ok(naive) = NaiveDateTime::parse_from_str(date_str, "%Y-%m-%d %H:%M:%S") {
        return Some(DateTime::from_naive_utc_and_offset(naive, Utc));
    }

    if let Ok(naive) =
        NaiveDateTime::parse_from_str(&format!("{} 00:00:00", date_str), "%Y-%m-%d %H:%M:%S")
    {
        return Some(DateTime::from_naive_utc_and_offset(naive, Utc));
    }

    None
}

pub fn is_legacy_mode(cli: &Cli) -> bool {
    cli.command.is_none()
}

pub fn merge_legacy_args(cli: &Cli) -> ScanArgs {
    ScanArgs {
        detect_all: false,
        list_plugins: false,
        plugin: None,
        download_robots: false,
        short: false,
        compact: false,
        screenshot: false,
        resume_file: None,
        content_analysis: false,
        tls_analysis: false,
        comprehensive_tls: false,
        desync: false,
        desync_safe_mode: false,
        desync_target: None,
        i_have_authorization: false,
        force_store: !cli.no_store_history,
        session_name: None,
        tags: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_date_string() {
        let result = parse_date_string("2024-01-15 14:30:00");
        assert!(result.is_some());

        let result = parse_date_string("2024-01-15");
        assert!(result.is_some());

        let result = parse_date_string("invalid");
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_severity() {
        let args = OutputArgs {
            format: "html".to_string(),
            output: None,
            theme: "light".to_string(),
            url_pattern: None,
            start_date: None,
            end_date: None,
            min_severity: Some("critical".to_string()),
            has_detections: None,
            has_tls_issues: None,
            has_desync_findings: None,
            status_codes: None,
            limit: 1000,
            aggregate: false,
            template: None,
        };

        assert_eq!(args.parse_min_severity(), Some(FindingSeverity::Critical));
    }

    #[test]
    fn test_parse_status_codes() {
        let args = OutputArgs {
            format: "html".to_string(),
            output: None,
            theme: "light".to_string(),
            url_pattern: None,
            start_date: None,
            end_date: None,
            min_severity: None,
            has_detections: None,
            has_tls_issues: None,
            has_desync_findings: None,
            status_codes: Some("200,404,500".to_string()),
            limit: 1000,
            aggregate: false,
            template: None,
        };

        let codes = args.parse_status_codes().unwrap();
        assert_eq!(codes, vec!["200", "404", "500"]);
    }

    #[test]
    fn test_clean_args_cutoff() {
        let args = CleanArgs {
            before: None,
            days: Some(30),
            dry_run: false,
            confirm: false,
            compact: false,
        };

        let cutoff = args.calculate_cutoff_date().unwrap();
        let expected = Utc::now() - chrono::Duration::days(30);
        let diff = (cutoff.timestamp() - expected.timestamp()).abs();
        assert!(diff < 60);
    }
}
