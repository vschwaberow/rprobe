// File: desync_cli.rs
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023-2025
// - Volker Schwaberow <volker@schwaberow.de>

use crate::desync_scanner::{
    generate_desync_report, DesyncConfig, DesyncResult, DesyncScanner, DesyncSeverity,
};
use clap::Args;
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use log::warn;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use url::Url;

#[derive(Args, Debug, Clone)]
pub struct DesyncArgs {
    #[arg(short = 'i', long = "input")]
    pub input_file: Option<String>,

    #[arg(long = "target")]
    pub target_url: Option<String>,

    #[arg(short = 'o', long = "output", default_value = "desync_results")]
    pub output_dir: String,

    #[arg(long = "format", default_value = "jsonl")]
    pub output_format: String,

    #[arg(long = "safe-mode")]
    pub safe_mode: bool,

    #[arg(long = "connect-timeout", default_value = "3000")]
    pub connect_timeout: u64,

    #[arg(long = "read-timeout", default_value = "8000")]
    pub read_timeout: u64,

    #[arg(short = 'c', long = "concurrency", default_value = "8")]
    pub concurrency: usize,

    #[arg(long = "rate-limit", default_value = "60")]
    pub rate_limit: u32,

    #[arg(long = "canary", default_value = "rpd")]
    pub canary_prefix: String,

    #[arg(long = "collaborator")]
    pub collaborator_url: Option<String>,

    #[arg(long = "max-targets", default_value = "1000")]
    pub max_targets: usize,

    #[arg(short = 'v', long = "verbose")]
    pub verbose: bool,

    #[arg(long = "min-severity", default_value = "low")]
    pub min_severity: String,

    #[arg(long = "skip-tests")]
    pub skip_tests: Option<String>,

    #[arg(long = "i-have-authorization")]
    pub skip_authorization_check: bool,

    #[arg(long = "enable-timing-analysis")]
    pub enable_timing_analysis: bool,

    #[arg(long = "timing-samples", default_value = "3")]
    pub timing_samples: usize,

    #[arg(long = "timing-threshold", default_value = "500")]
    pub timing_threshold_ms: u64,

    #[arg(long = "enable-advanced-chunking")]
    pub enable_advanced_chunking: bool,

    #[arg(long = "enable-h2-downgrade")]
    pub enable_h2_downgrade_tests: bool,

    #[arg(long = "enable-cache-probing")]
    pub enable_cache_probing: bool,

    #[arg(long = "max-connections-per-host", default_value = "3")]
    pub max_connections_per_host: usize,
}

pub async fn run_desync_scan(
    args: DesyncArgs,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    std::fs::create_dir_all(&args.output_dir)?;

    println!("{}", "=".repeat(80).bright_red());
    println!(
        "{}",
        "DEF CON HTTP-Must-Die Desync Scanner".bright_red().bold()
    );
    println!("{}", "=".repeat(80).bright_red());
    println!();
    println!(
        "{}",
        "CRITICAL WARNING: DANGEROUS SECURITY TESTING TOOL"
            .bright_red()
            .bold()
    );
    println!(
        "{}",
        "This tool performs HTTP request smuggling attacks that can:".bright_yellow()
    );
    println!("   - Cause service disruption and downtime");
    println!("   - Interfere with legitimate user traffic");
    println!("   - Trigger security alerts and incident response");
    println!("   - Potentially violate computer fraud laws");
    println!();
    println!("{}", "LEGAL REQUIREMENT:".bright_red().bold());
    println!("   You MUST have explicit written authorization to test these targets.");
    println!("   Unauthorized security testing is illegal in most jurisdictions.");
    println!();

    if !args.skip_authorization_check {
        println!(
            "{}",
            "Do you have explicit written authorization to test all target systems? (yes/NO):"
                .bright_yellow()
        );
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;

        if input.trim().to_lowercase() != "yes" {
            println!(
                "{}",
                "Authorization not confirmed. Exiting for safety.".red()
            );
            println!("   Use --i-have-authorization flag only if you have proper authorization.");
            return Ok(());
        }
    }

    perform_target_safety_check(&args).await?;

    println!(
        "{}",
        "Proceeding with authorized security testing...".green()
    );
    println!();

    let targets = load_targets(&args).await?;
    if targets.is_empty() {
        eprintln!(
            "{}",
            "No targets specified. Use -t for single target or -i for input file".red()
        );
        return Ok(());
    }

    println!("Loaded {} target(s)", targets.len());

    let config = DesyncConfig {
        safe_mode: args.safe_mode,
        max_body_size: if args.safe_mode { 4096 } else { 8192 },
        connect_timeout: Duration::from_millis(args.connect_timeout),
        read_timeout: Duration::from_millis(args.read_timeout),
        reuse_connections: true,
        rate_limit_per_host: args.rate_limit,
        retry_on_idle_close: 1,
        canary_prefix: args.canary_prefix.clone(),
        collaborator_url: args.collaborator_url.clone(),
        max_targets: args.max_targets,
        enable_timing_analysis: args.enable_timing_analysis,
        timing_samples: args.timing_samples,
        timing_threshold_ms: args.timing_threshold_ms,
        enable_connection_pooling: true,
        max_connections_per_host: args.max_connections_per_host,
        enable_cache_probing: args.enable_cache_probing,
        enable_h2_downgrade_tests: args.enable_h2_downgrade_tests,
        enable_advanced_chunking: args.enable_advanced_chunking,
        enable_non_poisoning_mode: true,
        timeout_only_patterns: true,
        parser_fingerprint_payloads: vec![
            "X-Forwarded-For: 127.0.0.1".to_string(),
            "X-Real-IP: 192.168.1.1".to_string(),
            "Via: 1.1 proxy".to_string(),
        ],
    };

    let scanner = Arc::new(DesyncScanner::new(config)?);

    let pb = ProgressBar::new(targets.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template(
                "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos:>7}/{len:7} {msg}",
            )
            .unwrap()
            .progress_chars("##-"),
    );

    let semaphore = Arc::new(Semaphore::new(args.concurrency));
    let mut all_results = Vec::new();

    let mut handles = Vec::new();

    for target in targets {
        let scanner_clone = scanner.clone();
        let semaphore_clone = semaphore.clone();
        let pb_clone = pb.clone();

        let handle = tokio::spawn(async move {
            let _permit = semaphore_clone.acquire().await.unwrap();
            pb_clone.set_message(format!("Scanning {}", target));

            let results = match scanner_clone.scan_target(&target).await {
                Ok(results) => results,
                Err(e) => {
                    warn!("Failed to scan {}: {}", target, e);
                    vec![]
                }
            };

            pb_clone.inc(1);
            results
        });

        handles.push(handle);
    }

    for handle in handles {
        match handle.await {
            Ok(mut results) => all_results.append(&mut results),
            Err(e) => warn!("Task failed: {}", e),
        }
    }

    pb.finish_with_message("Scan completed");

    let min_severity = parse_severity(&args.min_severity);
    let filtered_results: Vec<_> = all_results
        .into_iter()
        .filter(|r| severity_level(&r.severity) >= severity_level(&min_severity))
        .collect();

    display_summary(&filtered_results);

    save_results(&filtered_results, &args).await?;

    println!("\nScan completed. Results saved to: {}", args.output_dir);

    Ok(())
}

async fn load_targets(
    args: &DesyncArgs,
) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
    let mut targets = Vec::new();

    if let Some(target) = &args.target_url {
        targets.push(target.clone());
    }

    if let Some(input_file) = &args.input_file {
        let file = File::open(input_file)?;
        let reader = BufReader::new(file);

        for line in reader.lines() {
            let line = line?;
            let trimmed = line.trim();
            if !trimmed.is_empty() && !trimmed.starts_with('#') {
                if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
                    targets.push(trimmed.to_string());
                } else {
                    targets.push(format!("http://{}", trimmed));
                }
            }
        }
    } else if args.target_url.is_none() {
        use std::io::{self, BufRead};

        let stdin = io::stdin();
        let stdin_lock = stdin.lock();

        for line in stdin_lock.lines() {
            let line = line?;
            let trimmed = line.trim();
            if !trimmed.is_empty() && !trimmed.starts_with('#') {
                if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
                    targets.push(trimmed.to_string());
                } else {
                    targets.push(format!("http://{}", trimmed));
                }
            }
        }
    }

    if targets.len() > args.max_targets {
        targets.truncate(args.max_targets);
        println!("Limited to {} targets", args.max_targets);
    }

    Ok(targets)
}

fn display_summary(results: &[DesyncResult]) {
    println!("\nScan Summary");
    println!("================");

    if results.is_empty() {
        println!("No vulnerabilities detected");
        return;
    }

    let mut by_severity = std::collections::HashMap::new();
    let mut by_host = std::collections::HashMap::new();

    for result in results {
        *by_severity.entry(&result.severity).or_insert(0) += 1;
        by_host
            .entry(&result.url)
            .or_insert(Vec::new())
            .push(result);
    }

    println!("Findings by severity:");
    for severity in [
        DesyncSeverity::Critical,
        DesyncSeverity::High,
        DesyncSeverity::Medium,
        DesyncSeverity::Low,
        DesyncSeverity::Info,
    ] {
        if let Some(&count) = by_severity.get(&severity) {
            let color = match severity {
                DesyncSeverity::Critical => "bright_red",
                DesyncSeverity::High => "red",
                DesyncSeverity::Medium => "yellow",
                DesyncSeverity::Low => "blue",
                DesyncSeverity::Info => "cyan",
            };
            println!(
                "  {} {:?}: {}",
                severity_icon(&severity),
                severity,
                format!("{}", count).color(color)
            );
        }
    }

    println!("\nMost vulnerable hosts:");
    let mut host_counts: Vec<_> = by_host
        .iter()
        .map(|(host, results)| (host, results.len()))
        .collect();
    host_counts.sort_by(|a, b| b.1.cmp(&a.1));

    for (host, count) in host_counts.iter().take(10) {
        println!(
            "  {} {} ({} findings)",
            "".bright_yellow(),
            host,
            count.to_string().red()
        );
    }

    let critical_high: Vec<_> = results
        .iter()
        .filter(|r| matches!(r.severity, DesyncSeverity::Critical | DesyncSeverity::High))
        .collect();

    if !critical_high.is_empty() {
        println!("\n🚨 Critical/High Severity Findings:");
        for result in critical_high {
            println!(
                "  {} {} - {:?} on {}",
                severity_icon(&result.severity),
                format!("{:?}", result.severity).red(),
                result.test_type,
                result.url
            );
            if !result.signals.is_empty() {
                println!("    📡 Signals: {}", result.signals.len());
            }
            if let Some(marker) = &result.contamination_marker {
                println!("    Marker: {}", marker.yellow());
            }
        }
    }
}

async fn save_results(
    results: &[DesyncResult],
    args: &DesyncArgs,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");

    match args.output_format.as_str() {
        "json" => {
            let filename = format!("{}/desync_results_{}.json", args.output_dir, timestamp);
            let mut file = File::create(&filename)?;
            let json = serde_json::to_string_pretty(results)?;
            file.write_all(json.as_bytes())?;
            println!("JSON results: {}", filename);
        }
        "jsonl" => {
            let filename = format!("{}/desync_results_{}.jsonl", args.output_dir, timestamp);
            let mut file = File::create(&filename)?;
            for result in results {
                let json = serde_json::to_string(result)?;
                writeln!(file, "{}", json)?;
            }
            println!("JSONL results: {}", filename);
        }
        "txt" => {
            let filename = format!("{}/desync_results_{}.txt", args.output_dir, timestamp);
            let mut file = File::create(&filename)?;
            let report = generate_desync_report(results);
            file.write_all(report.as_bytes())?;
            println!("Text report: {}", filename);
        }
        "html" => {
            let filename = format!("{}/desync_results_{}.html", args.output_dir, timestamp);
            let html_report = generate_html_report(results);
            let mut file = File::create(&filename)?;
            file.write_all(html_report.as_bytes())?;
            println!("HTML report: {}", filename);
        }
        _ => {
            return Err(format!("Unsupported output format: {}", args.output_format).into());
        }
    }

    let summary_file = format!("{}/desync_summary_{}.txt", args.output_dir, timestamp);
    let mut file = File::create(&summary_file)?;
    writeln!(file, "DEF CON HTTP-Must-Die Desync Scan Summary")?;
    writeln!(file, "=======================================")?;
    writeln!(
        file,
        "Scan completed: {}",
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
    )?;
    writeln!(file, "Total findings: {}", results.len())?;
    writeln!(
        file,
        "Targets scanned: {}",
        results
            .iter()
            .map(|r| &r.url)
            .collect::<std::collections::HashSet<_>>()
            .len()
    )?;

    let mut by_severity = std::collections::HashMap::new();
    for result in results {
        *by_severity.entry(&result.severity).or_insert(0) += 1;
    }

    writeln!(file, "\nFindings by severity:")?;
    for severity in [
        DesyncSeverity::Critical,
        DesyncSeverity::High,
        DesyncSeverity::Medium,
        DesyncSeverity::Low,
        DesyncSeverity::Info,
    ] {
        if let Some(&count) = by_severity.get(&severity) {
            writeln!(file, "  {:?}: {}", severity, count)?;
        }
    }

    Ok(())
}

fn generate_html_report(results: &[DesyncResult]) -> String {
    let mut html = String::new();

    html.push_str(
        "<!DOCTYPE html><html><head><title>DEF CON HTTP-Must-Die Desync Scan Report</title>",
    );
    html.push_str("<style>");
    html.push_str("body { font-family: Arial, sans-serif; margin: 40px; }");
    html.push_str(".critical { color: #dc3545; font-weight: bold; }");
    html.push_str(".high { color: #fd7e14; font-weight: bold; }");
    html.push_str(".medium { color: #ffc107; font-weight: bold; }");
    html.push_str(".low { color: #17a2b8; }");
    html.push_str(".info { color: #6c757d; }");
    html.push_str("table { border-collapse: collapse; width: 100%; }");
    html.push_str("th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }");
    html.push_str("th { background-color: #f2f2f2; }");
    html.push_str(
        ".marker { font-family: monospace; background-color: #f8f9fa; padding: 2px 4px; }",
    );
    html.push_str("</style></head><body>");

    html.push_str("<h1>🚨 DEF CON HTTP-Must-Die Desync Scan Report</h1>");
    html.push_str(&format!(
        "<p><strong>Generated:</strong> {}</p>",
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
    ));
    html.push_str(&format!(
        "<p><strong>Total Findings:</strong> {}</p>",
        results.len()
    ));

    if results.is_empty() {
        html.push_str("<p>No vulnerabilities detected</p>");
    } else {
        html.push_str("<h2>Summary by Severity</h2>");
        html.push_str("<table><tr><th>Severity</th><th>Count</th><th>Description</th></tr>");

        let mut by_severity = std::collections::HashMap::new();
        for result in results {
            *by_severity.entry(&result.severity).or_insert(0) += 1;
        }

        for severity in [
            DesyncSeverity::Critical,
            DesyncSeverity::High,
            DesyncSeverity::Medium,
            DesyncSeverity::Low,
            DesyncSeverity::Info,
        ] {
            if let Some(&count) = by_severity.get(&severity) {
                let css_class = match severity {
                    DesyncSeverity::Critical => "critical",
                    DesyncSeverity::High => "high",
                    DesyncSeverity::Medium => "medium",
                    DesyncSeverity::Low => "low",
                    DesyncSeverity::Info => "info",
                };
                let description = match severity {
                    DesyncSeverity::Critical => "Double-desync with confirmed marker contamination",
                    DesyncSeverity::High => "Request smuggling with strong evidence",
                    DesyncSeverity::Medium => "Potential request smuggling indicators",
                    DesyncSeverity::Low => "Suspicious responses requiring investigation",
                    DesyncSeverity::Info => "Informational findings",
                };
                html.push_str(&format!(
                    "<tr><td class=\"{}\"> {:?}</td><td>{}</td><td>{}</td></tr>",
                    css_class, severity, count, description
                ));
            }
        }
        html.push_str("</table>");

        html.push_str("<h2>Detailed Findings</h2>");
        html.push_str("<table><tr><th>URL</th><th>Test Type</th><th>Severity</th><th>Status</th><th>Marker</th><th>Timing</th><th>Signals</th></tr>");

        for result in results {
            let css_class = match result.severity {
                DesyncSeverity::Critical => "critical",
                DesyncSeverity::High => "high",
                DesyncSeverity::Medium => "medium",
                DesyncSeverity::Low => "low",
                DesyncSeverity::Info => "info",
            };

            html.push_str(&format!(
                "<tr><td>{}</td><td>{:?}</td><td class=\"{}\">{:?}</td><td>{}</td><td class=\"marker\">{}</td><td>{}ms</td><td>{}</td></tr>",
                result.url,
                result.test_type,
                css_class,
                result.severity,
                result.response_status,
                result.contamination_marker.as_deref().unwrap_or("N/A"),
                result.timing_ms,
                result.signals.len()
            ));
        }
        html.push_str("</table>");
    }

    html.push_str("<hr><p><em>Generated by rprobe DEF CON HTTP-Must-Die scanner</em></p>");
    html.push_str("</body></html>");

    html
}

fn parse_severity(severity_str: &str) -> DesyncSeverity {
    match severity_str.to_lowercase().as_str() {
        "critical" => DesyncSeverity::Critical,
        "high" => DesyncSeverity::High,
        "medium" => DesyncSeverity::Medium,
        "low" => DesyncSeverity::Low,
        "info" => DesyncSeverity::Info,
        _ => DesyncSeverity::Low,
    }
}

fn severity_level(severity: &DesyncSeverity) -> u8 {
    match severity {
        DesyncSeverity::Critical => 4,
        DesyncSeverity::High => 3,
        DesyncSeverity::Medium => 2,
        DesyncSeverity::Low => 1,
        DesyncSeverity::Info => 0,
    }
}

fn severity_icon(severity: &DesyncSeverity) -> &'static str {
    match severity {
        DesyncSeverity::Critical => "CRITICAL",
        DesyncSeverity::High => "HIGH",
        DesyncSeverity::Medium => "MEDIUM",
        DesyncSeverity::Low => "LOW",
        DesyncSeverity::Info => "INFO",
    }
}

async fn perform_target_safety_check(
    args: &DesyncArgs,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut targets = Vec::new();

    if let Some(target) = &args.target_url {
        targets.push(target.clone());
    }

    if let Some(input_file) = &args.input_file {
        if std::path::Path::new(input_file).exists() {
            let file = File::open(input_file)?;
            let reader = BufReader::new(file);
            for line in reader.lines() {
                let line = line?.trim().to_string();
                if !line.is_empty() && !line.starts_with('#') {
                    targets.push(line);
                }
            }
        }
    }

    let dangerous_domains = vec![
        "amazon.com",
        "amazonaws.com",
        "aws.com",
        "google.com",
        "googleapis.com",
        "googleusercontent.com",
        "gstatic.com",
        "microsoft.com",
        "microsoftonline.com",
        "azure.com",
        "outlook.com",
        "facebook.com",
        "twitter.com",
        "linkedin.com",
        "github.com",
        "stackoverflow.com",
        "reddit.com",
        "wikipedia.org",
        ".gov",
        ".mil",
        ".edu",
        "paypal.com",
        "stripe.com",
        "square.com",
        "cloudflare.com",
        "fastly.com",
        "akamai.com",
        "cloudfront.net",
    ];

    let mut warnings = Vec::new();

    for target in &targets {
        if let Ok(parsed_url) = Url::parse(target) {
            if let Some(host) = parsed_url.host_str() {
                let host_lower = host.to_lowercase();

                for dangerous in &dangerous_domains {
                    if host_lower.contains(dangerous) {
                        warnings.push(format!(
                            "RISK: Target {} appears to be a major service/infrastructure",
                            host
                        ));
                    }
                }

                if host_lower.contains("localhost")
                    || host_lower.contains("127.0.0.1")
                    || host_lower.contains("::1")
                    || host_lower.contains("192.168.")
                    || host_lower.contains("10.")
                    || host_lower.contains("172.")
                {
                    warnings.push(format!(
                        "WARNING: Target {} appears to be internal/localhost",
                        host
                    ));
                }
            }
        }
    }

    if !warnings.is_empty() {
        println!("{}", "SAFETY WARNINGS DETECTED:".bright_red().bold());
        for warning in &warnings {
            println!("  {}", warning.bright_yellow());
        }
        println!();
        println!("These targets may require special authorization or could be illegal to test.");
        println!("Are you absolutely certain you have authorization for ALL targets? (yes/NO):");

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        if input.trim().to_lowercase() != "yes" {
            println!(
                "{}",
                "SAFETY EXIT: Terminating to prevent unauthorized testing.".red()
            );
            std::process::exit(1);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_parsing() {
        assert_eq!(parse_severity("critical"), DesyncSeverity::Critical);
        assert_eq!(parse_severity("HIGH"), DesyncSeverity::High);
        assert_eq!(parse_severity("medium"), DesyncSeverity::Medium);
        assert_eq!(parse_severity("invalid"), DesyncSeverity::Low);
    }

    #[test]
    fn test_severity_levels() {
        assert!(severity_level(&DesyncSeverity::Critical) > severity_level(&DesyncSeverity::High));
        assert!(severity_level(&DesyncSeverity::High) > severity_level(&DesyncSeverity::Medium));
        assert!(severity_level(&DesyncSeverity::Medium) > severity_level(&DesyncSeverity::Low));
        assert!(severity_level(&DesyncSeverity::Low) > severity_level(&DesyncSeverity::Info));
    }

    #[test]
    fn test_severity_icons() {
        assert_eq!(severity_icon(&DesyncSeverity::Critical), "CRITICAL");
        assert_eq!(severity_icon(&DesyncSeverity::High), "HIGH");
        assert_eq!(severity_icon(&DesyncSeverity::Info), "INFO");
    }
}
