// File: report.rs
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2025
// - Volker Schwaberow <volker@schwaberow.de>

use chrono::Local;
use log::error;
use serde::Serialize;
use std::fs::File;
use std::io::{Result, Write};
use std::path::Path;

#[derive(Debug, Serialize, Clone)]
pub struct ReportEntry {
    pub url: String,
    pub status: String,
    pub detections: Vec<String>,
}

#[derive(Debug)]
pub enum ReportFormat {
    Text,
    Json,
}

pub struct ReportGenerator;

impl ReportGenerator {
    pub fn generate_report(
        entries: &[ReportEntry],
        output_path: &str,
        format: ReportFormat,
    ) -> Result<()> {
        
        if let Some(parent) = Path::new(output_path).parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent)?;
            }
        }

        match format {
            ReportFormat::Text => Self::generate_text_report(entries, output_path),
            ReportFormat::Json => Self::generate_json_report(entries, output_path),
        }
    }

    pub fn generate_text_report(entries: &[ReportEntry], output_path: &str) -> Result<()> {
        let mut file = File::create(output_path)?;
        
        writeln!(file, "rprobe Scan Report")?;
        writeln!(file, "Date: {}", Local::now().format("%Y-%m-%d %H:%M:%S"))?;
        writeln!(file, "Total URLs scanned: {}", entries.len())?;
        writeln!(file, "----------------------------------------")?;
        
        for entry in entries {
            let status_text = if entry.status == "0" {
                "Failed".to_string()
            } else {
                format!("HTTP {}", entry.status)
            };
            
            writeln!(file, "URL: {}", entry.url)?;
            writeln!(file, "Status: {}", status_text)?;
            
            if !entry.detections.is_empty() {
                writeln!(file, "Detections:")?;
                for detection in &entry.detections {
                    writeln!(file, "  - {}", detection)?;
                }
            } else {
                writeln!(file, "No detections")?;
            }
            
            writeln!(file, "----------------------------------------")?;
        }
        
        writeln!(file, "End of Report")?;
        Ok(())
    }

    pub fn generate_json_report(entries: &[ReportEntry], output_path: &str) -> Result<()> {
        #[derive(Serialize)]
        struct Report {
            date: String,
            total_urls: usize,
            entries: Vec<ReportEntry>,
        }

        let report = Report {
            date: Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            total_urls: entries.len(),
            entries: entries.to_vec(),
        };

        let json = serde_json::to_string_pretty(&report).unwrap_or_else(|e| {
            error!("Failed to serialize report to JSON: {}", e);
            String::from("Error generating JSON report")
        });
        
        let mut file = File::create(output_path)?;
        writeln!(file, "{}", json)?;
        
        Ok(())
    }

    pub fn generate_csv_report(entries: &[ReportEntry], output_path: &str) -> Result<()> {
        let mut file = File::create(output_path)?;        
        writeln!(file, "URL,Status,Detections")?;
        
        for entry in entries {
            let detections = entry.detections.join("; ");
            
            let escaped_detections = detections.replace('"', "\"\"");
            
            writeln!(
                file,
                "{},\"{}\",\"{}\"",
                entry.url,
                entry.status,
                escaped_detections
            )?;
        }
        
        Ok(())
    }

    pub fn generate_html_report(entries: &[ReportEntry], output_path: &str) -> Result<()> {
        let mut file = File::create(output_path)?;
        
        let mut detection_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        let mut total_responsive = 0;
        let mut total_failed = 0;
        
        for entry in entries {
            if entry.status != "0" {
                total_responsive += 1;
            } else {
                total_failed += 1;
            }
            
            for detection in &entry.detections {
                *detection_counts.entry(detection.clone()).or_insert(0) += 1;
            }
        }
            
        let mut sorted_detections: Vec<(String, usize)> = detection_counts.into_iter().collect();
        sorted_detections.sort_by(|a, b| b.1.cmp(&a.1));
        
        writeln!(file, "<!DOCTYPE html>")?;
        writeln!(file, "<html lang=\"en\">")?;
        writeln!(file, "<head>")?;
        writeln!(file, "  <meta charset=\"UTF-8\">")?;
        writeln!(file, "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">")?;
        writeln!(file, "  <title>rprobe Scan Report</title>")?;
        writeln!(file, "  <style>")?;
        writeln!(file, "    body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; }}")?;
        writeln!(file, "    .container {{ max-width: 1200px; margin: 0 auto; }}")?;
        writeln!(file, "    h1, h2 {{ color: #333; }}")?;
        writeln!(file, "    .summary {{ background-color: #f5f5f5; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}")?;
        writeln!(file, "    .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; }}")?;
        writeln!(file, "    .summary-item {{ background-color: #fff; padding: 10px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}")?;
        writeln!(file, "    .stat-number {{ font-size: 24px; font-weight: bold; }}")?;
        writeln!(file, "    .stat-label {{ color: #666; }}")?;
        writeln!(file, "    table {{ width: 100%; border-collapse: collapse; }}")?;
        writeln!(file, "    th {{ background-color: #4CAF50; color: white; text-align: left; padding: 8px; }}")?;
        writeln!(file, "    td {{ border: 1px solid #ddd; padding: 8px; }}")?;
        writeln!(file, "    tr:nth-child(even) {{ background-color: #f2f2f2; }}")?;
        writeln!(file, "    tr:hover {{ background-color: #ddd; }}")?;
        writeln!(file, "    .status-success {{ color: green; }}")?;
        writeln!(file, "    .status-redirect {{ color: orange; }}")?;
        writeln!(file, "    .status-error {{ color: red; }}")?;
        writeln!(file, "    .status-failed {{ color: darkred; }}")?;
        writeln!(file, "    .detection-tag {{ display: inline-block; margin: 2px; padding: 3px 6px; background-color: #e0e0e0; border-radius: 3px; font-size: 12px; }}")?;
        writeln!(file, "    .chart-container {{ margin-top: 20px; }}")?;
        writeln!(file, "  </style>")?;
        writeln!(file, "</head>")?;
        writeln!(file, "<body>")?;
        writeln!(file, "  <div class=\"container\">")?;
        writeln!(file, "    <h1>rprobe Scan Report</h1>")?;
        writeln!(file, "    <p>Report generated on: {}</p>", Local::now().format("%Y-%m-%d %H:%M:%S"))?;  
        writeln!(file, "    <div class=\"summary\">")?;
        writeln!(file, "      <h2>Summary</h2>")?;
        writeln!(file, "      <div class=\"summary-grid\">")?;
        writeln!(file, "        <div class=\"summary-item\">")?;
        writeln!(file, "          <div class=\"stat-number\">{}</div>", entries.len())?;
        writeln!(file, "          <div class=\"stat-label\">Total URLs Scanned</div>")?;
        writeln!(file, "        </div>")?;
        writeln!(file, "        <div class=\"summary-item\">")?;
        writeln!(file, "          <div class=\"stat-number\">{}</div>", total_responsive)?;
        writeln!(file, "          <div class=\"stat-label\">Responsive</div>")?;
        writeln!(file, "        </div>")?;
        writeln!(file, "        <div class=\"summary-item\">")?;
        writeln!(file, "          <div class=\"stat-number\">{}</div>", total_failed)?;
        writeln!(file, "          <div class=\"stat-label\">Failed</div>")?;
        writeln!(file, "        </div>")?;
        writeln!(file, "        <div class=\"summary-item\">")?;
        writeln!(file, "          <div class=\"stat-number\">{}</div>", sorted_detections.len())?;
        writeln!(file, "          <div class=\"stat-label\">Unique Detections</div>")?;
        writeln!(file, "        </div>")?;
        writeln!(file, "      </div>")?;
        writeln!(file, "    </div>")?;
        
        if !sorted_detections.is_empty() {
            writeln!(file, "    <h2>Top Detections</h2>")?;
            writeln!(file, "    <table>")?;
            writeln!(file, "      <tr><th>Detection</th><th>Count</th></tr>")?;
            
            for (detection, count) in sorted_detections.iter().take(10) {
                writeln!(file, "      <tr><td>{}</td><td>{}</td></tr>", detection, count)?;
            }
            
            writeln!(file, "    </table>")?;
        }
        
        writeln!(file, "    <h2>Scan Results</h2>")?;
        writeln!(file, "    <table>")?;
        writeln!(file, "      <tr><th>URL</th><th>Status</th><th>Detections</th></tr>")?;
        
        for entry in entries {
            let status_class = if entry.status == "0" {
                "status-failed"
            } else {
                let status_code = entry.status.parse::<u16>().unwrap_or(0);
                if status_code >= 200 && status_code < 300 {
                    "status-success"
                } else if status_code >= 300 && status_code < 400 {
                    "status-redirect"
                } else {
                    "status-error"
                }
            };
            
            let status_text = if entry.status == "0" {
                "Failed".to_string()
            } else {
                format!("HTTP {}", entry.status)
            };
            
            writeln!(file, "      <tr>")?;
            writeln!(file, "        <td>{}</td>", entry.url)?;
            writeln!(file, "        <td class=\"{}\">'{}'</td>", status_class, status_text)?;
            
            writeln!(file, "        <td>")?;
            for detection in &entry.detections {
                writeln!(file, "          <span class=\"detection-tag\">{}</span>", detection)?;
            }
            writeln!(file, "        </td>")?;
            
            writeln!(file, "      </tr>")?;
        }
        
        writeln!(file, "    </table>")?;
        writeln!(file, "  </div>")?;
        writeln!(file, "</body>")?;
        writeln!(file, "</html>")?;
        
        Ok(())
    }
}
