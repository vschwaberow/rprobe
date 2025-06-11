// File: report_tests.rs
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2025
// - Volker Schwaberow <volker@schwaberow.de>

#[cfg(test)]
mod tests {
    use crate::report::*;
    use tempfile::TempDir;
    use std::fs;
    use serde_json::Value;

    fn create_test_entries() -> Vec<ReportEntry> {
        vec![
            ReportEntry {
                url: "https://example.com".to_string(),
                status: "200".to_string(),
                detections: vec!["Apache Basic: Apache/2.4.41".to_string(), "PHP Basic: PHP/7.4.3".to_string()],
            },
            ReportEntry {
                url: "https://test.com".to_string(),
                status: "301".to_string(),
                detections: vec!["Nginx Basic: nginx/1.18.0".to_string()],
            },
            ReportEntry {
                url: "https://failed.com".to_string(),
                status: "0".to_string(),
                detections: vec![],
            },
            ReportEntry {
                url: "https://wordpress.com".to_string(),
                status: "200".to_string(),
                detections: vec!["Wordpress Basic: WordPress Detected".to_string(), "PHP Basic: PHP/8.0.0".to_string()],
            },
        ]
    }

    fn create_temp_file() -> (TempDir, String) {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("report.txt").to_string_lossy().to_string();
        (temp_dir, file_path)
    }

    #[test]
    fn test_report_entry_creation() {
        let entry = ReportEntry {
            url: "https://example.com".to_string(),
            status: "200".to_string(),
            detections: vec!["Detection 1".to_string()],
        };
        assert_eq!(entry.url, "https://example.com");
        assert_eq!(entry.status, "200");
        assert_eq!(entry.detections.len(), 1);
    }

    #[test]
    fn test_generate_text_report() {
        let (_temp_dir, file_path) = create_temp_file();
        let entries = create_test_entries();
        
        let result = ReportGenerator::generate_text_report(&entries, &file_path);
        assert!(result.is_ok());
        
        let content = fs::read_to_string(&file_path).unwrap();
        
        assert!(content.contains("rprobe Scan Report"));
        assert!(content.contains("Date:"));
        assert!(content.contains("Total URLs scanned: 4"));
        
        assert!(content.contains("URL: https://example.com"));
        assert!(content.contains("Status: HTTP 200"));
        assert!(content.contains("Apache Basic: Apache/2.4.41"));
        assert!(content.contains("PHP Basic: PHP/7.4.3"));
        
        assert!(content.contains("URL: https://test.com"));
        assert!(content.contains("Status: HTTP 301"));
        assert!(content.contains("Nginx Basic: nginx/1.18.0"));
        
        assert!(content.contains("URL: https://failed.com"));
        assert!(content.contains("Status: Failed"));
        assert!(content.contains("No detections"));
        
        assert!(content.contains("End of Report"));
    }

    #[test]
    fn test_generate_text_report_empty_entries() {
        let (_temp_dir, file_path) = create_temp_file();
        let entries: Vec<ReportEntry> = vec![];
        
        let result = ReportGenerator::generate_text_report(&entries, &file_path);
        assert!(result.is_ok());
        
        let content = fs::read_to_string(&file_path).unwrap();
        assert!(content.contains("Total URLs scanned: 0"));
    }

    #[test]
    fn test_generate_json_report() {
        let (_temp_dir, file_path) = create_temp_file();
        let entries = create_test_entries();
        
        let result = ReportGenerator::generate_json_report(&entries, &file_path);
        assert!(result.is_ok());
        
        let content = fs::read_to_string(&file_path).unwrap();
        let json: Value = serde_json::from_str(&content).unwrap();
        
        assert!(json["date"].is_string());
        assert_eq!(json["total_urls"], 4);
        assert_eq!(json["entries"].as_array().unwrap().len(), 4);
        
        let first_entry = &json["entries"][0];
        assert_eq!(first_entry["url"], "https://example.com");
        assert_eq!(first_entry["status"], "200");
        assert_eq!(first_entry["detections"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn test_generate_csv_report() {
        let (_temp_dir, file_path) = create_temp_file();
        let entries = create_test_entries();
        
        let result = ReportGenerator::generate_csv_report(&entries, &file_path);
        assert!(result.is_ok());
        
        let content = fs::read_to_string(&file_path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        
        assert_eq!(lines[0], "URL,Status,Detections");
        
        assert!(lines[1].contains("https://example.com"));
        assert!(lines[1].contains("\"200\""));
        assert!(lines[1].contains("Apache Basic: Apache/2.4.41; PHP Basic: PHP/7.4.3"));
        
        assert!(lines[2].contains("https://test.com"));
        assert!(lines[2].contains("\"301\""));
        
        assert!(lines[3].contains("https://failed.com"));
        assert!(lines[3].contains("\"0\""));
        assert!(lines[3].contains("\"\""));
    }

    #[test]
    fn test_generate_csv_report_with_quotes() {
        let (_temp_dir, file_path) = create_temp_file();
        let entries = vec![
            ReportEntry {
                url: "https://quotes.com".to_string(),
                status: "200".to_string(),
                detections: vec!["Detection with \"quotes\"".to_string()],
            },
        ];
        
        let result = ReportGenerator::generate_csv_report(&entries, &file_path);
        assert!(result.is_ok());
        
        let content = fs::read_to_string(&file_path).unwrap();
        assert!(content.contains("\"Detection with \"\"quotes\"\"\""));
    }

    #[test]
    fn test_generate_html_report() {
        let (_temp_dir, file_path) = create_temp_file();
        let entries = create_test_entries();
        
        let result = ReportGenerator::generate_html_report(&entries, &file_path);
        assert!(result.is_ok());
        
        let content = fs::read_to_string(&file_path).unwrap();
        
        assert!(content.contains("<!DOCTYPE html>"));
        assert!(content.contains("<html lang=\"en\">"));
        assert!(content.contains("<title>rprobe Scan Report</title>"));
        
        assert!(content.contains("<div class=\"stat-number\">4</div>")); 
        assert!(content.contains("<div class=\"stat-number\">3</div>")); 
        assert!(content.contains("<div class=\"stat-number\">1</div>")); 
        
        assert!(content.contains("Top Detections"));
        assert!(content.contains("PHP Basic: PHP/")); 
        
        assert!(content.contains("https://example.com"));
        assert!(content.contains("class=\"status-success\""));
        assert!(content.contains("'HTTP 200'"));
        
        assert!(content.contains("https://test.com"));
        assert!(content.contains("class=\"status-redirect\""));
        assert!(content.contains("'HTTP 301'"));
        
        assert!(content.contains("https://failed.com"));
        assert!(content.contains("class=\"status-failed\""));
        assert!(content.contains("'Failed'"));
        
        assert!(content.contains("<span class=\"detection-tag\">Apache Basic: Apache/2.4.41</span>"));
        assert!(content.contains("<span class=\"detection-tag\">Nginx Basic: nginx/1.18.0</span>"));
    }

    #[test]
    fn test_generate_html_report_status_classes() {
        let (_temp_dir, file_path) = create_temp_file();
        let entries = vec![
            ReportEntry { url: "https://ok.com".to_string(), status: "200".to_string(), detections: vec![] },
            ReportEntry { url: "https://redirect.com".to_string(), status: "301".to_string(), detections: vec![] },
            ReportEntry { url: "https://notfound.com".to_string(), status: "404".to_string(), detections: vec![] },
            ReportEntry { url: "https://error.com".to_string(), status: "500".to_string(), detections: vec![] },
            ReportEntry { url: "https://failed.com".to_string(), status: "0".to_string(), detections: vec![] },
        ];
        
        let result = ReportGenerator::generate_html_report(&entries, &file_path);
        assert!(result.is_ok());
        
        let content = fs::read_to_string(&file_path).unwrap();
        
        assert!(content.contains("class=\"status-success\">'HTTP 200'"));
        assert!(content.contains("class=\"status-redirect\">'HTTP 301'"));
        assert!(content.contains("class=\"status-error\">'HTTP 404'"));
        assert!(content.contains("class=\"status-error\">'HTTP 500'"));
        assert!(content.contains("class=\"status-failed\">'Failed'"));
    }

    #[test]
    fn test_generate_report_with_format() {
        let temp_dir = TempDir::new().unwrap();
        let text_path = temp_dir.path().join("report.txt").to_string_lossy().to_string();
        let json_path = temp_dir.path().join("report.json").to_string_lossy().to_string();
        
        let entries = create_test_entries();
        
        let text_result = ReportGenerator::generate_report(&entries, &text_path, ReportFormat::Text);
        assert!(text_result.is_ok());
        assert!(fs::metadata(&text_path).is_ok());
        
        let json_result = ReportGenerator::generate_report(&entries, &json_path, ReportFormat::Json);
        assert!(json_result.is_ok());
        assert!(fs::metadata(&json_path).is_ok());
    }

    #[test]
    fn test_generate_report_creates_parent_directory() {
        let temp_dir = TempDir::new().unwrap();
        let nested_path = temp_dir.path().join("nested/dir/report.txt").to_string_lossy().to_string();
        
        let entries = create_test_entries();
        let result = ReportGenerator::generate_report(&entries, &nested_path, ReportFormat::Text);
        
        assert!(result.is_ok());
        assert!(fs::metadata(&nested_path).is_ok());
    }

    #[test]
    fn test_html_detection_counts() {
        let (_temp_dir, file_path) = create_temp_file();
        let entries = vec![
            ReportEntry {
                url: "https://site1.com".to_string(),
                status: "200".to_string(),
                detections: vec!["PHP Basic: PHP/7.4".to_string(), "Apache".to_string()],
            },
            ReportEntry {
                url: "https://site2.com".to_string(),
                status: "200".to_string(),
                detections: vec!["PHP Basic: PHP/7.4".to_string(), "Nginx".to_string()],
            },
            ReportEntry {
                url: "https://site3.com".to_string(),
                status: "200".to_string(),
                detections: vec!["PHP Basic: PHP/7.4".to_string()],
            },
        ];
        
        let result = ReportGenerator::generate_html_report(&entries, &file_path);
        assert!(result.is_ok());
        
        let content = fs::read_to_string(&file_path).unwrap();
        
        assert!(content.contains("<td>PHP Basic: PHP/7.4</td><td>3</td>"));
        
        assert!(content.contains("<div class=\"stat-number\">3</div>"));
        assert!(content.contains("<div class=\"stat-label\">Unique Detections</div>"));
    }

    #[test]
    fn test_empty_entries_all_formats() {
        let temp_dir = TempDir::new().unwrap();
        let entries: Vec<ReportEntry> = vec![];
        
        let text_path = temp_dir.path().join("empty.txt").to_string_lossy().to_string();
        assert!(ReportGenerator::generate_text_report(&entries, &text_path).is_ok());
        
        let json_path = temp_dir.path().join("empty.json").to_string_lossy().to_string();
        assert!(ReportGenerator::generate_json_report(&entries, &json_path).is_ok());
        let json_content = fs::read_to_string(&json_path).unwrap();
        let json: Value = serde_json::from_str(&json_content).unwrap();
        assert_eq!(json["total_urls"], 0);
        assert!(json["entries"].as_array().unwrap().is_empty());
        
        let csv_path = temp_dir.path().join("empty.csv").to_string_lossy().to_string();
        assert!(ReportGenerator::generate_csv_report(&entries, &csv_path).is_ok());
        let csv_content = fs::read_to_string(&csv_path).unwrap();
        assert_eq!(csv_content.trim(), "URL,Status,Detections");
        
        let html_path = temp_dir.path().join("empty.html").to_string_lossy().to_string();
        assert!(ReportGenerator::generate_html_report(&entries, &html_path).is_ok());
        let html_content = fs::read_to_string(&html_path).unwrap();
        assert!(html_content.contains("<div class=\"stat-number\">0</div>"));
    }
}