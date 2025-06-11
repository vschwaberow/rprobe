// File: e2e_tests.rs
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2025
// - Volker Schwaberow <volker@schwaberow.de>

use rprobe::config::ConfigParameter;
use rprobe::content_analyzer::ContentAnalyzer;
use rprobe::getstate::GetState;
use rprobe::http::Http;
use rprobe::httpinner::HttpInner;
use rprobe::plugins::PluginHandler;
use rprobe::report::{ReportEntry, ReportFormat, ReportGenerator};
use wiremock::{MockServer, Mock, ResponseTemplate};
use wiremock::matchers::{method, path};
use reqwest::header::HeaderMap;
use serial_test::serial;
use std::fs;
use std::num::NonZeroU32;
use std::sync::Arc;
use tempfile::TempDir;

#[tokio::test]
#[serial]
async fn test_complete_scan_workflow() {
    // Setup mock server with various pages
    let mock_server = MockServer::start().await;
    
    // WordPress site
    Mock::given(method("GET"))
        .and(path("/wp-site"))
        .respond_with(ResponseTemplate::new(200)
            .set_body_string(r#"
                <html>
                    <head>
                        <meta name="generator" content="WordPress 6.0">
                        <script src="/wp-includes/js/jquery.js"></script>
                    </head>
                    <body>WordPress Site</body>
                </html>
            "#)
            .append_header("server", "Apache/2.4.41"))
        .mount(&mock_server)
        .await;
    
    // Apache site with PHP
    Mock::given(method("GET"))
        .and(path("/apache-php"))
        .respond_with(ResponseTemplate::new(200)
            .set_body_string("<html><body>Apache PHP Site</body></html>")
            .append_header("server", "Apache/2.4.41")
            .append_header("x-powered-by", "PHP/7.4.3"))
        .mount(&mock_server)
        .await;
    
    // Nginx site
    Mock::given(method("GET"))
        .and(path("/nginx-site"))
        .respond_with(ResponseTemplate::new(200)
            .set_body_string("<html><body>Nginx Site</body></html>")
            .append_header("server", "nginx/1.18.0"))
        .mount(&mock_server)
        .await;
    
    // Site with sensitive data
    Mock::given(method("GET"))
        .and(path("/sensitive"))
        .respond_with(ResponseTemplate::new(200)
            .set_body_string(r#"
                <html>
                    <body>
                        <p>Contact: admin@example.com</p>
                        <p>auth_token="sk-1234567890abcdef"</p>
                        <script>var secret = "AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI";</script>
                    </body>
                </html>
            "#))
        .mount(&mock_server)
        .await;
    
    // Failed request
    Mock::given(method("GET"))
        .and(path("/error"))
        .respond_with(ResponseTemplate::new(500)
            .set_body_string("Internal Server Error"))
        .mount(&mock_server)
        .await;
    
    // Step 1: Setup configuration
    let mut config = ConfigParameter::new();
    config.set_workers(2);
    config.set_timeout(5);
    
    // Step 2: Create HTTP client and perform requests
    let state = Arc::new(GetState::new());
    let mut http = Http::new(state, config.clone(), NonZeroU32::new(10).unwrap());
    
    let urls = Arc::new(vec![
        format!("{}/wp-site", mock_server.uri()),
        format!("{}/apache-php", mock_server.uri()),
        format!("{}/nginx-site", mock_server.uri()),
        format!("{}/sensitive", mock_server.uri()),
        format!("{}/error", mock_server.uri()),
    ]);
    
    let http_results = http.work(urls).await;
    
    // Step 3: Run plugin detection
    let plugin_handler = PluginHandler::new();
    let mut report_entries = Vec::new();
    
    for http_result in &http_results {
        let mut detections = Vec::new();
        
        if http_result.success() {
            detections = plugin_handler.run(http_result);
        }
        
        let entry = ReportEntry {
            url: http_result.url().to_string(),
            status: http_result.status().to_string(),
            detections,
        };
        
        report_entries.push(entry);
    }
    
    // Step 4: Verify plugin detections
    assert_eq!(http_results.len(), 5);
    
    // Check WordPress detection
    let wp_result = http_results.iter().find(|r| r.url().contains("/wp-site")).unwrap();
    let wp_detections = plugin_handler.run(wp_result);
    assert!(!wp_detections.is_empty());
    assert!(wp_detections.iter().any(|d| d.contains("Wordpress Basic")));
    assert!(wp_detections.iter().any(|d| d.contains("Apache Basic")));
    
    // Check Apache + PHP detection
    let apache_result = http_results.iter().find(|r| r.url().contains("/apache-php")).unwrap();
    let apache_detections = plugin_handler.run(apache_result);
    assert!(apache_detections.iter().any(|d| d.contains("Apache Basic")));
    assert!(apache_detections.iter().any(|d| d.contains("PHP Basic")));
    
    // Check Nginx detection
    let nginx_result = http_results.iter().find(|r| r.url().contains("/nginx-site")).unwrap();
    let nginx_detections = plugin_handler.run(nginx_result);
    assert!(nginx_detections.iter().any(|d| d.contains("Nginx Basic")));
    
    // Step 5: Content analysis
    let sensitive_result = http_results.iter().find(|r| r.url().contains("/sensitive")).unwrap();
    let content_findings = ContentAnalyzer::analyze(sensitive_result);
    
    assert!(!content_findings.is_empty());
    assert!(content_findings.iter().any(|f| f.category == "Email Address"));
    assert!(content_findings.iter().any(|f| f.category == "Auth Token"));
    
    // Step 6: Generate reports
    let temp_dir = TempDir::new().unwrap();
    
    // Text report
    let text_path = temp_dir.path().join("report.txt").to_string_lossy().to_string();
    let text_result = ReportGenerator::generate_report(&report_entries, &text_path, ReportFormat::Text);
    assert!(text_result.is_ok());
    
    let text_content = fs::read_to_string(&text_path).unwrap();
    assert!(text_content.contains("rprobe Scan Report"));
    assert!(text_content.contains("Total URLs scanned: 5"));
    assert!(text_content.contains("Wordpress Basic"));
    assert!(text_content.contains("Apache Basic"));
    assert!(text_content.contains("Nginx Basic"));
    
    // JSON report
    let json_path = temp_dir.path().join("report.json").to_string_lossy().to_string();
    let json_result = ReportGenerator::generate_report(&report_entries, &json_path, ReportFormat::Json);
    assert!(json_result.is_ok());
    
    let json_content = fs::read_to_string(&json_path).unwrap();
    let json_data: serde_json::Value = serde_json::from_str(&json_content).unwrap();
    assert_eq!(json_data["total_urls"], 5);
    assert_eq!(json_data["entries"].as_array().unwrap().len(), 5);
    
    // CSV report
    let csv_path = temp_dir.path().join("report.csv").to_string_lossy().to_string();
    let csv_result = ReportGenerator::generate_csv_report(&report_entries, &csv_path);
    assert!(csv_result.is_ok());
    
    // HTML report
    let html_path = temp_dir.path().join("report.html").to_string_lossy().to_string();
    let html_result = ReportGenerator::generate_html_report(&report_entries, &html_path);
    assert!(html_result.is_ok());
    
    let html_content = fs::read_to_string(&html_path).unwrap();
    assert!(html_content.contains("<!DOCTYPE html>"));
    assert!(html_content.contains("rprobe Scan Report"));
    assert!(html_content.contains("Total URLs Scanned"));
}

#[tokio::test]
#[serial]
async fn test_content_analysis_workflow() {
    let mock_server = MockServer::start().await;
    
    Mock::given(method("GET"))
        .and(path("/vuln-site"))
        .respond_with(ResponseTemplate::new(200)
            .set_body_string(r#"
                <html>
                    <head><title>Vulnerable Site</title></head>
                    <body>
                        <p>AWS Key: AKIAIOSFODNN7EXAMPLE</p>
                        <p>Email: contact@vulnerable-site.com</p>
                        <!-- TODO: Remove this debug code -->
                        <form method="get" action="/login">
                            <input type="password" name="pass">
                        </form>
                        <script>
                            eval(userInput);
                            document.write('<p>' + data + '</p>');
                        </script>
                    </body>
                </html>
            "#))
        .mount(&mock_server)
        .await;
    
    let config = ConfigParameter::new();
    let state = Arc::new(GetState::new());
    let mut http = Http::new(state, config, NonZeroU32::new(10).unwrap());
    
    let urls = Arc::new(vec![format!("{}/vuln-site", mock_server.uri())]);
    let results = http.work(urls).await;
    
    assert_eq!(results.len(), 1);
    let response = &results[0];
    
    // Basic content analysis
    let content_findings = ContentAnalyzer::analyze(response);
    assert!(!content_findings.is_empty());
    
    // Check for different types of findings
    let finding_categories: Vec<_> = content_findings.iter().map(|f| &f.category).collect();
    assert!(finding_categories.contains(&&"AWS Access Key".to_string()));
    assert!(finding_categories.contains(&&"Email Address".to_string()));
    assert!(finding_categories.contains(&&"Debug Comment".to_string()));
    
    // Form analysis
    let form_findings = ContentAnalyzer::analyze_forms(response);
    assert!(!form_findings.is_empty());
    assert!(form_findings.iter().any(|f| f.description.contains("POST method")));
    assert!(form_findings.iter().any(|f| f.description.contains("CSRF")));
    assert!(form_findings.iter().any(|f| f.description.contains("autocomplete")));
    
    // JavaScript analysis
    let js_findings = ContentAnalyzer::analyze_javascript(response);
    assert!(!js_findings.is_empty());
    assert!(js_findings.iter().any(|f| f.description.contains("eval()")));
    assert!(js_findings.iter().any(|f| f.description.contains("document.write()")));
}

#[test]
fn test_plugin_system_comprehensive() {
    let plugin_handler = PluginHandler::new();
    let plugins = plugin_handler.list();
    
    // Verify all expected plugins are registered
    assert!(plugins.contains(&"Wordpress Basic".to_string()));
    assert!(plugins.contains(&"Apache Basic".to_string()));
    assert!(plugins.contains(&"Nginx Basic".to_string()));
    assert!(plugins.contains(&"Laravel Plugin".to_string()));
    assert!(plugins.contains(&"PHP Basic Detection".to_string()));
    assert!(plugins.contains(&"Cloudflare Basic".to_string()));
    
    // Test multi-technology detection
    let mut headers = HeaderMap::new();
    headers.insert("server", "Apache/2.4.41".parse().unwrap());
    headers.insert("x-powered-by", "PHP/7.4.3".parse().unwrap());
    headers.insert("set-cookie", "laravel_session=abc123".parse().unwrap());
    
    let http_inner = HttpInner::new_with_all(
        headers,
        r#"<html>
            <meta name="generator" content="WordPress 6.0">
            <meta name="csrf-token" content="abc123">
            <div class="wp-content"></div>
        </html>"#.to_string(),
        200,
        "https://example.com".to_string(),
        true,
    );
    
    let detections = plugin_handler.run(&http_inner);
    
    // Should detect multiple technologies
    assert!(detections.len() >= 3);
    assert!(detections.iter().any(|d| d.contains("Apache")));
    assert!(detections.iter().any(|d| d.contains("PHP")));
    assert!(detections.iter().any(|d| d.contains("WordPress")));
    assert!(detections.iter().any(|d| d.contains("Laravel")));
}

#[tokio::test]
#[serial]
async fn test_error_handling_workflow() {
    let config = ConfigParameter::new();
    let state = Arc::new(GetState::new());
    let mut http = Http::new(state, config, NonZeroU32::new(10).unwrap());
    
    // Test with invalid URLs and connection failures
    let urls = Arc::new(vec![
        "http://localhost:99999".to_string(), // Connection refused
        "not-a-url".to_string(),              // Invalid URL
        "".to_string(),                       // Empty URL
    ]);
    
    let results = http.work(urls).await;
    
    assert_eq!(results.len(), 3);
    
    // All should have failed
    for result in &results {
        assert!(!result.success() || result.status() == 0);
    }
    
    // Test plugin handling of failed requests
    let plugin_handler = PluginHandler::new();
    for result in &results {
        let detections = plugin_handler.run(result);
        assert!(detections.is_empty()); // No detections on failed requests
    }
    
    // Test content analysis on failed requests
    for result in &results {
        let findings = ContentAnalyzer::analyze(result);
        assert!(findings.is_empty()); // No analysis on failed requests
    }
}

#[test]
fn test_configuration_workflow() {
    let mut config = ConfigParameter::new();
    
    // Test default values
    assert_eq!(config.timeout(), 10);
    assert_eq!(config.workers(), 10);
    assert!(config.http());
    assert!(config.https());
    assert!(!config.screenshot());
    assert_eq!(config.output_dir(), "scan");
    
    // Test configuration changes
    config.set_timeout(30);
    config.set_workers(5);
    config.set_http(false);
    config.set_screenshot(true);
    config.set_output_dir("custom_output".to_string());
    
    assert_eq!(config.timeout(), 30);
    assert_eq!(config.workers(), 5);
    assert!(!config.http());
    assert!(config.https());
    assert!(config.screenshot());
    assert_eq!(config.output_dir(), "custom_output");
    
    // Test cloning preserves settings
    let cloned_config = config.clone();
    assert_eq!(cloned_config.timeout(), 30);
    assert_eq!(cloned_config.workers(), 5);
    assert_eq!(cloned_config.output_dir(), "custom_output");
}