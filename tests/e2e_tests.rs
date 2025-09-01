// File: e2e_tests.rs
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023-2025
// - Volker Schwaberow <volker@schwaberow.de>

use reqwest::header::HeaderMap;
use rprobe::config::ConfigParameter;
use rprobe::content_analyzer::ContentAnalyzer;
use rprobe::httpinner::HttpInner;
use rprobe::plugins::PluginHandler;
use rprobe::report::{ReportEntry, ReportFormat, ReportGenerator};
use serial_test::serial;
use std::fs;
use tempfile::TempDir;

#[tokio::test]
#[serial]
async fn test_complete_scan_workflow() {
    let mut wp_headers = HeaderMap::new();
    wp_headers.insert("server", "Apache/2.4.41".parse().unwrap());
    let wp_result = HttpInner::new_with_all(
        wp_headers,
        r#"
                <html>
                    <head>
                        <meta name="generator" content="WordPress 6.0">
                        <script src="/wp-includes/js/jquery.js"></script>
                    </head>
                    <body>WordPress Site</body>
                </html>
            "#
        .to_string(),
        200,
        "https://example.com/wp-site".to_string(),
        true,
    );

    let mut apache_headers = HeaderMap::new();
    apache_headers.insert("server", "Apache/2.4.41".parse().unwrap());
    apache_headers.insert("x-powered-by", "PHP/7.4.3".parse().unwrap());
    let apache_result = HttpInner::new_with_all(
        apache_headers,
        "<html><body>Apache PHP Site</body></html>".to_string(),
        200,
        "https://example.com/apache-php".to_string(),
        true,
    );

    let mut nginx_headers = HeaderMap::new();
    nginx_headers.insert("server", "nginx/1.18.0".parse().unwrap());
    let nginx_result = HttpInner::new_with_all(
        nginx_headers,
        "<html><body>Nginx Site</body></html>".to_string(),
        200,
        "https://example.com/nginx-site".to_string(),
        true,
    );

    let sensitive_result = HttpInner::new_with_all(
        HeaderMap::new(),
        r#"
                <html>
                    <body>
                        <p>Contact: admin@example.com</p>
                        <p>auth_token="sk-1234567890abcdef"</p>
                        <script>var secret = "AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI";</script>
                    </body>
                </html>
            "#
        .to_string(),
        200,
        "https://example.com/sensitive".to_string(),
        true,
    );

    let error_result = HttpInner::new_with_all(
        HeaderMap::new(),
        "Internal Server Error".to_string(),
        500,
        "https://example.com/error".to_string(),
        false,
    );

    let http_results = vec![
        wp_result,
        apache_result,
        nginx_result,
        sensitive_result,
        error_result,
    ];

    let mut plugin_handler = PluginHandler::new();
    let mut report_entries = Vec::new();

    for http_result in &http_results {
        let mut detections = Vec::new();

        if http_result.success() {
            let plugin_results = plugin_handler.run(http_result);
            detections = plugin_results
                .into_iter()
                .map(|result| format!("{}: {}", result.plugin_name, result.detection_info))
                .collect();
        }

        let entry = ReportEntry {
            url: http_result.url().to_string(),
            status: http_result.status().to_string(),
            detections,
        };

        report_entries.push(entry);
    }

    assert_eq!(http_results.len(), 5);

    let wp_result = http_results
        .iter()
        .find(|r| r.url().contains("/wp-site"))
        .unwrap();
    let wp_plugin_results = plugin_handler.run(wp_result);
    assert!(!wp_plugin_results.is_empty());
    assert!(wp_plugin_results
        .iter()
        .any(|r| r.plugin_name.contains("WordPress Basic")));
    assert!(wp_plugin_results
        .iter()
        .any(|r| r.plugin_name.contains("Apache Basic")));

    let apache_result = http_results
        .iter()
        .find(|r| r.url().contains("/apache-php"))
        .unwrap();
    let apache_plugin_results = plugin_handler.run(apache_result);
    assert!(apache_plugin_results
        .iter()
        .any(|r| r.plugin_name.contains("Apache Basic")));
    assert!(apache_plugin_results
        .iter()
        .any(|r| r.plugin_name.contains("PHP Basic")));

    let nginx_result = http_results
        .iter()
        .find(|r| r.url().contains("/nginx-site"))
        .unwrap();
    let nginx_plugin_results = plugin_handler.run(nginx_result);
    assert!(nginx_plugin_results
        .iter()
        .any(|r| r.plugin_name.contains("Nginx Basic")));

    let sensitive_result = http_results
        .iter()
        .find(|r| r.url().contains("/sensitive"))
        .unwrap();
    let content_findings = ContentAnalyzer::analyze(sensitive_result);

    assert!(!content_findings.is_empty());
    assert!(content_findings
        .iter()
        .any(|f| f.category == "Email Address"));
    assert!(content_findings.iter().any(|f| f.category == "Auth Token"));

    let temp_dir = TempDir::new().unwrap();

    let text_path = temp_dir
        .path()
        .join("report.txt")
        .to_string_lossy()
        .to_string();
    let text_result =
        ReportGenerator::generate_report(&report_entries, &text_path, ReportFormat::Text);
    assert!(text_result.is_ok());

    let text_content = fs::read_to_string(&text_path).unwrap();
    assert!(text_content.contains("rprobe Scan Report"));
    assert!(text_content.contains("Total URLs scanned: 5"));
    assert!(text_content.contains("WordPress Basic"));
    assert!(text_content.contains("Apache Basic"));
    assert!(text_content.contains("Nginx Basic"));

    let json_path = temp_dir
        .path()
        .join("report.json")
        .to_string_lossy()
        .to_string();
    let json_result =
        ReportGenerator::generate_report(&report_entries, &json_path, ReportFormat::Json);
    assert!(json_result.is_ok());

    let json_content = fs::read_to_string(&json_path).unwrap();
    let json_data: serde_json::Value = serde_json::from_str(&json_content).unwrap();
    assert_eq!(json_data["total_urls"], 5);
    assert_eq!(json_data["entries"].as_array().unwrap().len(), 5);

    let csv_path = temp_dir
        .path()
        .join("report.csv")
        .to_string_lossy()
        .to_string();
    let csv_result = ReportGenerator::generate_csv_report(&report_entries, &csv_path);
    assert!(csv_result.is_ok());

    let html_path = temp_dir
        .path()
        .join("report.html")
        .to_string_lossy()
        .to_string();
    let html_result = ReportGenerator::generate_html_report(&report_entries, &html_path);
    assert!(html_result.is_ok());

    let html_content = fs::read_to_string(&html_path).unwrap();
    assert!(html_content.contains("<!DOCTYPE html>"));
    assert!(html_content.contains("rprobe Scan Report"));
    assert!(html_content.contains("Total URLs Scanned"));
}

#[test]
fn test_content_analysis_workflow() {
    let response = HttpInner::new_with_all(
        HeaderMap::new(),
        r#"
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
            "#
        .to_string(),
        200,
        "https://vulnerable-site.com".to_string(),
        true,
    );

    let content_findings = ContentAnalyzer::analyze(&response);
    assert!(!content_findings.is_empty());

    let finding_categories: Vec<_> = content_findings.iter().map(|f| &f.category).collect();
    assert!(finding_categories.contains(&&"AWS Access Key".to_string()));
    assert!(finding_categories.contains(&&"Email Address".to_string()));
    assert!(finding_categories.contains(&&"Debug Comment".to_string()));

    let form_findings = ContentAnalyzer::analyze_forms(&response);
    assert!(!form_findings.is_empty());
    assert!(form_findings
        .iter()
        .any(|f| f.description.contains("POST method")));
    assert!(form_findings.iter().any(|f| f.description.contains("CSRF")));
    assert!(form_findings
        .iter()
        .any(|f| f.description.contains("autocomplete")));

    let js_findings = ContentAnalyzer::analyze_javascript(&response);
    assert!(!js_findings.is_empty());
    assert!(js_findings.iter().any(|f| f.description.contains("eval()")));
    assert!(js_findings
        .iter()
        .any(|f| f.description.contains("document.write()")));
}

#[test]
fn test_plugin_system_comprehensive() {
    let mut plugin_handler = PluginHandler::new();
    let plugins = plugin_handler.list();

    assert!(plugins.contains(&"WordPress Basic".to_string()));
    assert!(plugins.contains(&"Apache Basic".to_string()));
    assert!(plugins.contains(&"Nginx Basic".to_string()));
    assert!(plugins.contains(&"Laravel".to_string()));
    assert!(plugins.contains(&"PHP Basic".to_string()));
    assert!(plugins.contains(&"Cloudflare Basic".to_string()));

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
        </html>"#
            .to_string(),
        200,
        "https://example.com".to_string(),
        true,
    );

    let plugin_results = plugin_handler.run(&http_inner);

    assert!(plugin_results.len() >= 3);
    assert!(plugin_results
        .iter()
        .any(|r| r.plugin_name.contains("Apache") || r.detection_info.contains("Apache")));
    assert!(plugin_results
        .iter()
        .any(|r| r.plugin_name.contains("PHP") || r.detection_info.contains("PHP")));
    assert!(plugin_results
        .iter()
        .any(|r| r.plugin_name.contains("WordPress") || r.detection_info.contains("WordPress")));
    assert!(plugin_results
        .iter()
        .any(|r| r.plugin_name.contains("Laravel") || r.detection_info.contains("Laravel")));
}

#[test]
fn test_error_handling_workflow() {
    let results = vec![
        HttpInner::new_with_all(
            HeaderMap::new(),
            "Connection refused".to_string(),
            0,
            "http://localhost:99999".to_string(),
            false,
        ),
        HttpInner::new_with_all(
            HeaderMap::new(),
            "URL validation failed".to_string(),
            0,
            "not-a-url".to_string(),
            false,
        ),
        HttpInner::new_with_all(
            HeaderMap::new(),
            "Empty URL".to_string(),
            0,
            "".to_string(),
            false,
        ),
    ];

    assert_eq!(results.len(), 3);

    for result in &results {
        assert!(!result.success());
    }

    let mut plugin_handler = PluginHandler::new();
    for result in &results {
        let plugin_results = plugin_handler.run(result);
        assert!(plugin_results.is_empty());
    }

    for result in &results {
        let findings = ContentAnalyzer::analyze(result);
        assert!(findings.is_empty());
    }
}

#[test]
fn test_configuration_workflow() {
    let mut config = ConfigParameter::new();

    assert_eq!(config.timeout(), 10);
    assert_eq!(config.workers(), 10);
    assert!(config.http());
    assert!(config.https());
    assert!(!config.screenshot());
    assert_eq!(config.output_dir(), "scan");

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

    let cloned_config = config.clone();
    assert_eq!(cloned_config.timeout(), 30);
    assert_eq!(cloned_config.workers(), 5);
    assert_eq!(cloned_config.output_dir(), "custom_output");
}
