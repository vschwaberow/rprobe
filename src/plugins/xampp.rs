// File: xampp.rs
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023-2025
// - Volker Schwaberow <volker@schwaberow.de>

use crate::httpinner::HttpInner;
use crate::plugins::{Plugin, PluginCategory, PluginError, PluginMetadata, PluginResult};
use log::{debug, info};
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashMap;
use std::time::Instant;

pub struct XamppPlugin;

static VERSION_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"<title>XAMPP Version ([^\r\n<]+)[\s]*</title>").unwrap());

static OS_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"<title>XAMPP for ([^\r\n<]{5,8}) [\d\.a-z]{3,6}[\s]*</title>").unwrap()
});

static META_AUTHOR_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"<meta name=\"author\" content=\"Kai Oswald Seidler\">"#).unwrap());

static SECURITY_CONCEPT_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"<p style=\"margin-left: 2\\.6em; font-size: 1\\.2em; color: red;\">New XAMPP security concept:</p>"#).unwrap()
});

static WELCOME_TEXT_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)welcome\s+to\s+xampp").unwrap());

static XAMPP_REDIRECT_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^https?://[\d\.a-z]{1,256}/xampp/?$").unwrap());

static APACHE_WINDOWS_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)apache.*win32").unwrap());

impl Plugin for XamppPlugin {
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: "XAMPP",
            version: "1.0.0",
            description: "XAMPP Apache distribution detection with MySQL, PHP and Perl",
            category: PluginCategory::WebServer,
            author: "rprobe team",
            priority: 5,
            enabled: true,
        }
    }

    fn run(&self, http_inner: &HttpInner) -> Result<Option<PluginResult>, PluginError> {
        let start_time = Instant::now();

        debug!("Starting XAMPP detection for URL: {}", http_inner.url());

        let mut xampp_info = HashMap::new();
        let headers = http_inner.headers();
        let body = http_inner.body();

        if let Some(location) = headers.get("location") {
            if let Ok(location_str) = location.to_str() {
                if XAMPP_REDIRECT_REGEX.is_match(location_str) {
                    debug!("XAMPP redirect detected: {}", location_str);
                    xampp_info.insert("redirect", format!("Location[{}]", location_str));
                }
            }
        }

        if let Some(server) = headers.get("server") {
            if let Ok(server_str) = server.to_str() {
                if APACHE_WINDOWS_REGEX.is_match(server_str) {
                    debug!("Apache Windows server detected: {}", server_str);
                    xampp_info.insert("server", format!("Apache Windows[{}]", server_str));
                }
            }
        }

        if !body.is_empty() && body.len() < 200000 {
            if let Some(captures) = VERSION_REGEX.captures(body) {
                let version = captures.get(1).map_or("", |m| m.as_str()).trim();
                if !version.is_empty() {
                    debug!("XAMPP version detected: {}", version);
                    xampp_info.insert("version", format!("Version[{}]", version));
                }
            }

            if let Some(captures) = OS_REGEX.captures(body) {
                let os = captures.get(1).map_or("", |m| m.as_str()).trim();
                if !os.is_empty() {
                    debug!("XAMPP OS detected: {}", os);
                    xampp_info.insert("os", format!("OS[{}]", os));
                }
            }

            if META_AUTHOR_REGEX.is_match(body) {
                debug!("XAMPP meta author detected");
                xampp_info.insert("author", "Default Meta Author".to_string());
            }

            if SECURITY_CONCEPT_REGEX.is_match(body) {
                debug!("XAMPP security concept text detected");
                xampp_info.insert("security", "Security Concept Text".to_string());
            }

            if WELCOME_TEXT_REGEX.is_match(body) {
                debug!("XAMPP welcome text detected");
                xampp_info.insert("welcome", "Welcome Text".to_string());
            }

            let body_lower = body.to_lowercase();
            if body_lower.contains("xampp") {
                if body_lower.contains("php") && body_lower.contains("mysql") {
                    debug!("XAMPP stack components detected");
                    xampp_info.insert("stack", "XAMPP Stack Components".to_string());
                } else if !xampp_info.contains_key("version") && !xampp_info.contains_key("os") {
                    debug!("General XAMPP text detected");
                    xampp_info.insert("general", "XAMPP Text".to_string());
                }
            }
        }

        if !xampp_info.is_empty() {
            let confidence = self.calculate_confidence(&xampp_info);
            let detection_info = self.format_detection_info(&xampp_info);

            let execution_time = start_time.elapsed().as_millis();

            info!(
                "XAMPP detected: {} (confidence: {}/10, {}ms)",
                detection_info, confidence, execution_time
            );

            Ok(Some(PluginResult {
                plugin_name: self.metadata().name.to_string(),
                detection_info,
                confidence,
                execution_time_ms: execution_time,
                category: self.metadata().category,
            }))
        } else {
            debug!("No XAMPP indicators found");
            Ok(None)
        }
    }

    fn should_run(&self, http_inner: &HttpInner) -> bool {
        if !http_inner.success() && http_inner.status() != 403 {
            return false;
        }

        if let Some(location) = http_inner.headers().get("location") {
            if let Ok(location_str) = location.to_str() {
                if location_str.to_lowercase().contains("/xampp") {
                    return true;
                }
            }
        }

        if let Some(server) = http_inner.headers().get("server") {
            if let Ok(server_str) = server.to_str() {
                if server_str.to_lowercase().contains("apache") {
                    return true;
                }
            }
        }

        let body = http_inner.body();
        if body.len() < 50000 {
            let body_lower = body.to_lowercase();
            if body_lower.contains("xampp") || body_lower.contains("kai oswald seidler") {
                return true;
            }
        }

        true
    }
}

impl XamppPlugin {
    fn calculate_confidence(&self, xampp_info: &HashMap<&str, String>) -> u8 {
        let mut confidence = 0u8;

        for detection_type in xampp_info.keys() {
            match *detection_type {
                "version" => confidence = confidence.saturating_add(90),
                "os" => confidence = confidence.saturating_add(85),
                "author" => confidence = confidence.saturating_add(75),
                "security" => confidence = confidence.saturating_add(80),
                "welcome" => confidence = confidence.saturating_add(70),
                "server" => confidence = confidence.saturating_add(65),
                "redirect" => confidence = confidence.saturating_add(25),
                "stack" => confidence = confidence.saturating_add(60),
                "general" => confidence = confidence.saturating_add(40),
                _ => confidence = confidence.saturating_add(30),
            }
        }

        let scaled = (confidence.min(100) as f32 / 10.0).round() as u8;
        scaled.clamp(1, 10)
    }

    fn format_detection_info(&self, xampp_info: &HashMap<&str, String>) -> String {
        let mut parts = Vec::new();

        if let Some(version_info) = xampp_info.get("version") {
            parts.push(version_info.clone());
        }

        if let Some(os_info) = xampp_info.get("os") {
            parts.push(os_info.clone());
        }

        for (detection_type, value) in xampp_info {
            if *detection_type != "version" && *detection_type != "os" {
                parts.push(value.clone());
            }
        }

        if parts.is_empty() {
            "XAMPP Apache Distribution".to_string()
        } else {
            format!("XAMPP Apache Distribution ({})", parts.join(", "))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{HeaderMap, HeaderValue};

    fn create_test_http_inner(headers: HeaderMap, body: String, status: u16) -> HttpInner {
        HttpInner::new_with_all(
            headers,
            body,
            status,
            "https://example.com".to_string(),
            true,
        )
    }

    #[test]
    fn test_plugin_metadata() {
        let plugin = XamppPlugin;
        let metadata = plugin.metadata();

        assert_eq!(metadata.name, "XAMPP");
        assert_eq!(metadata.version, "1.0.0");
        assert!(metadata.description.contains("XAMPP Apache distribution"));
        assert_eq!(metadata.category, PluginCategory::WebServer);
        assert!(metadata.enabled);
        assert_eq!(metadata.priority, 5);
    }

    #[test]
    fn test_version_detection() {
        let plugin = XamppPlugin;
        let body = r#"<title>XAMPP Version 8.1.6</title>"#.to_string();
        let http_inner = create_test_http_inner(HeaderMap::new(), body, 200);

        let result = plugin.run(&http_inner);
        assert!(result.is_ok());
        let plugin_result = result.unwrap();
        assert!(plugin_result.is_some());

        let pr = plugin_result.unwrap();
        assert_eq!(pr.plugin_name, "XAMPP");
        assert!(pr.detection_info.contains("Version[8.1.6]"));
        assert!(pr.confidence >= 8);
        assert_eq!(pr.category, PluginCategory::WebServer);
    }

    #[test]
    fn test_os_detection() {
        let plugin = XamppPlugin;
        let body = r#"<title>XAMPP for Windows 8.1.6</title>"#.to_string();
        let http_inner = create_test_http_inner(HeaderMap::new(), body, 200);

        let result = plugin.run(&http_inner);
        assert!(result.is_ok());
        let plugin_result = result.unwrap();
        assert!(plugin_result.is_some());

        let pr = plugin_result.unwrap();
        assert!(pr.detection_info.contains("OS[Windows]"));
        assert!(pr.confidence >= 8);
    }

    #[test]
    fn test_meta_author_detection() {
        let plugin = XamppPlugin;
        let body = r#"<meta name=\"author\" content=\"Kai Oswald Seidler\">"#.to_string();
        let http_inner = create_test_http_inner(HeaderMap::new(), body, 200);

        let result = plugin.run(&http_inner);
        assert!(result.is_ok());
        let plugin_result = result.unwrap();
        assert!(plugin_result.is_some());

        let pr = plugin_result.unwrap();
        assert!(pr.detection_info.contains("Default Meta Author"));
        assert!(pr.confidence >= 7);
    }

    #[test]
    fn test_security_concept_detection() {
        let plugin = XamppPlugin;
        let body = r#"<p style=\"margin-left: 2.6em; font-size: 1.2em; color: red;\">New XAMPP security concept:</p>"#.to_string();
        let http_inner = create_test_http_inner(HeaderMap::new(), body, 403);

        let result = plugin.run(&http_inner);
        assert!(result.is_ok());
        let plugin_result = result.unwrap();
        assert!(plugin_result.is_some());

        let pr = plugin_result.unwrap();
        assert!(pr.detection_info.contains("Security Concept Text"));
        assert!(pr.confidence >= 8);
    }

    #[test]
    fn test_redirect_detection() {
        let plugin = XamppPlugin;
        let mut headers = HeaderMap::new();
        headers.insert(
            "location",
            HeaderValue::from_static("http://localhost/xampp/"),
        );

        let http_inner = create_test_http_inner(headers, String::new(), 302);
        let result = plugin.run(&http_inner);

        assert!(result.is_ok());
        let plugin_result = result.unwrap();
        assert!(plugin_result.is_some());

        let pr = plugin_result.unwrap();
        assert!(pr
            .detection_info
            .contains("Location[http://localhost/xampp/]"));
    }

    #[test]
    fn test_location_header_redirect() {
        let plugin = XamppPlugin;
        let mut headers = HeaderMap::new();
        headers.insert(
            "location",
            HeaderValue::from_static("https://example.com/xampp"),
        );

        let http_inner = create_test_http_inner(headers, String::new(), 302);
        let result = plugin.run(&http_inner);

        assert!(result.is_ok());
        let plugin_result = result.unwrap();
        assert!(plugin_result.is_some());

        let pr = plugin_result.unwrap();
        assert!(pr
            .detection_info
            .contains("Location[https://example.com/xampp"));
    }

    #[test]
    fn test_apache_windows_server() {
        let plugin = XamppPlugin;
        let mut headers = HeaderMap::new();
        headers.insert("server", HeaderValue::from_static("Apache/2.4.54 (Win32)"));

        let http_inner = create_test_http_inner(headers, String::new(), 200);
        let result = plugin.run(&http_inner);

        assert!(result.is_ok());
        let plugin_result = result.unwrap();
        assert!(plugin_result.is_some());

        let pr = plugin_result.unwrap();
        assert!(pr.detection_info.contains("Apache Windows"));
    }

    #[test]
    fn test_welcome_text_detection() {
        let plugin = XamppPlugin;
        let body =
            "Welcome to XAMPP! You have successfully installed Apache distribution.".to_string();
        let http_inner = create_test_http_inner(HeaderMap::new(), body, 200);

        let result = plugin.run(&http_inner);
        assert!(result.is_ok());
        let plugin_result = result.unwrap();
        assert!(plugin_result.is_some());

        let pr = plugin_result.unwrap();
        assert!(pr.detection_info.contains("Welcome Text"));
    }

    #[test]
    fn test_multiple_patterns() {
        let plugin = XamppPlugin;
        let body = r#"
            <title>XAMPP Version 8.1.6</title>
            <meta name=\"author\" content=\"Kai Oswald Seidler\">
            Welcome to XAMPP!
        "#
        .to_string();
        let http_inner = create_test_http_inner(HeaderMap::new(), body, 200);

        let result = plugin.run(&http_inner);
        assert!(result.is_ok());
        let plugin_result = result.unwrap();
        assert!(plugin_result.is_some());

        let pr = plugin_result.unwrap();
        assert!(pr.detection_info.contains("Version[8.1.6]"));
        assert!(pr.detection_info.contains("Default Meta Author"));
        assert!(pr.detection_info.contains("Welcome Text"));
        assert_eq!(pr.confidence, 10);
    }

    #[test]
    fn test_confidence_calculation() {
        let plugin = XamppPlugin;

        let mut version_info = HashMap::new();
        version_info.insert("version", "Version[8.1.6]".to_string());
        assert_eq!(plugin.calculate_confidence(&version_info), 9);

        let mut multiple_info = HashMap::new();
        multiple_info.insert("version", "Version[8.1.6]".to_string());
        multiple_info.insert("author", "Default Meta Author".to_string());
        assert_eq!(plugin.calculate_confidence(&multiple_info), 10);

        let mut low_confidence_info = HashMap::new();
        low_confidence_info.insert("general", "XAMPP Text".to_string());
        assert_eq!(plugin.calculate_confidence(&low_confidence_info), 4);
    }

    #[test]
    fn test_no_xampp_indicators() {
        let plugin = XamppPlugin;
        let body = "This is a regular Apache server".to_string();
        let http_inner = create_test_http_inner(HeaderMap::new(), body, 200);

        let result = plugin.run(&http_inner);
        assert!(result.is_ok());
        let plugin_result = result.unwrap();
        assert!(plugin_result.is_none());
    }

    #[test]
    fn test_failed_http_request() {
        let plugin = XamppPlugin;
        let http_inner = HttpInner::new_with_all(
            HeaderMap::new(),
            String::new(),
            500,
            "https://example.com".to_string(),
            false,
        );

        assert!(!plugin.should_run(&http_inner));
    }
}
