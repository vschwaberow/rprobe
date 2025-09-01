// File: apachebasic.rs
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023-2025
// - Volker Schwaberow <volker@schwaberow.de>

#![allow(clippy::useless_vec)]

use crate::httpinner::HttpInner;
use crate::plugins::{Plugin, PluginCategory, PluginError, PluginMetadata, PluginResult};
use log::{debug, info};
use once_cell::sync::Lazy;

pub struct ApacheBasicPlugin;

use crate::plugins::pattern_matcher::OptimizedPatternMatcher;

static BODY_PATTERNS: Lazy<OptimizedPatternMatcher> = Lazy::new(|| {
    OptimizedPatternMatcher::new(
        &[
            ("It works!", "Standard HTML Body"),
            ("This IP is being shared among many domains.", "Shared IP Message"),
        ],
        &[
            (r"<html>Apache is functioning normally</html>", "Apache Functioning Message"),
            (r"<body><center>This IP is being shared among many domains\.<br>", "Shared IP Notice"),
            (r"<html><head><title>Apache2 Ubuntu Default Page: It works</title></head>", "Ubuntu Default Page"),
            (r"Apache/\d+\.\d+\.\d+", "Apache Version Info"),
        ]
    )
});

static HEADER_PATTERNS: Lazy<OptimizedPatternMatcher> = Lazy::new(|| {
    OptimizedPatternMatcher::new(
        &[],
        &[
            (r"^Apache$", "Server Header"),
            (r"^Apache/\d+\.\d+(?:\.\d+)?(?: .*)?$", "Server Version Header"),
            (r"(?i)apache", "Header Indicates 'Apache'"),
        ]
    )
});

impl Plugin for ApacheBasicPlugin {
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: "Apache Basic",
            version: "1.2.0",
            description: "Apache HTTP server detection through server headers, default pages, and content analysis",
            category: PluginCategory::WebServer,
            author: "rprobe team",
            priority: 1,
            enabled: true,
        }
    }

    fn should_run(&self, http_inner: &HttpInner) -> bool {
        if !http_inner.success() {
            return false;
        }

        if let Some(server) = http_inner.headers().get("server") {
            if let Ok(server_str) = server.to_str() {
                if server_str.to_lowercase().contains("apache") {
                    return true;
                }
            }
        }

        let body = http_inner.body();
        if body.len() < 10000 && body.contains("It works!") || body.contains("Apache") {
            return true;
        }

        true
    }

    fn run(&self, http_inner: &HttpInner) -> Result<Option<PluginResult>, PluginError> {
        debug!(
            "Starting Apache Basic detection for URL: {}",
            http_inner.url()
        );

        let mut detections = Vec::new();
        let mut confidence_score = 0u8;

        // Use optimized pattern matching for body content
        let body_matches = BODY_PATTERNS.find_matches(http_inner.body());
        for detection in body_matches {
            debug!("Apache detected in body: {}", detection);
            
            let pattern_confidence = match detection {
                "Standard HTML Body" => {
                    detections.push("Standard HTML Body");
                    5
                },
                "Shared IP Message" => {
                    detections.push("Shared IP Message");
                    2
                },
                "Apache Functioning Message" => {
                    detections.push("Apache Functioning Message");
                    4
                },
                "Shared IP Notice" => {
                    detections.push("Shared IP Notice");
                    3
                },
                "Ubuntu Default Page" => {
                    detections.push("Ubuntu Default Page");
                    4
                },
                "Apache Version Info" => {
                    detections.push("Apache Version Info");
                    3
                },
                _ => {
                    detections.push(detection);
                    2
                },
            };
            confidence_score = confidence_score.saturating_add(pattern_confidence);
        }

        // Use optimized pattern matching for headers
        if let Some(server_header_value) = http_inner.headers().get("server") {
            let server_value = server_header_value.to_str().unwrap_or("");
            let header_matches = HEADER_PATTERNS.find_matches(server_value);
            
            for detection in header_matches {
                debug!("Apache detected in header: {}", detection);
                
                let header_confidence = match detection {
                    "Server Header" => {
                        detections.push("Server Header");
                        4
                    },
                    "Server Version Header" => {
                        detections.push("Server Version Header");
                        5
                    },
                    "Header Indicates 'Apache'" => {
                        detections.push("Header Indicates 'Apache'");
                        3
                    },
                    _ => {
                        detections.push(detection);
                        2
                    },
                };
                confidence_score = confidence_score.saturating_add(header_confidence);
            }
        }

        if detections.is_empty() || confidence_score < 2 {
            debug!(
                "No confident Apache detection for URL: {}",
                http_inner.url()
            );
            return Ok(None);
        }

        let order = vec![
            "Server Version Header",
            "Server Header",
            "Standard HTML Body",
            "Apache Functioning Message",
            "Ubuntu Default Page",
            "Apache Version Info",
            "Shared IP Notice",
            "Shared IP Message",
            "Header Indicates 'Apache'",
        ];

        detections.sort_by_key(|det| order.iter().position(|&o| o == *det).unwrap_or(order.len()));
        detections.dedup();

        let final_confidence = std::cmp::min(confidence_score, 8);
        let detection_info = format!("Apache HTTP Server ({})", detections.join(", "));

        info!(
            "Apache detected: {} (confidence: {}/10)",
            detection_info, final_confidence
        );

        Ok(Some(PluginResult {
            plugin_name: self.metadata().name.to_string(),
            detection_info,
            confidence: final_confidence,
            execution_time_ms: 0,
            category: PluginCategory::WebServer,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
    use std::str::FromStr;

    fn create_test_http_inner(body: &str, headers: Vec<(&str, &str)>) -> HttpInner {
        let mut header_map = HeaderMap::new();
        for (key, value) in headers {
            header_map.insert(
                HeaderName::from_str(key).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }

        HttpInner::new_with_all(
            header_map,
            body.to_string(),
            200,
            "https://example.com".to_string(),
            true,
        )
    }

    #[test]
    fn test_metadata() {
        let plugin = ApacheBasicPlugin;
        let metadata = plugin.metadata();

        assert_eq!(metadata.name, "Apache Basic");
        assert_eq!(metadata.version, "1.2.0");
        assert_eq!(metadata.category, PluginCategory::WebServer);
        assert_eq!(metadata.author, "rprobe team");
        assert_eq!(metadata.priority, 1);
        assert!(metadata.enabled);
        assert!(metadata.description.contains("Apache"));
    }

    #[test]
    fn test_should_run_failed_request() {
        let plugin = ApacheBasicPlugin;
        let mut http_inner = create_test_http_inner("test", vec![]);
        http_inner.set_success(false);

        assert!(!plugin.should_run(&http_inner));
    }

    #[test]
    fn test_should_run_apache_header() {
        let plugin = ApacheBasicPlugin;
        let http_inner = create_test_http_inner("test", vec![("server", "Apache/2.4.41")]);

        assert!(plugin.should_run(&http_inner));
    }

    #[test]
    fn test_should_run_it_works_body() {
        let plugin = ApacheBasicPlugin;
        let http_inner = create_test_http_inner("It works!", vec![]);

        assert!(plugin.should_run(&http_inner));
    }

    #[test]
    fn test_should_run_apache_body() {
        let plugin = ApacheBasicPlugin;
        let http_inner = create_test_http_inner("Apache is running", vec![]);

        assert!(plugin.should_run(&http_inner));
    }

    #[test]
    fn test_should_run_regular_content() {
        let plugin = ApacheBasicPlugin;
        let http_inner = create_test_http_inner("regular content", vec![]);

        assert!(plugin.should_run(&http_inner));
    }

    #[test]
    fn test_server_header_apache() {
        let plugin = ApacheBasicPlugin;
        let http_inner = create_test_http_inner("", vec![("server", "Apache")]);

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        assert!(plugin_result.detection_info.contains("Server Header"));
        assert!(plugin_result.confidence >= 4);
    }

    #[test]
    fn test_server_version_header() {
        let plugin = ApacheBasicPlugin;
        let http_inner = create_test_http_inner("", vec![("server", "Apache/2.4.41")]);

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        assert!(plugin_result
            .detection_info
            .contains("Server Version Header"));
        assert!(plugin_result.confidence >= 5);
    }

    #[test]
    fn test_server_header_contains_apache() {
        let plugin = ApacheBasicPlugin;
        let http_inner = create_test_http_inner("", vec![("server", "Apache/2.4.41 (Ubuntu)")]);

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        assert!(plugin_result.detection_info.contains("Apache"));
    }

    #[test]
    fn test_standard_html_body() {
        let plugin = ApacheBasicPlugin;
        let http_inner =
            create_test_http_inner("<html><body><h1>It works!</h1></body></html>", vec![]);

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        assert!(plugin_result.detection_info.contains("Standard HTML Body"));
        assert!(plugin_result.confidence >= 5);
    }

    #[test]
    fn test_ubuntu_default_page() {
        let plugin = ApacheBasicPlugin;
        let http_inner = create_test_http_inner(
            "<html><head><title>Apache2 Ubuntu Default Page: It works</title></head>",
            vec![],
        );

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        assert!(plugin_result.detection_info.contains("Ubuntu Default Page"));
        assert!(plugin_result.confidence >= 4);
    }

    #[test]
    fn test_apache_functioning_message() {
        let plugin = ApacheBasicPlugin;
        let http_inner =
            create_test_http_inner("<html>Apache is functioning normally</html>", vec![]);

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        assert!(plugin_result
            .detection_info
            .contains("Apache Functioning Message"));
        assert!(plugin_result.confidence >= 4);
    }

    #[test]
    fn test_shared_ip_notice() {
        let plugin = ApacheBasicPlugin;
        let http_inner = create_test_http_inner(
            "<body><center>This IP is being shared among many domains.<br>",
            vec![],
        );

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        assert!(plugin_result.detection_info.contains("Shared IP Notice"));
    }

    #[test]
    fn test_apache_version_info() {
        let plugin = ApacheBasicPlugin;
        let http_inner = create_test_http_inner("Running Apache/2.4.41 server", vec![]);

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        assert!(plugin_result.detection_info.contains("Apache Version Info"));
        assert!(plugin_result.confidence >= 3);
    }

    #[test]
    fn test_multiple_detections() {
        let plugin = ApacheBasicPlugin;
        let http_inner = create_test_http_inner(
            "<html><body><h1>It works!</h1><p>Apache/2.4.41 is running</p></body></html>",
            vec![("server", "Apache/2.4.41 (Ubuntu)")],
        );

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        assert!(plugin_result
            .detection_info
            .contains("Server Version Header"));
        assert!(plugin_result.detection_info.contains("Standard HTML Body"));
        assert!(plugin_result.detection_info.contains("Apache Version Info"));
        assert_eq!(plugin_result.confidence, 8);
    }

    #[test]
    fn test_case_insensitive_header() {
        let plugin = ApacheBasicPlugin;
        let http_inner = create_test_http_inner("", vec![("server", "APACHE/2.4.41")]);

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        assert!(plugin_result.detection_info.contains("Apache"));
    }

    #[test]
    fn test_no_detection_empty_content() {
        let plugin = ApacheBasicPlugin;
        let http_inner = create_test_http_inner("", vec![]);

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_no_detection_unrelated_content() {
        let plugin = ApacheBasicPlugin;
        let http_inner = create_test_http_inner(
            "<html><body>Welcome to nginx</body></html>",
            vec![("server", "nginx/1.18.0")],
        );

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_low_confidence_threshold() {
        let plugin = ApacheBasicPlugin;
        let http_inner = create_test_http_inner("Apache", vec![]);

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_detection_ordering() {
        let plugin = ApacheBasicPlugin;
        let http_inner = create_test_http_inner(
            "<html><body><h1>It works!</h1><p>Apache Version: Apache/2.4.41</p></body></html>",
            vec![("server", "Apache/2.4.41")],
        );

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        let detection_parts: Vec<&str> = plugin_result.detection_info.split(',').collect();

        let version_pos = detection_parts
            .iter()
            .position(|&x| x.contains("Server Version Header"));
        let standard_pos = detection_parts
            .iter()
            .position(|&x| x.contains("Standard HTML Body"));
        let info_pos = detection_parts
            .iter()
            .position(|&x| x.contains("Apache Version Info"));

        assert!(version_pos.is_some());
        assert!(standard_pos.is_some());
        assert!(info_pos.is_some());

        assert!(version_pos < standard_pos);
    }

    #[test]
    fn test_confidence_scoring() {
        let plugin = ApacheBasicPlugin;

        let test_cases = vec![
            (("", vec![("server", "Apache/2.4.41")]), 5),
            (("", vec![("server", "Apache")]), 4),
            (("<html><body><h1>It works!</h1></body></html>", vec![]), 5),
            (("<html>Apache is functioning normally</html>", vec![]), 4),
            (("Running Apache/2.4.41", vec![]), 3),
        ];

        for ((body, headers), expected_min_confidence) in test_cases {
            let http_inner = create_test_http_inner(body, headers);
            let result = plugin.run(&http_inner).unwrap();

            assert!(result.is_some());
            let plugin_result = result.unwrap();
            assert!(plugin_result.confidence >= expected_min_confidence);
        }
    }

    #[test]
    fn test_plugin_name_consistency() {
        let plugin = ApacheBasicPlugin;
        let http_inner = create_test_http_inner("", vec![("server", "Apache")]);

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        assert_eq!(plugin_result.plugin_name, "Apache Basic");
        assert_eq!(plugin_result.category, PluginCategory::WebServer);
    }

    #[test]
    fn test_deduplication() {
        let plugin = ApacheBasicPlugin;
        let http_inner = create_test_http_inner(
            "<html><body><h1>It works!</h1><h1>It works!</h1></body></html>",
            vec![("server", "Apache")],
        );

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        let detection_info = &plugin_result.detection_info;

        let standard_count = detection_info.matches("Standard HTML Body").count();
        let server_count = detection_info.matches("Server Header").count();

        assert_eq!(standard_count, 1);
        assert_eq!(server_count, 1);
    }

    #[test]
    fn test_shared_ip_message() {
        let plugin = ApacheBasicPlugin;
        let http_inner =
            create_test_http_inner("This IP is being shared among many domains.", vec![]);

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        assert!(plugin_result.detection_info.contains("Shared IP Message"));
    }

    #[test]
    fn test_complex_apache_version() {
        let plugin = ApacheBasicPlugin;
        let http_inner = create_test_http_inner("", vec![("server", "Apache/2.4.41.10")]);

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        assert!(plugin_result.detection_info.contains("Apache"));
    }

    #[test]
    fn test_apache_with_extra_info() {
        let plugin = ApacheBasicPlugin;
        let http_inner = create_test_http_inner(
            "",
            vec![("server", "Apache/2.4 (Red Hat Enterprise Linux)")],
        );

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        assert!(plugin_result.detection_info.contains("Apache"));
    }

    #[test]
    fn test_large_body_with_apache() {
        let plugin = ApacheBasicPlugin;
        let large_body = format!(
            "{}<html><body><h1>It works!</h1></body></html>{}",
            "x".repeat(5000),
            "y".repeat(5000)
        );
        let http_inner = create_test_http_inner(&large_body, vec![]);

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        assert!(plugin_result.detection_info.contains("Standard HTML Body"));
    }
}
