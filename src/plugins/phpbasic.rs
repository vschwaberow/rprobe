// File: phpbasic.rs
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023-2025
// - Volker Schwaberow <volker@schwaberow.de>

use crate::httpinner::HttpInner;
use crate::plugins::pattern_matcher::OptimizedPatternMatcher;
use crate::plugins::{Plugin, PluginCategory, PluginError, PluginMetadata, PluginResult};
use log::{debug, info};
use once_cell::sync::Lazy;
use regex::Regex;

pub struct PHPBasicPlugin;

static PHP_VERSION_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"PHP\s*/?(\d+\.\d+(?:\.\d+)?)").expect("Failed to compile PHP version regex")
});

static BODY_PATTERNS: Lazy<OptimizedPatternMatcher> = Lazy::new(|| {
    OptimizedPatternMatcher::new(
        &[
            ("<?php", "PHPCode"),
            ("PHP Warning", "PHPWarning"),
            ("PHP Parse error", "PHPParseError"),
            ("Fatal error: Uncaught Error", "PHPFatalError"),
            ("Notice: Undefined variable", "PHPNotice"),
            ("Deprecated:", "PHPDeprecated"),
        ],
        &[],
    )
});

static PATTERN_CONFIDENCE: Lazy<std::collections::HashMap<&'static str, u8>> = Lazy::new(|| {
    [
        ("PHPCode", 4u8),
        ("PHPWarning", 3u8),
        ("PHPParseError", 3u8),
        ("PHPFatalError", 3u8),
        ("PHPNotice", 2u8),
        ("PHPDeprecated", 2u8),
    ]
    .iter()
    .cloned()
    .collect()
});

impl Plugin for PHPBasicPlugin {
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: "PHP Basic",
            version: "1.2.0",
            description: "PHP scripting language detection through headers, cookies, error messages, and source code patterns",
            category: PluginCategory::ApplicationFramework,
            author: "rprobe team",
            priority: 4,
            enabled: true,
        }
    }

    fn should_run(&self, http_inner: &HttpInner) -> bool {
        if !http_inner.success() {
            let status = http_inner.status();
            if (500..600).contains(&status) {
                return true;
            }
            return false;
        }

        let headers = http_inner.headers();

        if let Some(powered_by) = headers.get("x-powered-by") {
            if let Ok(powered_str) = powered_by.to_str() {
                if powered_str.to_lowercase().contains("php") {
                    return true;
                }
            }
        }

        if let Some(server) = headers.get("server") {
            if let Ok(server_str) = server.to_str() {
                if server_str.to_lowercase().contains("php") {
                    return true;
                }
            }
        }

        for val in headers.get_all("set-cookie").iter() {
            if let Ok(cookie_str) = val.to_str() {
                if cookie_str.contains("PHPSESSID") {
                    return true;
                }
            }
        }

        true
    }

    fn run(&self, http_inner: &HttpInner) -> Result<Option<PluginResult>, PluginError> {
        debug!("Starting PHP Basic detection for URL: {}", http_inner.url());

        let mut detections: Vec<String> = Vec::new();
        let mut confidence_score = 0u8;
        let headers = http_inner.headers();

        if let Some(x_powered_by) = headers.get("x-powered-by") {
            let header_value = x_powered_by.to_str().unwrap_or("");
            if let Some(captures) = PHP_VERSION_REGEX.captures(header_value) {
                let version = captures.get(1).map_or("", |m| m.as_str());
                debug!("PHP detected: X-Powered-By Header with version {}", version);
                detections.push(format!("XPoweredBy[PHP/{}]", version));
                confidence_score = confidence_score.saturating_add(5);
            } else if header_value.to_lowercase().contains("php") {
                debug!("PHP detected: X-Powered-By Header contains PHP");
                detections.push("XPoweredBy[PHP]".to_string());
                confidence_score = confidence_score.saturating_add(4);
            }
        }

        if let Some(server_header) = headers.get("server") {
            let server_value = server_header.to_str().unwrap_or("");
            if let Some(captures) = PHP_VERSION_REGEX.captures(server_value) {
                let version = captures.get(1).map_or("", |m| m.as_str());
                debug!("PHP detected: Server Header with version {}", version);
                detections.push(format!("HTTPServer[PHP/{}]", version));
                confidence_score = confidence_score.saturating_add(4);
            } else if server_value.to_lowercase().contains("php") {
                debug!("PHP detected: Server Header contains PHP");
                detections.push("HTTPServer[PHP]".to_string());
                confidence_score = confidence_score.saturating_add(3);
            }
        }

        for val in headers.get_all("set-cookie").iter() {
            let cookie_str = val.to_str().unwrap_or("");
            if cookie_str.contains("PHPSESSID") {
                debug!("PHP detected: PHPSESSID Cookie found");
                detections.push("Cookie[PHPSESSID]".to_string());
                confidence_score = confidence_score.saturating_add(4);
            }
        }

        let body = http_inner.body();
        if !body.is_empty() && body.len() < 100000 {
            let body_matches = BODY_PATTERNS.find_matches(body);
            for description in body_matches {
                debug!("PHP detected: Body pattern {} found", description);
                detections.push(description.to_string());
                let pattern_confidence = PATTERN_CONFIDENCE.get(description).copied().unwrap_or(1);
                confidence_score = confidence_score.saturating_add(pattern_confidence);
            }
        }

        if detections.is_empty() || confidence_score < 2 {
            debug!("No confident PHP detection for URL: {}", http_inner.url());
            return Ok(None);
        }

        let order = vec![
            "XPoweredBy[PHP/".to_string(),
            "HTTPServer[PHP/".to_string(),
            "XPoweredBy[PHP]".to_string(),
            "HTTPServer[PHP]".to_string(),
            "Cookie[PHPSESSID]".to_string(),
            "PHPCode".to_string(),
            "PHPWarning".to_string(),
            "PHPParseError".to_string(),
            "PHPFatalError".to_string(),
            "PHPNotice".to_string(),
            "PHPDeprecated".to_string(),
        ];

        detections.sort_by_key(|det| {
            order
                .iter()
                .position(|o| {
                    if o.ends_with('/') {
                        det.starts_with(o)
                    } else {
                        det == o
                    }
                })
                .unwrap_or(order.len())
        });

        detections.dedup();

        let final_confidence = std::cmp::min(confidence_score, 8);
        let detection_info = format!("PHP Scripting Language ({})", detections.join(", "));

        info!(
            "PHP detected: {} (confidence: {}/10)",
            detection_info, final_confidence
        );

        Ok(Some(PluginResult {
            plugin_name: self.metadata().name.to_string(),
            detection_info,
            confidence: final_confidence,
            execution_time_ms: 0,
            category: PluginCategory::ApplicationFramework,
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
        let plugin = PHPBasicPlugin;
        let metadata = plugin.metadata();

        assert_eq!(metadata.name, "PHP Basic");
        assert_eq!(metadata.version, "1.2.0");
        assert_eq!(metadata.category, PluginCategory::ApplicationFramework);
        assert_eq!(metadata.author, "rprobe team");
        assert_eq!(metadata.priority, 4);
        assert!(metadata.enabled);
        assert!(metadata.description.contains("PHP"));
    }

    #[test]
    fn test_x_powered_by_php_version() {
        let plugin = PHPBasicPlugin;
        let http_inner = create_test_http_inner("", vec![("x-powered-by", "PHP/8.0.0")]);

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        assert!(plugin_result
            .detection_info
            .contains("XPoweredBy[PHP/8.0.0]"));
        assert!(plugin_result.confidence >= 5);
    }

    #[test]
    fn test_x_powered_by_php_generic() {
        let plugin = PHPBasicPlugin;
        let http_inner = create_test_http_inner("", vec![("x-powered-by", "PHP")]);

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        assert!(plugin_result.detection_info.contains("XPoweredBy[PHP]"));
        assert!(plugin_result.confidence >= 4);
    }

    #[test]
    fn test_server_header_php_version() {
        let plugin = PHPBasicPlugin;
        let http_inner =
            create_test_http_inner("", vec![("server", "Apache/2.4.41 (Ubuntu) PHP/7.4.3")]);

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        assert!(plugin_result
            .detection_info
            .contains("HTTPServer[PHP/7.4.3]"));
        assert!(plugin_result.confidence >= 4);
    }

    #[test]
    fn test_phpsessid_cookie() {
        let plugin = PHPBasicPlugin;
        let http_inner = create_test_http_inner(
            "",
            vec![("set-cookie", "PHPSESSID=abc123def456; path=/; HttpOnly")],
        );

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        assert!(plugin_result.detection_info.contains("Cookie[PHPSESSID]"));
        assert!(plugin_result.confidence >= 4);
    }

    #[test]
    fn test_php_code_in_body() {
        let plugin = PHPBasicPlugin;
        let http_inner = create_test_http_inner("<?php echo 'Hello World'; ?>", vec![]);

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        assert!(plugin_result.detection_info.contains("PHPCode"));
        assert!(plugin_result.confidence >= 4);
    }

    #[test]
    fn test_php_warning_in_body() {
        let plugin = PHPBasicPlugin;
        let http_inner = create_test_http_inner("PHP Warning: Division by zero", vec![]);

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        assert!(plugin_result.detection_info.contains("PHPWarning"));
        assert!(plugin_result.confidence >= 3);
    }

    #[test]
    fn test_php_parse_error() {
        let plugin = PHPBasicPlugin;
        let http_inner =
            create_test_http_inner("PHP Parse error: syntax error, unexpected token", vec![]);

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        assert!(plugin_result.detection_info.contains("PHPParseError"));
        assert!(plugin_result.confidence >= 3);
    }

    #[test]
    fn test_php_fatal_error() {
        let plugin = PHPBasicPlugin;
        let http_inner = create_test_http_inner(
            "Fatal error: Uncaught Error: Call to undefined function",
            vec![],
        );

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        assert!(plugin_result.detection_info.contains("PHPFatalError"));
        assert!(plugin_result.confidence >= 3);
    }

    #[test]
    fn test_php_notice() {
        let plugin = PHPBasicPlugin;
        let http_inner = create_test_http_inner("Notice: Undefined variable: test", vec![]);

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        assert!(plugin_result.detection_info.contains("PHPNotice"));
        assert!(plugin_result.confidence >= 2);
    }

    #[test]
    fn test_php_deprecated() {
        let plugin = PHPBasicPlugin;
        let http_inner = create_test_http_inner(
            "Deprecated: Function create_function() is deprecated",
            vec![],
        );

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        assert!(plugin_result.detection_info.contains("PHPDeprecated"));
        assert!(plugin_result.confidence >= 2);
    }

    #[test]
    fn test_multiple_detections() {
        let plugin = PHPBasicPlugin;
        let http_inner = create_test_http_inner(
            "<?php echo 'Hello'; ?>\nPHP Warning: Notice",
            vec![
                ("x-powered-by", "PHP/8.0.0"),
                ("set-cookie", "PHPSESSID=abc123; path=/"),
            ],
        );

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        assert!(plugin_result
            .detection_info
            .contains("XPoweredBy[PHP/8.0.0]"));
        assert!(plugin_result.detection_info.contains("Cookie[PHPSESSID]"));
        assert!(plugin_result.detection_info.contains("PHPCode"));
        assert!(plugin_result.detection_info.contains("PHPWarning"));
        assert_eq!(plugin_result.confidence, 8);
    }

    #[test]
    fn test_no_detection() {
        let plugin = PHPBasicPlugin;
        let http_inner = create_test_http_inner("", vec![]);

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_should_run_failed_request() {
        let plugin = PHPBasicPlugin;
        let mut http_inner = create_test_http_inner("", vec![]);
        http_inner.set_success(false);
        http_inner.set_status(404);

        assert!(!plugin.should_run(&http_inner));
    }

    #[test]
    fn test_should_run_server_error() {
        let plugin = PHPBasicPlugin;
        let mut http_inner = create_test_http_inner("", vec![]);
        http_inner.set_success(false);
        http_inner.set_status(500);

        assert!(plugin.should_run(&http_inner));
    }

    #[test]
    fn test_should_run_with_php_header() {
        let plugin = PHPBasicPlugin;
        let http_inner = create_test_http_inner("", vec![("x-powered-by", "PHP/7.4")]);

        assert!(plugin.should_run(&http_inner));
    }

    #[test]
    fn test_should_run_with_phpsessid() {
        let plugin = PHPBasicPlugin;
        let http_inner = create_test_http_inner("", vec![("set-cookie", "PHPSESSID=test")]);

        assert!(plugin.should_run(&http_inner));
    }

    #[test]
    fn test_large_body_skipped() {
        let plugin = PHPBasicPlugin;
        let large_content = "<?php ".repeat(20000);
        let http_inner = create_test_http_inner(&large_content, vec![]);

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_confidence_scoring() {
        let plugin = PHPBasicPlugin;

        let test_cases = vec![
            (("", vec![("x-powered-by", "PHP/8.0.0")]), 5),
            (("", vec![("x-powered-by", "PHP")]), 4),
            (("", vec![("set-cookie", "PHPSESSID=test")]), 4),
            (("<?php echo 'test'; ?>", vec![]), 4),
            (("PHP Warning: test", vec![]), 3),
            (("Notice: Undefined variable", vec![]), 2),
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
        let plugin = PHPBasicPlugin;
        let http_inner = create_test_http_inner("", vec![("x-powered-by", "PHP/7.4")]);

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        assert_eq!(plugin_result.plugin_name, "PHP Basic");
        assert_eq!(plugin_result.category, PluginCategory::ApplicationFramework);
    }

    #[test]
    fn test_version_regex() {
        let plugin = PHPBasicPlugin;

        let test_cases = vec![
            ("PHP/8.0.0", "8.0.0"),
            ("PHP/7.4.3", "7.4.3"),
            ("PHP 5.6", "5.6"),
            ("Apache/2.4.41 PHP/7.2.24", "7.2.24"),
        ];

        for (input, expected_version) in test_cases {
            let http_inner = create_test_http_inner("", vec![("x-powered-by", input)]);
            let result = plugin.run(&http_inner).unwrap();

            assert!(result.is_some());
            let plugin_result = result.unwrap();
            assert!(plugin_result
                .detection_info
                .contains(&format!("PHP/{}", expected_version)));
        }
    }

    #[test]
    fn test_deduplication() {
        let plugin = PHPBasicPlugin;
        let http_inner = create_test_http_inner(
            "<?php echo 'test'; ?> <?php echo 'again'; ?>",
            vec![("x-powered-by", "PHP/7.4")],
        );

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        let detection_info = &plugin_result.detection_info;

        let php_code_count = detection_info.matches("PHPCode").count();
        assert_eq!(php_code_count, 1);
    }
}
