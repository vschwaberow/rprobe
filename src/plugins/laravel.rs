// File: laravel.rs
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023-2025
// - Volker Schwaberow <volker@schwaberow.de>

use crate::httpinner::HttpInner;
use crate::plugins::{Plugin, PluginCategory, PluginError, PluginMetadata, PluginResult};
use log::{debug, info};
use once_cell::sync::Lazy;
use regex::Regex;

pub struct LaravelPlugin;

static LARAVEL_BODY_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)laravel").expect("Failed to compile Laravel regex"));

impl Plugin for LaravelPlugin {
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: "Laravel",
            version: "1.1.0",
            description: "Laravel PHP framework detection through session cookies, headers, and content analysis.",
            category: PluginCategory::ApplicationFramework,
            author: "rprobe team",
            priority: 4,
            enabled: true,
        }
    }

    fn should_run(&self, http_inner: &HttpInner) -> bool {
        if !http_inner.success() {
            return false;
        }

        if let Some(powered_by) = http_inner.headers().get("x-powered-by") {
            if let Ok(powered_str) = powered_by.to_str() {
                if powered_str.to_lowercase().contains("php") {
                    return true;
                }
            }
        }

        let mut has_laravel_cookie = false;
        for val in http_inner.headers().get_all("set-cookie").iter() {
            if let Ok(cookie_str) = val.to_str() {
                if cookie_str.to_lowercase().contains("laravel_session") {
                    has_laravel_cookie = true;
                    break;
                }
            }
        }
        if has_laravel_cookie {
            return true;
        }

        true
    }

    fn run(&self, http_inner: &HttpInner) -> Result<Option<PluginResult>, PluginError> {
        debug!("Starting Laravel detection for URL: {}", http_inner.url());

        let mut detections = Vec::new();
        let mut confidence_score = 0u8;
        let headers = http_inner.headers();
        let body = http_inner.body();

        for val in headers.get_all("set-cookie").iter() {
            if let Ok(cookie_str) = val.to_str() {
                let cookie_lower = cookie_str.to_lowercase();
                if cookie_lower.contains("laravel_session") {
                    info!("Laravel: Laravel session cookie detected");
                    detections.push("Cookie[Laravel_Session]".to_string());
                    confidence_score = confidence_score.saturating_add(4);
                }
                if cookie_lower.contains("xsrf-token") {
                    debug!("Laravel: CSRF token cookie detected");
                    detections.push("Cookie[CSRF_Token]".to_string());
                    confidence_score = confidence_score.saturating_add(2);
                }
            }
        }

        if let Some(x_powered_by) = headers.get("x-powered-by") {
            if let Ok(powered_by) = x_powered_by.to_str() {
                if powered_by.to_lowercase().contains("laravel") {
                    info!("Laravel: X-Powered-By header contains Laravel");
                    detections.push("Header[X-Powered-By]".to_string());
                    confidence_score = confidence_score.saturating_add(3);
                }
            }
        }

        if headers.get("x-csrf-token").is_some() {
            debug!("Laravel: CSRF token header detected");
            detections.push("Header[CSRF_Token]".to_string());
            confidence_score = confidence_score.saturating_add(2);
        }

        if !body.is_empty() && body.len() < 150_000 && LARAVEL_BODY_REGEX.is_match(body) {
            let body_lower = body.to_lowercase();

            let has_generic = body_lower.contains("laravel");
            if body_lower.contains("laravel mix")
                || body_lower.contains("laravel framework")
                || body_lower.contains("laravel.com")
            {
                info!("Laravel: Strong Laravel reference found in body");
                detections.push("Content[Laravel_Reference]".to_string());
                confidence_score = confidence_score.saturating_add(3);
            }
            if has_generic {
                debug!("Laravel: Generic Laravel mention found in body");
                detections.push("Content[Generic_Laravel]".to_string());
                let trimmed = body_lower.trim();
                if trimmed == "laravel" {
                    confidence_score = confidence_score.saturating_add(1);
                } else {
                    confidence_score = confidence_score.saturating_add(2);
                }
            }
        }

        if detections.is_empty() || confidence_score < 2 {
            debug!(
                "No confident Laravel detection for URL: {}",
                http_inner.url()
            );
            return Ok(None);
        }

        let final_confidence = std::cmp::min(confidence_score, 8);
        let detection_info = format!("Laravel framework ({})", detections.join(", "));

        info!(
            "Laravel detected: {} (confidence: {}/10)",
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

    fn name(&self) -> &'static str {
        self.metadata().name
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
            let name = HeaderName::from_str(key).unwrap();
            let val = HeaderValue::from_str(value).unwrap();
            if header_map.contains_key(&name) {
                header_map.append(name, val);
            } else {
                header_map.insert(name, val);
            }
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
        let plugin = LaravelPlugin;
        let metadata = plugin.metadata();

        assert_eq!(metadata.name, "Laravel");
        assert_eq!(metadata.version, "1.1.0");
        assert_eq!(metadata.category, PluginCategory::ApplicationFramework);
        assert_eq!(metadata.author, "rprobe team");
        assert_eq!(metadata.priority, 4);
        assert!(metadata.enabled);
        assert!(metadata.description.contains("Laravel"));
    }

    #[test]
    fn test_should_run_failed_request() {
        let plugin = LaravelPlugin;
        let mut http_inner = create_test_http_inner("test", vec![]);
        http_inner.set_success(false);

        assert!(!plugin.should_run(&http_inner));
    }

    #[test]
    fn test_should_run_with_php_header() {
        let plugin = LaravelPlugin;
        let http_inner = create_test_http_inner("test", vec![("x-powered-by", "PHP/8.0.0")]);

        assert!(plugin.should_run(&http_inner));
    }

    #[test]
    fn test_should_run_with_laravel_session() {
        let plugin = LaravelPlugin;
        let http_inner = create_test_http_inner(
            "test",
            vec![("set-cookie", "laravel_session=abc123; path=/")],
        );

        assert!(plugin.should_run(&http_inner));
    }

    #[test]
    fn test_should_run_regular_content() {
        let plugin = LaravelPlugin;
        let http_inner = create_test_http_inner("regular content", vec![]);

        assert!(plugin.should_run(&http_inner));
    }

    #[test]
    fn test_laravel_session_cookie_detection() {
        let plugin = LaravelPlugin;
        let http_inner = create_test_http_inner(
            "",
            vec![(
                "set-cookie",
                "laravel_session=abc123def456; path=/; httponly",
            )],
        );

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        assert!(plugin_result
            .detection_info
            .contains("Cookie[Laravel_Session]"));
        assert!(plugin_result.confidence >= 4);
    }

    #[test]
    fn test_csrf_token_cookie_detection() {
        let plugin = LaravelPlugin;
        let http_inner =
            create_test_http_inner("", vec![("set-cookie", "XSRF-TOKEN=xyz789; secure")]);

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        assert!(plugin_result.detection_info.contains("Cookie[CSRF_Token]"));
        assert!(plugin_result.confidence >= 2);
    }

    #[test]
    fn test_x_powered_by_header_laravel() {
        let plugin = LaravelPlugin;
        let http_inner = create_test_http_inner("", vec![("x-powered-by", "Laravel Framework")]);

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        assert!(plugin_result
            .detection_info
            .contains("Header[X-Powered-By]"));
        assert!(plugin_result.confidence >= 3);
    }

    #[test]
    fn test_csrf_token_header() {
        let plugin = LaravelPlugin;
        let http_inner = create_test_http_inner("", vec![("x-csrf-token", "abcd1234efgh5678")]);

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        assert!(plugin_result.detection_info.contains("Header[CSRF_Token]"));
        assert!(plugin_result.confidence >= 2);
    }

    #[test]
    fn test_laravel_mix_content() {
        let plugin = LaravelPlugin;
        let http_inner =
            create_test_http_inner("This site was built with Laravel Mix and webpack", vec![]);

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        assert!(plugin_result
            .detection_info
            .contains("Content[Laravel_Reference]"));
        assert!(plugin_result.confidence >= 3);
    }

    #[test]
    fn test_laravel_framework_content() {
        let plugin = LaravelPlugin;
        let http_inner = create_test_http_inner("Powered by Laravel Framework version 9", vec![]);

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        assert!(plugin_result
            .detection_info
            .contains("Content[Laravel_Reference]"));
        assert!(plugin_result.confidence >= 3);
    }

    #[test]
    fn test_laravel_com_reference() {
        let plugin = LaravelPlugin;
        let http_inner = create_test_http_inner("Visit laravel.com for more information", vec![]);

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        assert!(plugin_result
            .detection_info
            .contains("Content[Laravel_Reference]"));
        assert!(plugin_result.confidence >= 3);
    }

    #[test]
    fn test_generic_laravel_mention() {
        let plugin = LaravelPlugin;
        let http_inner = create_test_http_inner("I learned Laravel last year", vec![]);

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        assert!(plugin_result
            .detection_info
            .contains("Content[Generic_Laravel]"));
        assert!(plugin_result.confidence >= 1);
    }

    #[test]
    fn test_multiple_detections() {
        let plugin = LaravelPlugin;
        let http_inner = create_test_http_inner(
            "This Laravel application uses Laravel Mix",
            vec![
                ("set-cookie", "laravel_session=abc123; path=/"),
                ("x-csrf-token", "token123"),
                ("x-powered-by", "Laravel Framework"),
            ],
        );

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        assert!(plugin_result
            .detection_info
            .contains("Cookie[Laravel_Session]"));
        assert!(plugin_result.detection_info.contains("Header[CSRF_Token]"));
        assert!(plugin_result
            .detection_info
            .contains("Header[X-Powered-By]"));
        assert!(plugin_result
            .detection_info
            .contains("Content[Laravel_Reference]"));
        assert_eq!(plugin_result.confidence, 8);
    }

    #[test]
    fn test_case_insensitive_content() {
        let plugin = LaravelPlugin;
        let http_inner = create_test_http_inner("Built with LARAVEL framework", vec![]);

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        assert!(plugin_result
            .detection_info
            .contains("Content[Generic_Laravel]"));
    }

    #[test]
    fn test_no_detection_empty_content() {
        let plugin = LaravelPlugin;
        let http_inner = create_test_http_inner("", vec![]);

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_no_detection_unrelated_content() {
        let plugin = LaravelPlugin;
        let http_inner = create_test_http_inner("This is a Django application", vec![]);

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_large_body_skipped() {
        let plugin = LaravelPlugin;
        let large_content = "Laravel ".repeat(20000);
        let http_inner = create_test_http_inner(&large_content, vec![]);

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_low_confidence_threshold() {
        let plugin = LaravelPlugin;
        let http_inner = create_test_http_inner("Laravel", vec![]);

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_confidence_scoring() {
        let plugin = LaravelPlugin;

        let test_cases = vec![
            (("", vec![("set-cookie", "laravel_session=abc123")]), 4),
            (("Laravel framework content", vec![]), 3),
            (("", vec![("x-powered-by", "Laravel")]), 3),
            (("", vec![("x-csrf-token", "token")]), 2),
            (("", vec![("set-cookie", "XSRF-TOKEN=abc")]), 2),
            (("Just laravel", vec![]), 1),
        ];

        for ((body, headers), expected_min_confidence) in test_cases {
            let http_inner = create_test_http_inner(body, headers);
            let result = plugin.run(&http_inner).unwrap();

            if expected_min_confidence >= 2 {
                assert!(result.is_some());
                let plugin_result = result.unwrap();
                assert!(plugin_result.confidence >= expected_min_confidence);
            }
        }
    }

    #[test]
    fn test_multiple_cookies() {
        let plugin = LaravelPlugin;
        let http_inner = create_test_http_inner(
            "",
            vec![
                ("set-cookie", "laravel_session=abc123; path=/"),
                ("set-cookie", "XSRF-TOKEN=xyz789; secure"),
            ],
        );

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        assert!(plugin_result
            .detection_info
            .contains("Cookie[Laravel_Session]"));
        assert!(plugin_result.detection_info.contains("Cookie[CSRF_Token]"));
        assert!(plugin_result.confidence >= 6);
    }

    #[test]
    fn test_plugin_name_consistency() {
        let plugin = LaravelPlugin;
        let http_inner = create_test_http_inner("", vec![("set-cookie", "laravel_session=abc123")]);

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        assert_eq!(plugin_result.plugin_name, "Laravel");
        assert_eq!(plugin_result.category, PluginCategory::ApplicationFramework);
    }

    #[test]
    fn test_name_method() {
        let plugin = LaravelPlugin;
        assert_eq!(plugin.name(), "Laravel");
    }

    #[test]
    fn test_x_powered_by_case_insensitive() {
        let plugin = LaravelPlugin;
        let http_inner = create_test_http_inner("", vec![("x-powered-by", "LARAVEL FRAMEWORK V9")]);

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        assert!(plugin_result
            .detection_info
            .contains("Header[X-Powered-By]"));
    }

    #[test]
    fn test_empty_body_content() {
        let plugin = LaravelPlugin;
        let http_inner = create_test_http_inner("", vec![("x-csrf-token", "token123")]);

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        assert!(plugin_result.detection_info.contains("Header[CSRF_Token]"));
    }

    #[test]
    fn test_body_length_boundary() {
        let plugin = LaravelPlugin;
        let boundary_content = "Laravel ".repeat(14285);
        let http_inner = create_test_http_inner(&boundary_content, vec![]);

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        assert!(plugin_result.detection_info.contains("Content"));
    }
}
