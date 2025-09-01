// File: wordpressbasic.rs
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023-2025
// - Volker Schwaberow <volker@schwaberow.de>

#![allow(clippy::useless_vec)]

use crate::httpinner::HttpInner;
use crate::plugins::pattern_matcher::OptimizedPatternMatcher;
use crate::plugins::{Plugin, PluginCategory, PluginError, PluginMetadata, PluginResult};
use log::{debug, info};
use once_cell::sync::Lazy;
use regex::Regex;

pub struct WordpressBasicPlugin;

// Optimized body patterns - separate literal and regex patterns
static BODY_PATTERNS: Lazy<OptimizedPatternMatcher> = Lazy::new(|| {
    OptimizedPatternMatcher::new(
        &[
            ("wp-content", "WP Content"),
            ("wp-includes", "WP Includes"),
            ("WordPress", "WordPress Reference"),
        ],
        &[
            (r#"(?i)<meta\s+name="generator"\s+content="WordPress[^"]*""#, "Meta Generator"),
        ],
    )
});

static API_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)<link\s+rel=['"]https://api\.w\.org/['"]"#).unwrap());

// Confidence mapping for body patterns
static PATTERN_CONFIDENCE: Lazy<std::collections::HashMap<&'static str, u8>> = Lazy::new(|| {
    [
        ("Meta Generator", 5u8),
        ("WP Content", 3u8),
        ("WP Includes", 3u8),
        ("WordPress Reference", 2u8),
    ]
    .iter()
    .cloned()
    .collect()
});

impl Plugin for WordpressBasicPlugin {
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: "WordPress Basic",
            version: "1.2.0",
            description:
                "WordPress CMS detection through meta tags, directory structures, and API endpoints",
            category: PluginCategory::ContentManagementSystem,
            author: "rprobe team",
            priority: 5,
            enabled: true,
        }
    }

    fn should_run(&self, http_inner: &HttpInner) -> bool {
        if !http_inner.success() {
            return false;
        }

        let body = http_inner.body();

        if body.contains("wp-content") || body.contains("wp-includes") || body.contains("WordPress")
        {
            return true;
        }

        if let Some(powered_by) = http_inner.headers().get("x-powered-by") {
            if let Ok(powered_str) = powered_by.to_str() {
                if powered_str.to_lowercase().contains("php") {
                    return true;
                }
            }
        }

        true
    }

    fn run(&self, http_inner: &HttpInner) -> Result<Option<PluginResult>, PluginError> {
        debug!(
            "Starting WordPress Basic detection for URL: {}",
            http_inner.url()
        );

        let mut detections: Vec<&'static str> = Vec::new();
        let mut confidence_score = 0u8;
        let body = http_inner.body();

        // Use optimized pattern matcher for body analysis
        let body_matches = BODY_PATTERNS.find_matches(body);
        for description in body_matches {
            debug!("WordPress detected in body: {}", description);
            detections.push(description);

            let pattern_confidence = PATTERN_CONFIDENCE.get(description).copied().unwrap_or(2);
            confidence_score = confidence_score.saturating_add(pattern_confidence);
        }

        // Check API pattern separately
        if API_PATTERN.is_match(body) {
            debug!("WordPress detected: API Link found");
            detections.push("WordPress API Link");
            confidence_score = confidence_score.saturating_add(4);
        }

        if detections.is_empty() || confidence_score < 2 {
            debug!(
                "No confident WordPress detection for URL: {}",
                http_inner.url()
            );
            return Ok(None);
        }

        let order = vec![
            "Meta Generator",
            "WordPress API Link",
            "WP Content",
            "WP Includes",
            "WordPress Reference",
        ];

        detections.sort_by_key(|det| order.iter().position(|&o| o == *det).unwrap_or(order.len()));
        detections.dedup();

        let final_confidence = std::cmp::min(confidence_score, 8);
        let detection_info = format!("WordPress CMS ({})", detections.join(", "));

        info!(
            "WordPress detected: {} (confidence: {}/10)",
            detection_info, final_confidence
        );

        Ok(Some(PluginResult {
            plugin_name: self.metadata().name.to_string(),
            detection_info,
            confidence: final_confidence,
            execution_time_ms: 0,
            category: PluginCategory::ContentManagementSystem,
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
        let plugin = WordpressBasicPlugin;
        let metadata = plugin.metadata();

        assert_eq!(metadata.name, "WordPress Basic");
        assert_eq!(metadata.version, "1.2.0");
        assert_eq!(metadata.category, PluginCategory::ContentManagementSystem);
        assert_eq!(metadata.author, "rprobe team");
        assert_eq!(metadata.priority, 5);
        assert!(metadata.enabled);
        assert!(metadata.description.contains("WordPress"));
    }

    #[test]
    fn test_should_run_successful_request() {
        let plugin = WordpressBasicPlugin;
        let http_inner = create_test_http_inner("test content", vec![]);

        assert!(plugin.should_run(&http_inner));
    }

    #[test]
    fn test_should_run_failed_request() {
        let plugin = WordpressBasicPlugin;
        let mut http_inner = create_test_http_inner("test content", vec![]);
        http_inner.set_success(false);

        assert!(!plugin.should_run(&http_inner));
    }

    #[test]
    fn test_should_run_wordpress_content() {
        let plugin = WordpressBasicPlugin;
        let http_inner = create_test_http_inner("This site uses wp-content directory", vec![]);

        assert!(plugin.should_run(&http_inner));
    }

    #[test]
    fn test_should_run_wordpress_includes() {
        let plugin = WordpressBasicPlugin;
        let http_inner = create_test_http_inner("Loading from wp-includes folder", vec![]);

        assert!(plugin.should_run(&http_inner));
    }

    #[test]
    fn test_should_run_with_php_header() {
        let plugin = WordpressBasicPlugin;
        let http_inner = create_test_http_inner("test", vec![("x-powered-by", "PHP/8.0.0")]);

        assert!(plugin.should_run(&http_inner));
    }

    #[test]
    fn test_meta_generator_detection() {
        let plugin = WordpressBasicPlugin;
        let http_inner =
            create_test_http_inner(r#"<meta name="generator" content="WordPress 6.0">"#, vec![]);

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        assert!(plugin_result.detection_info.contains("Meta Generator"));
        assert!(plugin_result.confidence >= 5);
    }

    #[test]
    fn test_wp_content_detection() {
        let plugin = WordpressBasicPlugin;
        let http_inner = create_test_http_inner(
            r#"<link href="/wp-content/themes/twentytwenty/style.css" rel="stylesheet">"#,
            vec![],
        );

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        assert!(plugin_result.detection_info.contains("WP Content"));
        assert!(plugin_result.confidence >= 3);
    }

    #[test]
    fn test_wp_includes_detection() {
        let plugin = WordpressBasicPlugin;
        let http_inner = create_test_http_inner(
            r#"<script src="/wp-includes/js/jquery.js"></script>"#,
            vec![],
        );

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        assert!(plugin_result.detection_info.contains("WP Includes"));
        assert!(plugin_result.confidence >= 3);
    }

    #[test]
    fn test_api_link_detection() {
        let plugin = WordpressBasicPlugin;
        let http_inner = create_test_http_inner(
            r#"<link rel='https://api.w.org/' href='https://example.com/wp-json/' />"#,
            vec![],
        );

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        assert!(plugin_result.detection_info.contains("WordPress API Link"));
        assert!(plugin_result.confidence >= 4);
    }

    #[test]
    fn test_multiple_detections() {
        let plugin = WordpressBasicPlugin;
        let http_inner = create_test_http_inner(
            r#"<html>
                <meta name="generator" content="WordPress 6.0">
                <link href="/wp-content/themes/style.css">
                <script src="/wp-includes/js/jquery.js"></script>
                <link rel='https://api.w.org/' href='https://example.com/wp-json/' />
            </html>"#,
            vec![],
        );

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        assert!(plugin_result.detection_info.contains("Meta Generator"));
        assert!(plugin_result.detection_info.contains("WP Content"));
        assert!(plugin_result.detection_info.contains("WP Includes"));
        assert!(plugin_result.detection_info.contains("WordPress API Link"));
        assert_eq!(plugin_result.confidence, 8);
    }

    #[test]
    fn test_case_insensitive_detection() {
        let plugin = WordpressBasicPlugin;
        let http_inner = create_test_http_inner(
            r#"<META NAME="GENERATOR" CONTENT="WordPress 6.0">"#, vec![]);

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        assert!(plugin_result.detection_info.contains("Meta Generator"));
    }

    #[test]
    fn test_no_detection_empty_content() {
        let plugin = WordpressBasicPlugin;
        let http_inner = create_test_http_inner("", vec![]);

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_no_detection_unrelated_content() {
        let plugin = WordpressBasicPlugin;
        let http_inner = create_test_http_inner(
            r#"<html><body><h1>Welcome to our site</h1><p>This is a regular website.</p></body></html>"#,
            vec![],
        );

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_low_confidence_threshold() {
        let plugin = WordpressBasicPlugin;
        let http_inner = create_test_http_inner("Just a mention of WordPress in text", vec![]);

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());
        
        let plugin_result = result.unwrap();
        assert!(plugin_result.detection_info.contains("WordPress Reference"));
        assert!(plugin_result.confidence >= 2);
    }

    #[test]
    fn test_detection_ordering() {
        let plugin = WordpressBasicPlugin;
        let http_inner = create_test_http_inner(
            r#"<html>
                <script src="/wp-includes/js/jquery.js"></script>
                <meta name="generator" content="WordPress 6.0">
                <link href="/wp-content/themes/style.css">
                <link rel='https://api.w.org/' href='https://example.com/wp-json/' />
            </html>"#,
            vec![],
        );

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        let detection_parts: Vec<&str> = plugin_result.detection_info.split(',').collect();

        let meta_pos = detection_parts
            .iter()
            .position(|&x| x.contains("Meta Generator"));
        let api_pos = detection_parts
            .iter()
            .position(|&x| x.contains("WordPress API Link"));
        let content_pos = detection_parts
            .iter()
            .position(|&x| x.contains("WP Content"));
        let includes_pos = detection_parts
            .iter()
            .position(|&x| x.contains("WP Includes"));

        assert!(meta_pos.is_some());
        assert!(api_pos.is_some());
        assert!(content_pos.is_some());
        assert!(includes_pos.is_some());

        assert!(meta_pos < api_pos);
        assert!(api_pos < content_pos);
        assert!(content_pos < includes_pos);
    }

    #[test]
    fn test_plugin_name_consistency() {
        let plugin = WordpressBasicPlugin;
        let http_inner = create_test_http_inner(
            r#"<meta name="generator" content="WordPress 6.0">"#,
            vec![],
        );

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        assert_eq!(plugin_result.plugin_name, "WordPress Basic");
        assert_eq!(
            plugin_result.category,
            PluginCategory::ContentManagementSystem
        );
    }

    #[test]
    fn test_confidence_scoring() {
        let plugin = WordpressBasicPlugin;

        let test_cases = vec![
            (r#"<meta name="generator" content="WordPress 6.0">"#, 5),
            (
                r#"<link rel='https://api.w.org/' href='https://example.com/wp-json/' />"#,
                4,
            ),
            (r#"<link href="/wp-content/themes/style.css">"#, 3),
            (r#"<script src="/wp-includes/js/jquery.js"></script>"#, 3),
            ("WordPress site content", 2),
        ];

        for (content, expected_min_confidence) in test_cases {
            let http_inner = create_test_http_inner(content, vec![]);
            let result = plugin.run(&http_inner).unwrap();

            assert!(result.is_some());
            let plugin_result = result.unwrap();
            assert!(plugin_result.confidence >= expected_min_confidence);
        }
    }

    #[test]
    fn test_deduplication() {
        let plugin = WordpressBasicPlugin;
        let http_inner = create_test_http_inner(
            r#"<html>
                <meta name="generator" content="WordPress 6.0">
                <meta name="generator" content="WordPress 6.0">
                <link href="/wp-content/themes/style.css">
                <link href="/wp-content/plugins/plugin.css">
            </html>"#,
            vec![],
        );

        let result = plugin.run(&http_inner).unwrap();
        assert!(result.is_some());

        let plugin_result = result.unwrap();
        let detection_info = &plugin_result.detection_info;

        let meta_count = detection_info.matches("Meta Generator").count();
        let wp_content_count = detection_info.matches("WP Content").count();

        assert_eq!(meta_count, 1);
        assert_eq!(wp_content_count, 1);
    }
}