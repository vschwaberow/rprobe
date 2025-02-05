// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2025
// - Volker Schwaberow <volker@schwaberow.de>

use crate::httpinner::HttpInner;
use crate::plugins::Plugin;
use log::info;
use regex::Regex;

pub struct WordpressBasicPlugin;

impl Plugin for WordpressBasicPlugin {
    fn name(&self) -> &'static str {
        "Wordpress Basic"
    }

    fn run(&self, http_inner: &HttpInner) -> Option<String> {
        let body_patterns = [
            (r#"(?i)<meta\s+name="generator"\s+content="WordPress"#, "Meta Generator"),
            (r"(?i)wp-content", "WP Content"),
            (r"(?i)wp-includes", "WP Includes"),
        ];

        let mut detections: Vec<&'static str> = Vec::new();

        for (pattern, description) in &body_patterns {
            let re = Regex::new(pattern).unwrap();
            if re.is_match(http_inner.body()) {
                info!("WordPress detected in body: {}", description);
                detections.push(description);
            }
        }
        
        let api_pattern = r#"(?i)<link\s+rel=["']https://api\.w\.org/["']"#;
        let re = Regex::new(api_pattern).unwrap();
        if re.is_match(http_inner.body()) {
            info!("WordPress detected: API Link found");
            detections.push("WordPress API Link");
        }

        if !detections.is_empty() {
            detections.sort();
            detections.dedup();
            let detection_message = detections.join(", ");
            Some(format!("WordPress Detected: {}", detection_message))
        } else {
            None
        }
    }
}