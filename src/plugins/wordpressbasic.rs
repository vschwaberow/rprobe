// File: wordpressbasic.rs
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2025
// - Volker Schwaberow <volker@schwaberow.de>

use crate::httpinner::HttpInner;
use crate::plugins::Plugin;
use log::info;
use once_cell::sync::Lazy;
use regex::Regex;

pub struct WordpressBasicPlugin;

static BODY_PATTERNS: Lazy<Vec<(Regex, &str)>> = Lazy::new(|| {
    vec![
        (
            Regex::new(r#"(?i)<meta\s+name="generator"\s+content="WordPress"#).unwrap(),
            "Meta Generator",
        ),
        (Regex::new(r"(?i)wp-content").unwrap(), "WP Content"),
        (Regex::new(r"(?i)wp-includes").unwrap(), "WP Includes"),
    ]
});

static API_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)<link\s+rel=["']https://api\.w\.org/["']"#).unwrap()
});

impl Plugin for WordpressBasicPlugin {
    fn name(&self) -> &'static str {
        "Wordpress Basic"
    }

    fn run(&self, http_inner: &HttpInner) -> Option<String> {
        let mut detections: Vec<&'static str> = Vec::new();

        for (re, description) in BODY_PATTERNS.iter() {
            if re.is_match(http_inner.body()) {
                info!("WordPress detected in body: {}", description);
                detections.push(*description);
            }
        }
        
        if API_PATTERN.is_match(http_inner.body()) {
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