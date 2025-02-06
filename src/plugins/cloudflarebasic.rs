// File: cloudflarebasic.rs
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024
// - Volker Schwaberow <volker@schwaberow.de>

use crate::httpinner::HttpInner;
use crate::plugins::Plugin;
use log::info;
use once_cell::sync::Lazy;
use regex::{Regex, RegexBuilder};

pub struct CloudflareBasicPlugin;

static HEADER_PATTERNS: Lazy<Vec<(Regex, &str)>> = Lazy::new(|| {
    vec![
        (
            RegexBuilder::new(r"^cloudflare$")
                .case_insensitive(true)
                .build()
                .unwrap(),
            "Server Header",
        ),
        (
            RegexBuilder::new(r"^cloudflare/\d+\.\d+$")
                .case_insensitive(true)
                .build()
                .unwrap(),
            "Server Version Header",
        ),
        (Regex::new(r"^CF-RAY$").unwrap(), "CF-RAY Header"),
        (Regex::new(r"^CF-Cache-Status$").unwrap(), "CF-Cache-Status Header"),
        (Regex::new(r"^CF-Connecting-IP$").unwrap(), "CF-Connecting-IP Header"),
    ]
});

static BODY_PATTERNS: Lazy<Vec<(Regex, &str)>> = Lazy::new(|| {
    vec![
        (
            Regex::new(r"Attention Required!|Cloudflare").unwrap(),
            "Cloudflare Challenge Page",
        ),
        (Regex::new(r"Error 1006").unwrap(), "Cloudflare Error 1006"),
        (
            Regex::new(r"Access denied|Cloudflare").unwrap(),
            "Cloudflare Access Denied",
        ),
    ]
});

impl Plugin for CloudflareBasicPlugin {
    fn name(&self) -> &'static str {
        "Cloudflare Basic"
    }

    fn run(&self, http_inner: &HttpInner) -> Option<String> {
        let mut detections: Vec<&'static str> = Vec::new();

        // Check for headers in "Server"
        if let Some(server_header_value) = http_inner.headers().get("Server") {
            let server_value = server_header_value.to_str().unwrap_or("");
            for (re, description) in HEADER_PATTERNS.iter() {
                if re.is_match(server_value) {
                    info!("Cloudflare detected in header: {}", description);
                    detections.push(*description);
                }
            }
        }

        // Try checking headers by their name if present
        for (pattern, description) in HEADER_PATTERNS.iter() {
            if let Some(header_value) = http_inner.headers().get(pattern.as_str()) {
                let header_str = header_value.to_str().unwrap_or("");
                if !header_str.is_empty() {
                    info!("Cloudflare detected with header {}: {}", pattern.as_str(), description);
                    detections.push(*description);
                }
            }
        }

        for (re, description) in BODY_PATTERNS.iter() {
            if re.is_match(http_inner.body()) {
                info!("Cloudflare detected in body: {}", description);
                detections.push(*description);
            }
        }

        if !detections.is_empty() {
            let order = vec![
                "Server Header",
                "Server Version Header",
                "CF-RAY Header",
                "CF-Cache-Status Header",
                "CF-Connecting-IP Header",
                "Cloudflare Challenge Page",
                "Cloudflare Error 1006",
                "Cloudflare Access Denied",
            ];

            detections.sort_by_key(|det| order.iter().position(|&o| o == *det).unwrap_or(order.len()));
            detections.dedup();
            let detection_message = detections.join(", ");
            Some(format!("Cloudflare Detected: {}", detection_message))
        } else {
            None
        }
    }
}