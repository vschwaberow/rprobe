// File: nginxbasic.rs
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023
// - Volker Schwaberow <volker@schwaberow.de>

use crate::httpinner::HttpInner;
use crate::plugins::Plugin;
use log::info;
use once_cell::sync::Lazy;
use regex::{Regex, RegexBuilder};

pub struct NginxBasicPlugin;

static BODY_PATTERNS: Lazy<Vec<(Regex, &str)>> = Lazy::new(|| {
    vec![
        (Regex::new(r"<title>Welcome to nginx!</title>").unwrap(), "Default Title"),
        (Regex::new(r"<h1>Welcome to nginx</h1>").unwrap(), "Header Message"),
        (Regex::new(r"<center>nginx</center>").unwrap(), "Centered Text"),
        (
            Regex::new(r"<hr><center>nginx/\d+\.\d+\.\d+</center>").unwrap(),
            "Version Info",
        ),
        (Regex::new(r"Thank you for using nginx").unwrap(), "Thank You Message"),
    ]
});

static HEADER_PATTERNS: Lazy<Vec<(Regex, &str)>> = Lazy::new(|| {
    vec![
        (
            RegexBuilder::new(r"^nginx$")
                .case_insensitive(true)
                .build()
                .unwrap(),
            "Server Header",
        ),
        (
            RegexBuilder::new(r"^nginx/\d+\.\d+\.\d+$")
                .case_insensitive(true)
                .build()
                .unwrap(),
            "Server Version Header",
        ),
        (
            RegexBuilder::new(r"^openresty$")
                .case_insensitive(true)
                .build()
                .unwrap(),
            "OpenResty Header",
        ),
        (
            RegexBuilder::new(r"^openresty/\d+\.\d+\.\d+\.\d+$")
                .case_insensitive(true)
                .build()
                .unwrap(),
            "OpenResty Version Header",
        ),
    ]
});

impl Plugin for NginxBasicPlugin {
    fn name(&self) -> &'static str {
        "Nginx Basic"
    }

    fn run(&self, http_inner: &HttpInner) -> Option<String> {
        let mut detections: Vec<&'static str> = Vec::new();

        for (re, description) in BODY_PATTERNS.iter() {
            if re.is_match(http_inner.body()) {
                info!("Nginx detected in body: {}", description);
                detections.push(*description);
            }
        }

        if let Some(server_header_value) = http_inner.headers().get("Server") {
            let server_value = server_header_value.to_str().unwrap_or("");
            for (re, description) in HEADER_PATTERNS.iter() {
                if re.is_match(server_value) {
                    info!("Nginx detected in header: {}", description);
                    detections.push(*description);
                }
            }
        }

        if let Some(powered_by) = http_inner.headers().get("X-Powered-By") {
            let powered_value = powered_by.to_str().unwrap_or("").to_lowercase();
            if powered_value.contains("nginx") {
                info!("Nginx detected in X-Powered-By header");
                detections.push("X-Powered-By Header");
            }
        }

        if !detections.is_empty() {
            let order = vec![
                "Default Title",
                "Header Message",
                "Centered Text",
                "Version Info",
                "Thank You Message",
                "Server Header",
                "Server Version Header",
                "OpenResty Header",
                "OpenResty Version Header",
                "X-Powered-By Header",
            ];

            detections.sort_by_key(|det| order.iter().position(|&o| o == *det).unwrap_or(order.len()));
            detections.dedup();
            let detection_message = detections.join(", ");
            Some(format!("Nginx Server Detected: {}", detection_message))
        } else {
            None
        }
    }
}