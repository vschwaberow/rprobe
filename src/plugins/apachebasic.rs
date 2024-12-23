// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023
// - Volker Schwaberow <volker@schwaberow.de>

use crate::httpinner::HttpInner;
use crate::plugins::Plugin;
use log::info;
use regex::Regex;
use regex::RegexBuilder;

pub struct ApacheBasicPlugin;

impl Plugin for ApacheBasicPlugin {
    fn name(&self) -> &'static str {
        "Apache Basic"
    }

    fn run(&self, http_inner: &HttpInner) -> Option<String> {
        let body_patterns = [
            (
                r"<html><body><h1>It works!</h1></body></html>",
                "Standard HTML Body",
            ),
            (
                r"<html>Apache is functioning normally</html>",
                "Apache Functioning Message",
            ),
            (
                r"<body><center>This IP is being shared among many domains\.<br>",
                "Shared IP Notice",
            ),
            (
                r"<html><head><title>Apache2 Ubuntu Default Page: It works</title></head>",
                "Ubuntu Default Page",
            ),
            (
                r"This IP is being shared among many domains\.",
                "Shared IP Message",
            ),
            (r"Apache\/\d+\.\d+\.\d+", "Apache Version Info"),
        ];

        let header_patterns = [
            (r"^Apache$", "Server Header"),
            (r"^Apache/\d+\.\d+(\.\d+)?$", "Server Version Header"),
            (r"(?i)apache", "Server Header Contains 'Apache'"),
        ];

        let mut detections = Vec::new();

        for (pattern, description) in &body_patterns {
            let re = Regex::new(pattern).unwrap();
            if re.is_match(http_inner.body()) {
                info!("Apache detected in body: {}", description);
                detections.push(*description);
            }
        }

        for (pattern, description) in &header_patterns {
            if let Some(server_header_value) = http_inner.headers().get("Server") {
                let server_value = server_header_value.to_str().unwrap_or("");
                let re = RegexBuilder::new(pattern)
                    .case_insensitive(*pattern == "(?i)apache")
                    .build()
                    .unwrap();
                if re.is_match(server_value) {
                    info!("Apache detected in header: {}", description);
                    detections.push(*description);
                }
            }
        }

        if !detections.is_empty() {
            let order = vec![
                "Standard HTML Body",
                "Apache Functioning Message",
                "Ubuntu Default Page",
                "Shared IP Notice",
                "Shared IP Message",
                "Apache Version Info",
                "Server Header",
                "Server Version Header",
                "Server Header Contains 'Apache'",
            ];

            detections.sort_by_key(|det| order.iter().position(|&o| o == *det).unwrap_or(order.len()));

            detections.dedup();

            let detection_message = detections.join(", ");

            Some(format!("Apache Server Detected: {}", detection_message))
        } else {
            None
        }
    }
}
