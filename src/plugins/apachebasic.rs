// File: apachebasic.rs
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023
// - Volker Schwaberow <volker@schwaberow.de>

use crate::httpinner::HttpInner;
use crate::plugins::Plugin;
use log::info;
use once_cell::sync::Lazy;
use regex::{Regex, RegexBuilder};

pub struct ApacheBasicPlugin;

static BODY_PATTERNS: Lazy<Vec<(Regex, &str)>> = Lazy::new(|| {
    vec![
        (
            Regex::new(r"<html><body><h1>It works!</h1></body></html>").unwrap(),
            "Standard HTML Body",
        ),
        (
            Regex::new(r"<html>Apache is functioning normally</html>").unwrap(),
            "Apache Functioning Message",
        ),
        (
            Regex::new(r"<body><center>This IP is being shared among many domains\.<br>").unwrap(),
            "Shared IP Notice",
        ),
        (
            Regex::new(r"<html><head><title>Apache2 Ubuntu Default Page: It works</title></head>").unwrap(),
            "Ubuntu Default Page",
        ),
        (
            Regex::new(r"This IP is being shared among many domains\.").unwrap(),
            "Shared IP Message",
        ),
        (Regex::new(r"Apache\/\d+\.\d+\.\d+").unwrap(), "Apache Version Info"),
    ]
});

static HEADER_PATTERNS: Lazy<Vec<(Regex, &str)>> = Lazy::new(|| {
    vec![
        (
            RegexBuilder::new(r"^Apache$")
                .case_insensitive(true)
                .build()
                .unwrap(),
            "Server Header",
        ),
        (
            RegexBuilder::new(r"^Apache/\d+\.\d+(\.\d+)?$")
                .case_insensitive(true)
                .build()
                .unwrap(),
            "Server Version Header",
        ),
        (
            Regex::new(r"(?i)apache").unwrap(),
            "Server Header Contains 'Apache'",
        ),
    ]
});

impl Plugin for ApacheBasicPlugin {
    fn name(&self) -> &'static str {
        "Apache Basic"
    }

    fn run(&self, http_inner: &HttpInner) -> Option<String> {
        let mut detections = Vec::new();

        for (re, description) in BODY_PATTERNS.iter() {
            if re.is_match(http_inner.body()) {
                info!("Apache detected in body: {}", description);
                detections.push(*description);
            }
        }

        if let Some(server_header_value) = http_inner.headers().get("Server") {
            let server_value = server_header_value.to_str().unwrap_or("");
            for (re, description) in HEADER_PATTERNS.iter() {
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