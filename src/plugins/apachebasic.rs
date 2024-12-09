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
            r"<html><body><h1>It works!</h1></body></html>",
            r"<html>Apache is functioning normally</html>",
            r"<body><center>This IP is being shared among many domains\.<br>",
            r"<html><head><title>Apache2 Ubuntu Default Page: It works</title></head>",
            r"This IP is being shared among many domains\.",
            r"Apache\/\d+\.\d+\.\d+",
        ];

        let header_patterns = [r"^Apache$", r"^Apache/\d+\.\d+(\.\d+)?$"];

        for pattern in &body_patterns {
            let re = Regex::new(pattern).unwrap();
            if re.is_match(http_inner.body()) {
                info!("Apache server detected in body with pattern: {}", pattern);
                return Some("Apache Server detected in body".to_string());
            }
        }

        if let Some(server_header_value) = http_inner.headers().get("Server") {
            let server_value = server_header_value.to_str().unwrap_or("");
            for pattern in &header_patterns {
                let re = RegexBuilder::new(pattern)
                    .case_insensitive(true)
                    .build()
                    .unwrap();
                if re.is_match(server_value) {
                    info!("Apache server detected in header with pattern: {}", pattern);
                    return Some("Apache Server detected in header".to_string());
                }
            }
        }

        if let Some(server_header_value) = http_inner.headers().get("server") {
            let server_value = server_header_value.to_str().unwrap_or("");
            let server_value_lower = server_value.to_lowercase();
            if server_value_lower.contains("apache") {
                info!("Apache-Server im Header erkannt: {}", server_value);
                return Some("Apache-Server im Header erkannt".to_string());
            }
        }

        None
    }
}
