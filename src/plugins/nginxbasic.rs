// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023
// - Volker Schwaberow <volker@schwaberow.de>

use crate::httpinner::HttpInner;
use crate::plugins::Plugin;
use log::info;
use regex::Regex;
use regex::RegexBuilder;

pub struct NginxBasicPlugin;

impl Plugin for NginxBasicPlugin {
    fn name(&self) -> &'static str {
        "Nginx Basic"
    }

    fn run(&self, http_inner: &HttpInner) -> Option<String> {
        let body_patterns = [
            r"<title>Welcome to nginx!</title>",
            r"<h1>Welcome to nginx</h1>",
            r"<center>nginx</center>",
            r"<hr><center>nginx/\d+\.\d+\.\d+</center>",
            r"Thank you for using nginx",
        ];

        let header_patterns = [
            r"^nginx$",
            r"^nginx/\d+\.\d+\.\d+$",
            r"^openresty$",
            r"^openresty/\d+\.\d+\.\d+\.\d+$"
        ];

        for pattern in &body_patterns {
            let re = Regex::new(pattern).unwrap();
            if re.is_match(http_inner.body()) {
                info!("Nginx server detected in body with pattern: {}", pattern);
                return Some("Nginx Server detected in body".to_string());
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
                    info!("Nginx server detected in header with pattern: {}", pattern);
                    return Some("Nginx Server detected in header".to_string());
                }
            }
        }

        if let Some(powered_by) = http_inner.headers().get("X-Powered-By") {
            let powered_value = powered_by.to_str().unwrap_or("");
            if powered_value.to_lowercase().contains("nginx") {
                info!("Nginx server detected in X-Powered-By header");
                return Some("Nginx Server detected in X-Powered-By header".to_string());
            }
        }

        None
    }
}