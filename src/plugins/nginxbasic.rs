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
            (r"<title>Welcome to nginx!</title>", "Default Title"),
            (r"<h1>Welcome to nginx</h1>", "Header Message"),
            (r"<center>nginx</center>", "Centered Text"),
            (r"<hr><center>nginx/\d+\.\d+\.\d+</center>", "Version Info"),
            (r"Thank you for using nginx", "Thank You Message"),
        ];

        let header_patterns = [
            (r"^nginx$", "Server Header"),
            (r"^nginx/\d+\.\d+\.\d+$", "Server Version Header"),
            (r"^openresty$", "OpenResty Header"),
            (r"^openresty/\d+\.\d+\.\d+\.\d+$", "OpenResty Version Header"),
        ];

        let mut detections: Vec<&'static str> = Vec::new();

        for (pattern, description) in &body_patterns {
            let re = Regex::new(pattern).unwrap();
            if re.is_match(http_inner.body()) {
                info!("Nginx detected in body: {}", description);
                detections.push(description);
            }
        }

        if let Some(server_header_value) = http_inner.headers().get("Server") {
            let server_value = server_header_value.to_str().unwrap_or("");
            for (pattern, description) in &header_patterns {
                let re = RegexBuilder::new(pattern)
                    .case_insensitive(true)
                    .build()
                    .unwrap();
                if re.is_match(server_value) {
                    info!("Nginx detected in header: {}", description);
                    detections.push(description);
                }
            }
        }

        if let Some(powered_by) = http_inner.headers().get("X-Powered-By") {
            let powered_value = powered_by.to_str().unwrap_or("");
            if powered_value.to_lowercase().contains("nginx") {
                info!("Nginx detected in X-Powered-By header");
                detections.push("X-Powered-By Header");
            }
        }

        if !detections.is_empty() {
            // Define the desired order
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