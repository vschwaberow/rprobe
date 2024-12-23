// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024
// - Volker Schwaberow <volker@schwaberow.de>

use crate::httpinner::HttpInner;
use crate::plugins::Plugin;
use log::info;
use regex::Regex;
use regex::RegexBuilder;

pub struct CloudflareBasicPlugin;

impl Plugin for CloudflareBasicPlugin {
    fn name(&self) -> &'static str {
        "Cloudflare Basic"
    }

    fn run(&self, http_inner: &HttpInner) -> Option<String> {
        let header_patterns = [
            (r"^cloudflare$", "Server Header"),
            (r"^cloudflare/\d+\.\d+$", "Server Version Header"),
            (r"^CF-RAY$", "CF-RAY Header"),
            (r"^CF-Cache-Status$", "CF-Cache-Status Header"),
            (r"^CF-Connecting-IP$", "CF-Connecting-IP Header"),
        ];

        let body_patterns = [
            (r"Attention Required! | Cloudflare", "Cloudflare Challenge Page"),
            (r"Error 1006", "Cloudflare Error 1006"),
            (r"Access denied | Cloudflare", "Cloudflare Access Denied"),
        ];

        let mut detections: Vec<&'static str> = Vec::new();

        for (pattern, description) in &header_patterns {
            if let Some(header_value) = http_inner.headers().get("Server") {
                let server_value = header_value.to_str().unwrap_or("");
                let re = RegexBuilder::new(pattern)
                    .case_insensitive(true)
                    .build()
                    .unwrap();
                if re.is_match(server_value) {
                    info!("Cloudflare detected in header: {}", description);
                    detections.push(description);
                }
            }

            if let Some(header_value) = http_inner.headers().get(&*pattern.split("/").next().unwrap_or("")) {
                let header_str = header_value.to_str().unwrap_or("");
                if !header_str.is_empty() {
                    info!("Cloudflare detected with header {}: {}", pattern, description);
                    detections.push(description);
                }
            }
        }

        for (pattern, description) in &body_patterns {
            let re = Regex::new(pattern).unwrap();
            if re.is_match(http_inner.body()) {
                info!("Cloudflare detected in body: {}", description);
                detections.push(description);
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