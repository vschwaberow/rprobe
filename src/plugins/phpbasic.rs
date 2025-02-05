// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2025
// - Volker Schwaberow <volker@schwaberow.de>

use crate::httpinner::HttpInner;
use crate::plugins::Plugin;
use log::info;
use regex::Regex;

pub struct PHPBasicPlugin;

impl Plugin for PHPBasicPlugin {
    fn name(&self) -> &'static str {
        "PHP Basic Detection"
    }

    fn run(&self, http_inner: &HttpInner) -> Option<String> {
        let mut detections: Vec<String> = Vec::new();

        if let Some(x_powered_by) = http_inner.headers().get("X-Powered-By") {
            let header_value = x_powered_by.to_str().unwrap_or("");
            let php_version_re = Regex::new(r"PHP/?(\d+\.\d+(?:\.\d+)?)").unwrap();
            if let Some(captures) = php_version_re.captures(header_value) {
                let version = captures.get(1).map_or("", |m| m.as_str());
                info!("PHP Enhanced: X-Powered-By Header mit Version erkannt: {}", version);
                detections.push(format!("XPoweredBy[PHP/{}]", version));
            } else if header_value.to_lowercase().contains("php") {
                info!("PHP Enhanced: X-Powered-By Header enthält PHP");
                detections.push("XPoweredBy[PHP]".to_string());
            }
        }

        if let Some(server_header) = http_inner.headers().get("Server") {
            let server_value = server_header.to_str().unwrap_or("");
            let php_version_re = Regex::new(r"PHP/?(\d+\.\d+(?:\.\d+)?)").unwrap();
            if let Some(captures) = php_version_re.captures(server_value) {
                let version = captures.get(1).map_or("", |m| m.as_str());
                info!("PHP Enhanced: Server Header mit Version erkannt: {}", version);
                detections.push(format!("HTTPServer[PHP/{}]", version));
            } else if server_value.to_lowercase().contains("php") {
                info!("PHP Enhanced: Server Header enthält PHP");
                detections.push("HTTPServer[PHP]".to_string());
            }
        }

        if let Some(set_cookie) = http_inner.headers().get("Set-Cookie") {
            let cookie_str = set_cookie.to_str().unwrap_or("");
            if cookie_str.contains("PHPSESSID") {
                info!("PHP Enhanced: PHPSESSID Cookie erkannt");
                detections.push("Cookie[PHPSESSID]".to_string());
            }
        }

        let body_patterns = [
            (r"<\?php", "PHPCode"),
            (r"PHP Warning", "PHPWarning"),
            (r"PHP Parse error", "PHPParseError"),
            (r"Fatal error: Uncaught Error", "PHPFatalError"),
            (r"Notice: Undefined variable", "PHPNotice"),
            (r"Deprecated:", "PHPDeprecated"),
        ];
        for (pattern, description) in &body_patterns {
            let re = Regex::new(pattern).unwrap();
            if re.is_match(http_inner.body()) {
                info!("PHP Enhanced: Body-Muster erkannt: {}", description);
                detections.push(description.to_string());
            }
        }

        if !detections.is_empty() {
            let order = vec![
                "XPoweredBy[PHP]".to_string(),
                "HTTPServer[PHP]".to_string(),
                "XPoweredBy[PHP/".to_string(),
                "HTTPServer[PHP/".to_string(),
                "Cookie[PHPSESSID]".to_string(),
                "PHPCode".to_string(),
                "PHPWarning".to_string(),
                "PHPParseError".to_string(),
                "PHPFatalError".to_string(),
                "PHPNotice".to_string(),
                "PHPDeprecated".to_string(),
            ];

            detections.sort_by_key(|det| {
                order.iter()
                    .position(|o| {
                        if o.ends_with('/') {
                            det.starts_with(o)
                        } else {
                            det == o
                        }
                    })
                    .unwrap_or(order.len())
            });

            detections.dedup();

            let detection_message = detections.join(", ");
            Some(format!("PHP Detected: {}", detection_message))
        } else {
            None
        }
    }
}