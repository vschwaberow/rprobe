// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2025
// - Volker Schwaberow <volker@schwaberow.de>

use crate::httpinner::HttpInner;
use crate::plugins::Plugin;
use log::info;
use regex::Regex;

pub struct LaravelPlugin;

impl Plugin for LaravelPlugin {
    fn name(&self) -> &'static str {
        "Laravel Plugin"
    }

    fn run(&self, http_inner: &HttpInner) -> Option<String> {
        let mut detections = Vec::new();
        let headers = http_inner.headers();
        let body = http_inner.body();

        if let Some(cookie) = headers.get("set-cookie") {
            if let Ok(cookie_str) = cookie.to_str() {
                if cookie_str.contains("laravel_session") {
                    info!("Laravel: 'laravel_session' Cookie gefunden");
                    detections.push("Cookie[Laravel_Session]".to_string());
                }
            }
        }

        if let Some(x_powered_by) = headers.get("x-powered-by") {
            if let Ok(powered_by) = x_powered_by.to_str() {
                if powered_by.to_lowercase().contains("laravel") {
                    info!("Laravel: 'x-powered-by' Header enthält Laravel");
                    detections.push("XPoweredBy[Laravel]".to_string());
                }
            }
        }

        let laravel_regex = Regex::new(r"(?i)laravel").unwrap();
        if laravel_regex.is_match(body) {
            info!("Laravel: Hinweis im Body gefunden");
            detections.push("Body[Laravel]".to_string());
        }

        if detections.is_empty() {
            None
        } else {
            Some(format!("Laravel detected: {}", detections.join(", ")))
        }
    }
}