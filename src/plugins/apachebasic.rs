// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023
// - Volker Schwaberow <volker@schwaberow.de>

use crate::httpinner::HttpInner;
use crate::plugins::Plugin;
use std::collections::HashMap;

pub struct ApacheBasicPlugin {}

impl Plugin for ApacheBasicPlugin {
    fn name(&self) -> String {
        "apache_basic".to_string()
    }

    fn description(&self) -> String {
        "This plugin detects basic Apache web servers".to_string()
    }

    fn version(&self) -> String {
        "0.1.0".to_string()
    }

    fn author(&self) -> String {
        "Volker Schwaberow".to_string()
    }

    fn license(&self) -> String {
        "MIT".to_string()
    }

    fn run(&self, http_inner: &HttpInner) -> String {
        let sig = self.add_signatures();
        let mut found: Vec<String> = Vec::new();

        for (_, value) in sig.iter() {
            for signature in value {
                if http_inner.body().contains(signature) {
                    found.push("APACHE_BASIC".to_string());
                    break;
                }
            }
        }

        if found.contains(&"APACHE_BASIC".to_string()) {
            return "Apache Server".to_string();
        }

        String::new()
    }
}

impl ApacheBasicPlugin {
    pub fn add_signatures(&self) -> HashMap<String, Vec<&str>> {
        let mut sig = HashMap::new();

        let sig_vector = vec![
            "<html><body><h1>It works!</h1></body></html>",
            "<html>Apache is functioning normally</html>",
            "<body><center>This IP is being shared among many domains.<br>\nTo view the domain you are looking for, simply enter the domain name in the location bar of your web browser.<br>",
            "<html><head><title>Apache2 Ubuntu Default Page: It works</title></head>",
            "This IP is being shared among many domains.",
        ];
        sig.insert("APACHE_BASIC".to_string(), sig_vector);
        sig
    }

    pub fn new() -> Self {
        Self {}
    }
}
