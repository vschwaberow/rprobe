// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023
// - Volker Schwaberow <volker@schwaberow.de>

use crate::httpinner::HttpInner;
use crate::plugins::Plugin;

pub struct ApacheBasicPlugin;

impl Plugin for ApacheBasicPlugin {
    fn name(&self) -> &'static str {
        "Apache Basic"
    }

    fn run(&self, http_inner: &HttpInner) -> Option<String> {
        let signatures = [
            "<html><body><h1>It works!</h1></body></html>",
            "<html>Apache is functioning normally</html>",
            "<body><center>This IP is being shared among many domains.<br>",
            "<html><head><title>Apache2 Ubuntu Default Page: It works</title></head>",
            "This IP is being shared among many domains.",
        ];

        if signatures.iter().any(|&sig| http_inner.body().contains(sig)) {
            Some("Apache Server detected".to_string())
        } else {
            None
        }
    }
}
