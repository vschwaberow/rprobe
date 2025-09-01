// File: lib.rs
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023-2025
// - Volker Schwaberow <volker@schwaberow.de>

#![allow(clippy::uninlined_format_args)]
#![allow(clippy::module_inception)]
#![allow(clippy::bool_assert_comparison)]
#![allow(clippy::new_without_default)]
#![allow(clippy::useless_vec)]
#![allow(clippy::single_component_path_imports)]
#![allow(dead_code)]

pub mod config;
pub mod content_analyzer;
pub mod desync_cli;
pub mod desync_scanner;
pub mod getstate;
pub mod http;
pub mod httpinner;
pub mod plugins;
pub mod report;
pub mod screenshot;
pub mod storage;
pub mod tls_analyzer;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_imports() {
        let _ = config::ConfigParameter::default();
        let _ = content_analyzer::ContentAnalyzer::analyze(&httpinner::HttpInner::new());
        let _ = getstate::GetState::new();
        let _ = httpinner::HttpInner::new();
        let _ = plugins::PluginHandler::new();
        let _ = report::ReportEntry {
            url: String::new(),
            status: String::new(),
            detections: vec![],
        };
        let _ = tls_analyzer::TlsAnalyzer;
    }

    #[test]
    fn test_all_modules_compile() {}
}
