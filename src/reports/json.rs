// File: json.rs
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023-2025
// - Volker Schwaberow <volker@schwaberow.de>

use anyhow::Result;
use serde_json;

use super::{ReportConfig, ReportData, ReportGenerator};

pub struct JsonGenerator;

impl JsonGenerator {
    pub fn new() -> Self {
        Self
    }
}

impl ReportGenerator for JsonGenerator {
    fn generate(&self, data: &ReportData, _config: &ReportConfig) -> Result<String> {
        let json = serde_json::to_string_pretty(data)
            .map_err(|e| anyhow::anyhow!("Failed to serialize report to JSON: {}", e))?;
        Ok(json)
    }

    fn file_extension(&self) -> &'static str {
        "json"
    }

    fn content_type(&self) -> &'static str {
        "application/json"
    }
}
