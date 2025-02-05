// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2025
// - Volker Schwaberow <volker@schwaberow.de>

use serde::Serialize;
use std::fs::File;
use std::io::{Result, Write};

#[derive(Debug, Serialize)]
pub struct ReportEntry {
    pub url: String,
    pub status: String,
    pub detections: Vec<String>,
}

pub enum ReportFormat {
    Text,
    Json,
}

pub struct ReportGenerator;

impl ReportGenerator {
    pub fn generate_report(
        entries: &[ReportEntry],
        output_path: &str,
        format: ReportFormat,
    ) -> Result<()> {
        match format {
            ReportFormat::Text => Self::generate_text_report(entries, output_path),
            ReportFormat::Json => Self::generate_json_report(entries, output_path),
        }
    }

    pub fn generate_text_report(entries: &[ReportEntry], output_path: &str) -> Result<()> {
        let mut file = File::create(output_path)?;
        for entry in entries {
            writeln!(
                file,
                "{} [{}] {}",
                entry.url,
                entry.status,
                entry.detections.join(", ")
            )?;
        }
        Ok(())
    }

    pub fn generate_json_report(entries: &[ReportEntry], output_path: &str) -> Result<()> {
        let json = serde_json::to_string_pretty(entries).unwrap();
        let mut file = File::create(output_path)?;
        writeln!(file, "{}", json)?;
        Ok(())
    }
}