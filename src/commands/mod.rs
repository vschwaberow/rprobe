// File: mod.rs
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023-2025
// - Volker Schwaberow <volker@schwaberow.de>

use anyhow::Result;
use colored::*;

use crate::cli::{CleanArgs, CompareArgs, HistoryArgs, OutputArgs, StatsArgs};
use crate::storage::HistoryDatabase;

pub mod clean;
pub mod compare;
pub mod history;
pub mod output;
pub mod stats;

pub async fn handle_output_command(args: &OutputArgs, db: &HistoryDatabase) -> Result<()> {
    output::execute(args, db).await
}

pub async fn handle_history_command(args: &HistoryArgs, db: &HistoryDatabase) -> Result<()> {
    history::execute(args, db).await
}

pub async fn handle_compare_command(args: &CompareArgs, db: &HistoryDatabase) -> Result<()> {
    compare::execute(args, db).await
}

pub async fn handle_clean_command(args: &CleanArgs, db: &HistoryDatabase) -> Result<()> {
    clean::execute(args, db).await
}

pub async fn handle_stats_command(args: &StatsArgs, db: &HistoryDatabase) -> Result<()> {
    stats::execute(args, db).await
}

fn print_success(message: &str) {
    println!("{} {}", "✓".green().bold(), message);
}

fn print_error(message: &str) {
    eprintln!("{} {}", "✗".red().bold(), message);
}

fn print_warning(message: &str) {
    println!("{} {}", "⚠".yellow().bold(), message);
}

fn print_info(message: &str) {
    println!("{} {}", "ℹ".blue().bold(), message);
}

fn format_duration(ms: u64) -> String {
    if ms >= 60000 {
        format!(
            "{:.1}m {:.1}s",
            ms as f64 / 60000.0,
            (ms % 60000) as f64 / 1000.0
        )
    } else if ms >= 1000 {
        format!("{:.2}s", ms as f64 / 1000.0)
    } else {
        format!("{}ms", ms)
    }
}

fn format_file_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB"];
    let mut size = bytes as f64;
    let mut unit_index = 0;

    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }

    if unit_index == 0 {
        format!("{} {}", bytes, UNITS[unit_index])
    } else {
        format!("{:.2} {}", size, UNITS[unit_index])
    }
}
