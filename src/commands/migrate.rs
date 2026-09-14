// File: migrate.rs
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023-2025
// - Volker Schwaberow <volker@schwaberow.de>

use anyhow::Result;

use super::{print_info, print_success, print_warning};
use crate::cli::MigrateArgs;
use crate::storage::{HistoryDatabase, SCHEMA_VERSION};

pub async fn execute(args: &MigrateArgs, db: &mut HistoryDatabase) -> Result<()> {
    let current = db.schema_version()?;
    print_info(&format!(
        "History database schema version: {} (supported: {})",
        current, SCHEMA_VERSION
    ));

    if current == SCHEMA_VERSION && !args.force {
        print_success("Database already at the current schema; nothing to do");
        return Ok(());
    }

    if args.dry_run {
        print_info("Running migration in dry-run mode - no data will be rewritten");
    } else {
        print_info("Starting history database migration (backup will be created if needed)...");
    }

    let report = db.ensure_current_schema(args.dry_run)?;

    if report.skipped {
        print_success("Migration skipped; database already current");
        return Ok(());
    }

    print_info(&format!(
        "Migrated {} scan(s) and {} session(s) from schema v{} to v{}",
        report.scans_migrated, report.sessions_migrated, report.from_version, report.to_version
    ));

    if let Some(path) = report.backup_path {
        print_info(&format!("Backup written to {}", path.display()));
    }

    if args.dry_run {
        print_warning("Dry-run complete; re-run without --dry-run to apply changes");
    } else {
        print_success("Migration completed successfully");
    }

    Ok(())
}
