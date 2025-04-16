// File: screenshot.rs
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2025
// - Volker Schwaberow <volker@schwaberow.de>

use log::{debug, error, info};
use reqwest::Url;
use std::error::Error;
use std::fs;
use std::path::Path;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;

pub async fn capture_screenshot(url: &str, output_dir: &str) -> Result<(), Box<dyn Error>> {
    if !Path::new(output_dir).exists() {
        fs::create_dir_all(output_dir)?;
    }

    let parsed_url = Url::parse(url)?;
    let domain = parsed_url.host_str().unwrap_or("unknown");
    let path = parsed_url.path().replace('/', "_");
    let filename = if path.is_empty() || path == "_" {
        format!("{}/{}_{}.png", output_dir, domain, chrono::Utc::now().timestamp())
    } else {
        format!("{}/{}_{}.png", output_dir, domain, path)
    };

    info!("Capturing screenshot of {} to {}", url, filename);

    let result = try_capture_with_chromium(url, &filename).await;
    if result.is_ok() {
        return Ok(());
    }

    let result = try_capture_with_chrome(url, &filename).await;
    if result.is_ok() {
        return Ok(());
    }

    try_capture_with_wkhtmltoimage(url, &filename).await
}

async fn try_capture_with_chromium(url: &str, filename: &str) -> Result<(), Box<dyn Error>> {
    debug!("Attempting to capture with chromium...");
    
    let chromium_result = timeout(
        Duration::from_secs(30),
        Command::new("chromium")
            .args([
                "--headless",
                "--disable-gpu",
                "--no-sandbox",
                "--screenshot",
                filename,
                "--window-size=1920,1080",
                url,
            ])
            .output(),
    )
    .await;

    match chromium_result {
        Ok(output_result) => match output_result {
            Ok(output) => {
                if output.status.success() {
                    info!("Successfully captured screenshot with chromium");
                    Ok(())
                } else {
                    let error_msg = String::from_utf8_lossy(&output.stderr);
                    error!("Chromium screenshot failed: {}", error_msg);
                    Err(error_msg.into())
                }
            }
            Err(e) => {
                error!("Failed to execute chromium: {}", e);
                Err(e.into())
            }
        },
        Err(_) => {
            error!("Timeout while capturing screenshot with chromium");
            Err("Timeout error".into())
        }
    }
}

async fn try_capture_with_chrome(url: &str, filename: &str) -> Result<(), Box<dyn Error>> {
    debug!("Attempting to capture with google-chrome...");
    
    let chrome_result = timeout(
        Duration::from_secs(30),
        Command::new("google-chrome")
            .args([
                "--headless",
                "--disable-gpu",
                "--no-sandbox",
                "--screenshot",
                filename,
                "--window-size=1920,1080",
                url,
            ])
            .output(),
    )
    .await;

    match chrome_result {
        Ok(output_result) => match output_result {
            Ok(output) => {
                if output.status.success() {
                    info!("Successfully captured screenshot with google-chrome");
                    Ok(())
                } else {
                    let error_msg = String::from_utf8_lossy(&output.stderr);
                    error!("Chrome screenshot failed: {}", error_msg);
                    Err(error_msg.into())
                }
            }
            Err(e) => {
                error!("Failed to execute google-chrome: {}", e);
                Err(e.into())
            }
        },
        Err(_) => {
            error!("Timeout while capturing screenshot with google-chrome");
            Err("Timeout error".into())
        }
    }
}

async fn try_capture_with_wkhtmltoimage(url: &str, filename: &str) -> Result<(), Box<dyn Error>> {
    debug!("Attempting to capture with wkhtmltoimage...");
    
    let wkhtml_result = timeout(
        Duration::from_secs(30),
        Command::new("wkhtmltoimage")
            .args([
                "--quality", "80",
                "--width", "1920",
                "--height", "1080",
                url,
                filename,
            ])
            .output(),
    )
    .await;

    match wkhtml_result {
        Ok(output_result) => match output_result {
            Ok(output) => {
                if output.status.success() {
                    info!("Successfully captured screenshot with wkhtmltoimage");
                    Ok(())
                } else {
                    let error_msg = String::from_utf8_lossy(&output.stderr);
                    error!("wkhtmltoimage screenshot failed: {}", error_msg);
                    Err(error_msg.into())
                }
            }
            Err(e) => {
                error!("Failed to execute wkhtmltoimage: {}", e);
                Err(e.into())
            }
        },
        Err(_) => {
            error!("Timeout while capturing screenshot with wkhtmltoimage");
            Err("Timeout error".into())
        }
    }
}