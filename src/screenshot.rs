// File: screenshot.rs
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023-2025
// - Volker Schwaberow <volker@schwaberow.de>

use log::{debug, error, info};
use reqwest::Url;
use std::error::Error;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;

fn validate_url(url: &str) -> Result<(), Box<dyn Error>> {
    if url.is_empty() || url.len() > 2048 {
        return Err("Invalid URL length".into());
    }

    if url.contains('\0') || url.contains('\n') || url.contains('\r') {
        return Err("URL contains invalid characters".into());
    }

    let parsed = Url::parse(url)?;
    match parsed.scheme() {
        "http" | "https" => Ok(()),
        _ => Err("URL must use http or https scheme".into()),
    }
}

fn validate_filename(filename: &str) -> Result<(), Box<dyn Error>> {
    if filename.is_empty() || filename.len() > 255 {
        return Err("Invalid filename length".into());
    }

    if filename.contains('\0') || filename.contains('\n') || filename.contains('\r') {
        return Err("Filename contains invalid characters".into());
    }

    let invalid_chars = [
        '<', '>', ':', '"', '|', '?', '*', ';', '&', '$', '`', '\'', '\\', '\t',
    ];
    if filename.chars().any(|c| invalid_chars.contains(&c)) {
        return Err("Filename contains shell metacharacters".into());
    }

    let dangerous_patterns = ["$(", "&&", "||", ";"];
    if dangerous_patterns
        .iter()
        .any(|pattern| filename.contains(pattern))
    {
        return Err("Filename contains command injection patterns".into());
    }

    Ok(())
}

fn sanitize_filename(input: &str) -> String {
    let filtered: String = input
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
        .collect::<String>()
        .chars()
        .take(255)
        .collect();

    let mut result = if let Some(pos) = input.find('.') {
        if pos > 0 {
            let pre_dot_ascii: String = input[..pos]
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
                .collect();
            if pre_dot_ascii.is_empty() {
                filtered
            } else {
                filtered.trim_start_matches('.').to_string()
            }
        } else {
            filtered.trim_start_matches('.').to_string()
        }
    } else {
        filtered.trim_start_matches('.').to_string()
    };

    if result.is_empty() {
        result = "file".to_string();
    }

    result
}

fn generate_safe_filename(parsed_url: &Url, output_dir: &str) -> Result<String, Box<dyn Error>> {
    let output_path = PathBuf::from(output_dir);
    if !output_path.exists() {
        return Err("Output directory does not exist".into());
    }

    let domain = sanitize_filename(parsed_url.host_str().unwrap_or("unknown"));
    let path_segment = sanitize_filename(&parsed_url.path().replace('/', "_"));

    let filename = if path_segment.is_empty() || path_segment == "_" {
        format!("{}_{}.png", domain, chrono::Utc::now().timestamp())
    } else {
        format!("{}_{}.png", domain, path_segment)
    };

    let final_path = output_path.join(&filename);
    let canonical_output = output_path.canonicalize()?;

    let canonical_final = if final_path.exists() {
        final_path.canonicalize()?
    } else {
        canonical_output.join(final_path.file_name().ok_or("Invalid filename")?)
    };

    if !canonical_final.starts_with(&canonical_output) {
        return Err("Path traversal attempt detected".into());
    }

    Ok(final_path.to_string_lossy().to_string())
}

pub async fn capture_screenshot(
    url: &str,
    output_dir: &str,
) -> Result<Option<String>, Box<dyn Error>> {
    validate_url(url)?;

    if !Path::new(output_dir).exists() {
        fs::create_dir_all(output_dir)?;
    }

    let parsed_url = Url::parse(url)?;
    let filename = generate_safe_filename(&parsed_url, output_dir)?;

    info!("Capturing screenshot of {} to {}", url, filename);

    if let Ok(()) = try_capture_with_env_browser(url, &filename).await {
        return Ok(Some(filename));
    }

    if let Ok(()) = try_capture_with_chromium(url, &filename).await {
        return Ok(Some(filename));
    }

    if let Ok(()) = try_capture_with_chrome(url, &filename).await {
        return Ok(Some(filename));
    }

    if let Ok(()) = try_capture_with_chromium_browser(url, &filename).await {
        return Ok(Some(filename));
    }

    if let Ok(()) = try_capture_with_chrome_stable(url, &filename).await {
        return Ok(Some(filename));
    }

    try_capture_with_wkhtmltoimage(url, &filename)
        .await
        .map(|_| Some(filename))
}

async fn try_capture_with_chromium(url: &str, filename: &str) -> Result<(), Box<dyn Error>> {
    validate_url(url)?;
    validate_filename(filename)?;

    debug!("Attempting to capture with chromium...");

    let chromium_result = timeout(
        Duration::from_secs(30),
        Command::new("chromium")
            .arg(OsStr::new("--headless=new"))
            .arg(OsStr::new("--disable-gpu"))
            .arg(OsStr::new("--no-sandbox"))
            .arg(OsStr::new("--hide-scrollbars"))
            .arg(OsStr::new("--disable-dev-shm-usage"))
            .arg(OsStr::new("--screenshot"))
            .arg(OsStr::new(filename))
            .arg(OsStr::new("--window-size=1920,1080"))
            .arg(OsStr::new("--virtual-time-budget=8000"))
            .arg(OsStr::new(url))
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
    validate_url(url)?;
    validate_filename(filename)?;

    debug!("Attempting to capture with google-chrome...");

    let chrome_result = timeout(
        Duration::from_secs(30),
        Command::new("google-chrome")
            .arg(OsStr::new("--headless=new"))
            .arg(OsStr::new("--disable-gpu"))
            .arg(OsStr::new("--no-sandbox"))
            .arg(OsStr::new("--hide-scrollbars"))
            .arg(OsStr::new("--disable-dev-shm-usage"))
            .arg(OsStr::new("--screenshot"))
            .arg(OsStr::new(filename))
            .arg(OsStr::new("--window-size=1920,1080"))
            .arg(OsStr::new("--virtual-time-budget=8000"))
            .arg(OsStr::new(url))
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
    validate_url(url)?;
    validate_filename(filename)?;

    debug!("Attempting to capture with wkhtmltoimage...");

    let wkhtml_result = timeout(
        Duration::from_secs(30),
        Command::new("wkhtmltoimage")
            .arg(OsStr::new("--quality"))
            .arg(OsStr::new("80"))
            .arg(OsStr::new("--width"))
            .arg(OsStr::new("1920"))
            .arg(OsStr::new("--height"))
            .arg(OsStr::new("1080"))
            .arg(OsStr::new(url))
            .arg(OsStr::new(filename))
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

async fn try_capture_with_chromium_browser(
    url: &str,
    filename: &str,
) -> Result<(), Box<dyn Error>> {
    validate_url(url)?;
    validate_filename(filename)?;

    debug!("Attempting to capture with chromium-browser...");

    let result = timeout(
        Duration::from_secs(30),
        Command::new("chromium-browser")
            .arg(OsStr::new("--headless=new"))
            .arg(OsStr::new("--disable-gpu"))
            .arg(OsStr::new("--no-sandbox"))
            .arg(OsStr::new("--hide-scrollbars"))
            .arg(OsStr::new("--disable-dev-shm-usage"))
            .arg(OsStr::new("--screenshot"))
            .arg(OsStr::new(filename))
            .arg(OsStr::new("--window-size=1920,1080"))
            .arg(OsStr::new("--virtual-time-budget=8000"))
            .arg(OsStr::new(url))
            .output(),
    )
    .await;

    match result {
        Ok(output_result) => match output_result {
            Ok(output) => {
                if output.status.success() {
                    info!("Successfully captured screenshot with chromium-browser");
                    Ok(())
                } else {
                    let error_msg = String::from_utf8_lossy(&output.stderr);
                    error!("chromium-browser screenshot failed: {}", error_msg);
                    Err(error_msg.into())
                }
            }
            Err(e) => {
                error!("Failed to execute chromium-browser: {}", e);
                Err(e.into())
            }
        },
        Err(_) => {
            error!("Timeout while capturing screenshot with chromium-browser");
            Err("Timeout error".into())
        }
    }
}

async fn try_capture_with_chrome_stable(url: &str, filename: &str) -> Result<(), Box<dyn Error>> {
    validate_url(url)?;
    validate_filename(filename)?;

    debug!("Attempting to capture with google-chrome-stable...");

    let result = timeout(
        Duration::from_secs(30),
        Command::new("google-chrome-stable")
            .arg(OsStr::new("--headless=new"))
            .arg(OsStr::new("--disable-gpu"))
            .arg(OsStr::new("--no-sandbox"))
            .arg(OsStr::new("--hide-scrollbars"))
            .arg(OsStr::new("--disable-dev-shm-usage"))
            .arg(OsStr::new("--screenshot"))
            .arg(OsStr::new(filename))
            .arg(OsStr::new("--window-size=1920,1080"))
            .arg(OsStr::new("--virtual-time-budget=8000"))
            .arg(OsStr::new(url))
            .output(),
    )
    .await;

    match result {
        Ok(output_result) => match output_result {
            Ok(output) => {
                if output.status.success() {
                    info!("Successfully captured screenshot with google-chrome-stable");
                    Ok(())
                } else {
                    let error_msg = String::from_utf8_lossy(&output.stderr);
                    error!("google-chrome-stable screenshot failed: {}", error_msg);
                    Err(error_msg.into())
                }
            }
            Err(e) => {
                error!("Failed to execute google-chrome-stable: {}", e);
                Err(e.into())
            }
        },
        Err(_) => {
            error!("Timeout while capturing screenshot with google-chrome-stable");
            Err("Timeout error".into())
        }
    }
}

async fn try_capture_with_env_browser(url: &str, filename: &str) -> Result<(), Box<dyn Error>> {
    validate_url(url)?;
    validate_filename(filename)?;

    if let Ok(browser) = std::env::var("RPROBE_BROWSER") {
        debug!("Attempting to capture with env browser: {}", browser);
        let result = timeout(
            Duration::from_secs(30),
            Command::new(browser)
                .arg(OsStr::new("--headless=new"))
                .arg(OsStr::new("--disable-gpu"))
                .arg(OsStr::new("--no-sandbox"))
                .arg(OsStr::new("--hide-scrollbars"))
                .arg(OsStr::new("--disable-dev-shm-usage"))
                .arg(OsStr::new("--screenshot"))
                .arg(OsStr::new(filename))
                .arg(OsStr::new("--window-size=1920,1080"))
                .arg(OsStr::new("--virtual-time-budget=8000"))
                .arg(OsStr::new(url))
                .output(),
        )
        .await;

        return match result {
            Ok(output_result) => match output_result {
                Ok(output) => {
                    if output.status.success() {
                        info!("Successfully captured screenshot with env browser");
                        Ok(())
                    } else {
                        let error_msg = String::from_utf8_lossy(&output.stderr);
                        error!("Env browser screenshot failed: {}", error_msg);
                        Err(error_msg.into())
                    }
                }
                Err(e) => {
                    error!("Failed to execute env browser: {}", e);
                    Err(e.into())
                }
            },
            Err(_) => {
                error!("Timeout while capturing screenshot with env browser");
                Err("Timeout error".into())
            }
        };
    }

    Err("No RPROBE_BROWSER set".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_validate_url_valid_http() {
        assert!(validate_url("http://example.com").is_ok());
    }

    #[test]
    fn test_validate_url_valid_https() {
        assert!(validate_url("https://example.com").is_ok());
    }

    #[test]
    fn test_validate_url_with_path() {
        assert!(validate_url("https://example.com/path/to/page").is_ok());
    }

    #[test]
    fn test_validate_url_with_query() {
        assert!(validate_url("https://example.com/page?param=value").is_ok());
    }

    #[test]
    fn test_validate_url_empty() {
        assert!(validate_url("").is_err());
    }

    #[test]
    fn test_validate_url_too_long() {
        let long_url = format!("https://example.com/{}", "a".repeat(2048));
        assert!(validate_url(&long_url).is_err());
    }

    #[test]
    fn test_validate_url_null_character() {
        assert!(validate_url("https://example.com\0").is_err());
    }

    #[test]
    fn test_validate_url_newline_character() {
        assert!(validate_url("https://example.com\n").is_err());
    }

    #[test]
    fn test_validate_url_carriage_return() {
        assert!(validate_url("https://example.com\r").is_err());
    }

    #[test]
    fn test_validate_url_invalid_scheme_ftp() {
        assert!(validate_url("ftp://example.com").is_err());
    }

    #[test]
    fn test_validate_url_invalid_scheme_file() {
        assert!(validate_url("file:///etc/passwd").is_err());
    }

    #[test]
    fn test_validate_url_malformed() {
        assert!(validate_url("not-a-url").is_err());
    }

    #[test]
    fn test_validate_filename_valid() {
        assert!(validate_filename("test.png").is_ok());
        assert!(validate_filename("screenshot_2023.jpg").is_ok());
        assert!(validate_filename("file-name_123.png").is_ok());
    }

    #[test]
    fn test_validate_filename_empty() {
        assert!(validate_filename("").is_err());
    }

    #[test]
    fn test_validate_filename_too_long() {
        let long_filename = "a".repeat(256);
        assert!(validate_filename(&long_filename).is_err());
    }

    #[test]
    fn test_validate_filename_null_character() {
        assert!(validate_filename("test\0.png").is_err());
    }

    #[test]
    fn test_validate_filename_newline() {
        assert!(validate_filename("test\n.png").is_err());
    }

    #[test]
    fn test_validate_filename_invalid_characters() {
        let invalid_chars = [
            '<', '>', ':', '"', '|', '?', '*', ';', '&', '$', '`', '\'', '\\', '\t',
        ];

        for invalid_char in invalid_chars {
            let filename = format!("test{}.png", invalid_char);
            assert!(
                validate_filename(&filename).is_err(),
                "Character '{}' should be invalid",
                invalid_char
            );
        }
    }

    #[test]
    fn test_validate_filename_dangerous_patterns() {
        let dangerous_patterns = [
            "test$(echo).png",
            "test&&rm.png",
            "test||rm.png",
            "test;rm.png",
        ];

        for pattern in dangerous_patterns {
            assert!(
                validate_filename(pattern).is_err(),
                "Pattern '{}' should be invalid",
                pattern
            );
        }
    }

    #[test]
    fn test_sanitize_filename_alphanumeric() {
        assert_eq!(sanitize_filename("test123"), "test123");
    }

    #[test]
    fn test_sanitize_filename_allowed_chars() {
        assert_eq!(
            sanitize_filename("test-file_2023.png"),
            "test-file_2023.png"
        );
    }

    #[test]
    fn test_sanitize_filename_removes_invalid_chars() {
        assert_eq!(sanitize_filename("test<>:file"), "testfile");
        assert_eq!(sanitize_filename("file|with*bad?chars"), "filewithbadchars");
    }

    #[test]
    fn test_sanitize_filename_removes_leading_dots() {
        assert_eq!(sanitize_filename("...test.png"), "test.png");
        assert_eq!(sanitize_filename(".hidden"), "hidden");
    }

    #[test]
    fn test_sanitize_filename_empty_becomes_file() {
        assert_eq!(sanitize_filename(""), "file");
        assert_eq!(sanitize_filename("@#$%^"), "file");
    }

    #[test]
    fn test_sanitize_filename_truncates_long_names() {
        let long_name = "a".repeat(300);
        let result = sanitize_filename(&long_name);
        assert_eq!(result.len(), 255);
        assert_eq!(result, "a".repeat(255));
    }

    #[test]
    fn test_generate_safe_filename_valid_domain() {
        let temp_dir = TempDir::new().unwrap();
        let url = Url::parse("https://example.com").unwrap();

        let result = generate_safe_filename(&url, temp_dir.path().to_str().unwrap());
        assert!(result.is_ok());

        let filename = result.unwrap();
        assert!(filename.contains("example.com"));
        assert!(filename.ends_with(".png"));
    }

    #[test]
    fn test_generate_safe_filename_with_path() {
        let temp_dir = TempDir::new().unwrap();
        let url = Url::parse("https://example.com/path/to/page").unwrap();

        let result = generate_safe_filename(&url, temp_dir.path().to_str().unwrap());
        assert!(result.is_ok());

        let filename = result.unwrap();
        assert!(filename.contains("example.com"));
        assert!(filename.contains("path_to_page"));
        assert!(filename.ends_with(".png"));
    }

    #[test]
    fn test_generate_safe_filename_root_path() {
        let temp_dir = TempDir::new().unwrap();
        let url = Url::parse("https://example.com/").unwrap();

        let result = generate_safe_filename(&url, temp_dir.path().to_str().unwrap());
        assert!(result.is_ok());

        let filename = result.unwrap();
        assert!(filename.contains("example.com"));
        assert!(filename.ends_with(".png"));
    }

    #[test]
    fn test_generate_safe_filename_nonexistent_dir() {
        let url = Url::parse("https://example.com").unwrap();

        let result = generate_safe_filename(&url, "/nonexistent/directory");
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_safe_filename_path_traversal_protection() {
        let temp_dir = TempDir::new().unwrap();
        let url = Url::parse("https://example.com/../../../etc/passwd").unwrap();

        let result = generate_safe_filename(&url, temp_dir.path().to_str().unwrap());
        assert!(result.is_ok());

        let filename = result.unwrap();
        assert!(filename.starts_with(temp_dir.path().to_str().unwrap()));
    }

    #[tokio::test]
    async fn test_try_capture_with_chromium_invalid_url() {
        let temp_dir = TempDir::new().unwrap();
        let filename = temp_dir
            .path()
            .join("test.png")
            .to_str()
            .unwrap()
            .to_string();

        let result = try_capture_with_chromium("", &filename).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_try_capture_with_chromium_invalid_filename() {
        let result = try_capture_with_chromium("https://example.com", "").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_try_capture_with_chrome_invalid_url() {
        let temp_dir = TempDir::new().unwrap();
        let filename = temp_dir
            .path()
            .join("test.png")
            .to_str()
            .unwrap()
            .to_string();

        let result = try_capture_with_chrome("", &filename).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_try_capture_with_chrome_invalid_filename() {
        let result = try_capture_with_chrome("https://example.com", "").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_try_capture_with_wkhtmltoimage_invalid_url() {
        let temp_dir = TempDir::new().unwrap();
        let filename = temp_dir
            .path()
            .join("test.png")
            .to_str()
            .unwrap()
            .to_string();

        let result = try_capture_with_wkhtmltoimage("", &filename).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_try_capture_with_wkhtmltoimage_invalid_filename() {
        let result = try_capture_with_wkhtmltoimage("https://example.com", "").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_capture_screenshot_invalid_url() {
        let temp_dir = TempDir::new().unwrap();

        let result = capture_screenshot("", temp_dir.path().to_str().unwrap()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_capture_screenshot_creates_directory() {
        let temp_dir = TempDir::new().unwrap();
        let new_dir = temp_dir.path().join("screenshots");

        let _result = capture_screenshot("https://example.com", new_dir.to_str().unwrap()).await;

        assert!(new_dir.exists());
        assert!(new_dir.is_dir());
    }

    #[test]
    fn test_validate_url_edge_cases() {
        assert!(validate_url("https://127.0.0.1:8080").is_ok());
        assert!(validate_url("http://localhost").is_ok());
        assert!(validate_url("https://sub.domain.example.com").is_ok());
        assert!(validate_url("https://example.com:443/path?query=1#fragment").is_ok());
    }

    #[test]
    fn test_sanitize_filename_unicode() {
        assert_eq!(sanitize_filename("tëst"), "tst");
        assert_eq!(sanitize_filename("файл.png"), ".png");
        assert_eq!(sanitize_filename("测试文件"), "file");
    }

    #[test]
    fn test_validate_filename_edge_cases() {
        assert!(validate_filename("a").is_ok());
        assert!(validate_filename("test.").is_ok());
        assert!(validate_filename("123456789").is_ok());
        assert!(validate_filename("_-_.png").is_ok());
    }
}
