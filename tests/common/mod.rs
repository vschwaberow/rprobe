// File: mod.rs
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023-2025
// - Volker Schwaberow <volker@schwaberow.de>

use reqwest::Response;
use serde_json::json;
use std::collections::HashMap;
use wiremock::{MockServer, Mock, ResponseTemplate};
use wiremock::matchers::{method, path};

pub fn create_mock_response(status: u16, body: &str, headers: Option<HashMap<String, String>>) -> Response {
    use std::sync::Arc;
    use reqwest::{StatusCode, Version};
    
    // Create a simple response for testing
    // Note: This is a simplified mock - in real tests we'd use a proper mock server
    let mut res = ResponseTemplate::new(status);
    if let Some(headers) = headers {
        for (key, value) in headers {
            res = res.append_header(key.as_str(), value.as_str());
        }
    }
    
    // For testing purposes, we'll use wiremock to create responses
    // This function would typically be used in conjunction with a mock server
    panic!("This function requires a mock server instance - use create_mock_server instead")
}

pub async fn create_mock_server() -> MockServer {
    MockServer::start().await
}

pub fn create_test_response_body(title: &str, server: Option<&str>) -> String {
    let server_header = match server {
        Some(s) => format!(r#"<meta name="generator" content="{}" />"#, s),
        None => String::new(),
    };
    
    format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <title>{}</title>
    {}
</head>
<body>
    <h1>Test Page</h1>
    <p>This is a test response body</p>
</body>
</html>"#,
        title, server_header
    )
}

#[allow(dead_code)]
pub fn create_wordpress_response() -> String {
    r#"<!DOCTYPE html>
<html>
<head>
    <title>WordPress Test</title>
    <meta name="generator" content="WordPress 6.3" />
    <link rel="stylesheet" href="/wp-content/themes/twentytwentythree/style.css" />
</head>
<body class="wp-body">
    <div class="wp-content">
        <h1>WordPress Site</h1>
    </div>
    <script src="/wp-includes/js/jquery/jquery.min.js"></script>
</body>
</html>"#.to_string()
}

#[allow(dead_code)]
pub fn create_apache_response() -> String {
    r#"<!DOCTYPE html>
<html>
<head>
    <title>Apache Test</title>
</head>
<body>
    <h1>It works!</h1>
    <p>Apache/2.4.41 (Ubuntu) Server at example.com Port 80</p>
</body>
</html>"#.to_string()
}