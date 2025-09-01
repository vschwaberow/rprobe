// File: content_analyzer_tests.rs
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023-2025
// - Volker Schwaberow <volker@schwaberow.de>

#[cfg(test)]
mod tests {
    use crate::content_analyzer::*;
    use crate::httpinner::HttpInner;
    use pretty_assertions::assert_eq;
    use reqwest::header::HeaderMap;

    fn create_test_http_inner(body: &str, success: bool) -> HttpInner {
        HttpInner::new_with_all(
            HeaderMap::new(),
            body.to_string(),
            if success { 200 } else { 404 },
            "https://example.com".to_string(),
            success,
        )
    }

    #[test]
    fn test_finding_severity_display() {
        assert_eq!(FindingSeverity::Info.to_string(), "Info");
        assert_eq!(FindingSeverity::Low.to_string(), "Low");
        assert_eq!(FindingSeverity::Medium.to_string(), "Medium");
        assert_eq!(FindingSeverity::High.to_string(), "High");
        assert_eq!(FindingSeverity::Critical.to_string(), "Critical");
    }

    #[test]
    fn test_extract_context() {
        let content = "This is a test string with some sensitive data in the middle";
        let start = 26;
        let end = 39;

        let context = extract_context(content, start, end, 10);
        assert!(context.contains("sensitive data"));
        assert!(context.contains("..."));
    }

    #[test]
    fn test_analyze_no_findings_empty_content() {
        let http_inner = create_test_http_inner("", true);
        let findings = ContentAnalyzer::analyze(&http_inner);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_analyze_failed_request() {
        let http_inner = create_test_http_inner("api_key='secret123'", false);
        let findings = ContentAnalyzer::analyze(&http_inner);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_aws_access_key_detection() {
        let content = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE";
        let http_inner = create_test_http_inner(content, true);
        let findings = ContentAnalyzer::analyze(&http_inner);

        assert!(!findings.is_empty());
        let finding = &findings[0];
        assert_eq!(finding.category, "AWS Access Key");
        assert_eq!(finding.severity, FindingSeverity::Critical);
        assert!(finding.matched_text.is_some());
        assert!(finding.matched_text.as_ref().unwrap().contains("****"));
    }

    #[test]
    fn test_email_detection() {
        let content = "Contact us at admin@example.com or support@test.org";
        let http_inner = create_test_http_inner(content, true);
        let findings = ContentAnalyzer::analyze(&http_inner);

        assert_eq!(findings.len(), 2);
        for finding in &findings {
            assert_eq!(finding.category, "Email Address");
            assert_eq!(finding.severity, FindingSeverity::Low);
        }
    }

    #[test]
    fn test_internal_ip_detection() {
        let content = "Server IP: 192.168.1.100, Gateway: 10.0.0.1";
        let http_inner = create_test_http_inner(content, true);
        let findings = ContentAnalyzer::analyze(&http_inner);

        assert_eq!(findings.len(), 2);
        for finding in &findings {
            assert_eq!(finding.category, "Internal IP");
            assert_eq!(finding.severity, FindingSeverity::Medium);
        }
    }

    #[test]
    fn test_multiple_findings_in_single_content() {
        let content = r#"
            Email: admin@example.com
            Server: 192.168.1.100
        "#;
        let http_inner = create_test_http_inner(content, true);

        let content_findings = ContentAnalyzer::analyze(&http_inner);
        assert!(content_findings.len() >= 2);

        let has_email = content_findings
            .iter()
            .any(|f| f.category == "Email Address");
        let has_ip = content_findings.iter().any(|f| f.category == "Internal IP");

        assert!(has_email && has_ip);
    }
}
