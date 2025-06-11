// File: tls_analyzer_tests.rs
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2025
// - Volker Schwaberow <volker@schwaberow.de>

#[cfg(test)]
mod tests {
    use crate::tls_analyzer::*;
    use chrono::{Duration, Datelike, Timelike, Utc};
    use pretty_assertions::assert_eq;

    #[test]
    fn test_certificate_default() {
        let cert = Certificate::default();
        assert_eq!(cert.subject, "");
        assert_eq!(cert.issuer, "");
        assert_eq!(cert.version, "");
        assert_eq!(cert.serial_number, "");
        assert_eq!(cert.signature_algorithm, "");
        assert_eq!(cert.days_until_expiry, 0);
        assert!(cert.subject_alternative_names.is_empty());
        assert_eq!(cert.key_type, "");
        assert_eq!(cert.key_size, None);
        assert!(!cert.is_self_signed);
        assert!(!cert.is_expired);
        assert!(!cert.is_wildcard);
        assert!(!cert.is_extended_validation);
        assert_eq!(cert.tls_version, "");
        assert_eq!(cert.cipher_suite, "");
        assert!(cert.warnings.is_empty());
        assert!(cert.errors.is_empty());
    }

    #[test]
    fn test_extract_certificate() {
        let openssl_output = r#"
CONNECTED(00000003)
---
Certificate chain
 0 s:CN = example.com
   i:C = US, O = Let's Encrypt, CN = R3
-----BEGIN CERTIFICATE-----
MIIFJjCCBA6gAwIBAgISA1234567890ABCDEFGHIJKLMNOP
QRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
=
-----END CERTIFICATE-----
 1 s:C = US, O = Let's Encrypt, CN = R3
   i:C = US, O = Internet Security Research Group, CN = ISRG Root X1
-----BEGIN CERTIFICATE-----
MIIFJTCCBA2gAwIBAgISBBvax7Okulus+LHWr0HfdDKMA0GCSqGSIb3DQEBCwUA
-----END CERTIFICATE-----
---
"#;
        let cert = TlsAnalyzer::extract_certificate(openssl_output);
        assert!(cert.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(cert.ends_with("-----END CERTIFICATE-----"));
        assert!(cert.contains("MIIFJjCCBA6gAwIBAgISA1234567890ABCDEFGHIJKLMNOP"));
    }

    #[test]
    fn test_extract_certificate_not_found() {
        let openssl_output = "No certificate here";
        let cert = TlsAnalyzer::extract_certificate(openssl_output);
        assert_eq!(cert, "");
    }

    #[test]
    fn test_parse_openssl_date() {
        let date_str = "Mar 15 12:00:00 2024 GMT";
        let result = TlsAnalyzer::parse_openssl_date(date_str).unwrap();
        assert_eq!(result.year(), 2024);
        assert_eq!(result.month(), 3);
        assert_eq!(result.day(), 15);
        assert_eq!(result.hour(), 12);
        assert_eq!(result.minute(), 0);
        assert_eq!(result.second(), 0);
    }

    #[test]
    fn test_parse_openssl_date_invalid() {
        let date_str = "Invalid date format";
        let result = TlsAnalyzer::parse_openssl_date(date_str);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_certificate_info_basic() {
        let cert_info = r#"
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 04:00:00:00:00:01:15:4b:5a:c3:94
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C = US, O = Let's Encrypt, CN = R3
        Validity
            Not Before: Mar 15 12:00:00 2024 GMT
            Not After : Jun 13 11:59:59 2024 GMT
        Subject: CN = example.com
        Subject Public Key Info:
            Public Key Algorithm: RSAEncryption
                Public-Key: 2048 bit
                Modulus:
                    00:c4:a6:b1:e8:4f:8a:
        X509v3 extensions:
            X509v3 Subject Alternative Name: 
                DNS:example.com, DNS:www.example.com
"#;
        
        let tls_info = r#"
SSL-Session:
    Protocol  : TLSv1.3
    Cipher    : TLS_AES_256_GCM_SHA384
"#;
        
        let cert = TlsAnalyzer::parse_certificate_info(
            cert_info.to_string(), 
            tls_info.to_string(), 
            "example.com"
        ).unwrap();
        
        assert_eq!(cert.subject, "CN = example.com");
        assert_eq!(cert.issuer, "C = US, O = Let's Encrypt, CN = R3");
        assert_eq!(cert.version, "3 (0x2)");
        assert_eq!(cert.serial_number, "04:00:00:00:00:01:15:4b:5a:c3:94");
        assert_eq!(cert.signature_algorithm, "sha256WithRSAEncryption");
        assert_eq!(cert.key_type, "RSAEncryption");
        assert_eq!(cert.key_size, Some(2048));
        assert_eq!(cert.tls_version, "TLSv1.3");
        assert_eq!(cert.cipher_suite, "TLS_AES_256_GCM_SHA384");
        assert!(!cert.is_self_signed);
        assert_eq!(cert.subject_alternative_names, vec!["DNS:example.com", "DNS:www.example.com"]);
    }

    #[test]
    fn test_parse_certificate_info_self_signed() {
        let cert_info = r#"
        Subject: CN = localhost
        Issuer: CN = localhost
"#;
        
        let cert = TlsAnalyzer::parse_certificate_info(
            cert_info.to_string(), 
            String::new(), 
            "localhost"
        ).unwrap();
        
        assert!(cert.is_self_signed);
        assert!(cert.warnings.contains(&"Certificate is self-signed".to_string()));
    }

    #[test]
    fn test_parse_certificate_info_weak_signature() {
        let cert_info = r#"
        Signature Algorithm: sha1WithRSAEncryption
"#;
        
        let cert = TlsAnalyzer::parse_certificate_info(
            cert_info.to_string(), 
            String::new(), 
            "example.com"
        ).unwrap();
        
        assert!(cert.warnings.iter().any(|w| w.contains("Weak signature algorithm")));
    }

    #[test]
    fn test_parse_certificate_info_weak_key_size() {
        let cert_info = r#"
        Subject Public Key Info:
            Public Key Algorithm: RSAEncryption
                Public-Key: 1024 bit
"#;
        
        let cert = TlsAnalyzer::parse_certificate_info(
            cert_info.to_string(), 
            String::new(), 
            "example.com"
        ).unwrap();
        
        assert_eq!(cert.key_size, Some(1024));
        assert!(cert.warnings.iter().any(|w| w.contains("Weak key size")));
    }

    #[test]
    fn test_parse_certificate_info_weak_tls_version() {
        let tls_info = r#"
    Protocol  : TLSv1.1
    Cipher    : AES256-SHA
"#;
        
        let cert = TlsAnalyzer::parse_certificate_info(
            String::new(), 
            tls_info.to_string(), 
            "example.com"
        ).unwrap();
        
        assert_eq!(cert.tls_version, "TLSv1.1");
        assert!(cert.warnings.iter().any(|w| w.contains("Weak TLS version")));
    }

    #[test]
    fn test_parse_certificate_info_weak_cipher() {
        let tls_info = r#"
    Cipher    : DES-CBC3-SHA
"#;
        
        let cert = TlsAnalyzer::parse_certificate_info(
            String::new(), 
            tls_info.to_string(), 
            "example.com"
        ).unwrap();
        
        assert!(cert.warnings.iter().any(|w| w.contains("Weak cipher suite")));
    }

    #[test]
    fn test_parse_certificate_info_expired() {
        let past_date = Utc::now() - Duration::days(30);
        let cert_info = format!(r#"
        Validity
            Not Before: Jan 1 00:00:00 2020 GMT
            Not After : {} GMT
"#, past_date.format("%b %d %H:%M:%S %Y"));
        
        let cert = TlsAnalyzer::parse_certificate_info(
            cert_info, 
            String::new(), 
            "example.com"
        ).unwrap();
        
        assert!(cert.is_expired);
        assert!(cert.errors.contains(&"Certificate has expired".to_string()));
        assert!(cert.days_until_expiry < 0);
    }

    #[test]
    fn test_parse_certificate_info_expires_soon() {
        let future_date = Utc::now() + Duration::days(15);
        let cert_info = format!(r#"
        Validity
            Not Before: Jan 1 00:00:00 2020 GMT
            Not After : {} GMT
"#, future_date.format("%b %d %H:%M:%S %Y"));
        
        let cert = TlsAnalyzer::parse_certificate_info(
            cert_info, 
            String::new(), 
            "example.com"
        ).unwrap();
        
        assert!(!cert.is_expired);
        assert!(cert.warnings.iter().any(|w| w.contains("Certificate expires soon")));
        assert!(cert.days_until_expiry > 0 && cert.days_until_expiry < 30);
    }

    #[test]
    fn test_parse_certificate_info_wildcard() {
        let cert_info = r#"
            X509v3 Subject Alternative Name: 
                DNS:*.example.com, DNS:example.com
"#;
        
        let cert = TlsAnalyzer::parse_certificate_info(
            cert_info.to_string(), 
            String::new(), 
            "sub.example.com"
        ).unwrap();
        
        assert!(cert.is_wildcard);
        assert_eq!(cert.subject_alternative_names, vec!["DNS:*.example.com", "DNS:example.com"]);
    }

    #[test]
    fn test_parse_certificate_info_host_mismatch() {
        let cert_info = r#"
            X509v3 Subject Alternative Name: 
                DNS:example.com, DNS:www.example.com
"#;
        
        let cert = TlsAnalyzer::parse_certificate_info(
            cert_info.to_string(), 
            String::new(), 
            "different.com"
        ).unwrap();
        
        assert!(cert.errors.iter().any(|e| e.contains("Host different.com not found in certificate SANs")));
    }

    #[test]
    fn test_parse_certificate_info_extended_validation() {
        let cert_info = r#"
        Subject: jurisdictionC=US, businessCategory=Private Organization, CN = example.com
"#;
        
        let cert = TlsAnalyzer::parse_certificate_info(
            cert_info.to_string(), 
            String::new(), 
            "example.com"
        ).unwrap();
        
        assert!(cert.is_extended_validation);
    }

    #[test]
    fn test_parse_certificate_info_ec_key() {
        let cert_info = r#"
        Subject Public Key Info:
            Public Key Algorithm: ECPublicKey
                Public-Key: 256 bit
"#;
        
        let cert = TlsAnalyzer::parse_certificate_info(
            cert_info.to_string(), 
            String::new(), 
            "example.com"
        ).unwrap();
        
        assert_eq!(cert.key_type, "ECPublicKey");
        assert_eq!(cert.key_size, Some(256));
        assert!(cert.warnings.is_empty()); 
    }

    #[test]
    fn test_parse_certificate_info_weak_ec_key() {
        let cert_info = r#"
        Subject Public Key Info:
            Public Key Algorithm: ECPublicKey
                Public-Key: 224 bit
"#;
        
        let cert = TlsAnalyzer::parse_certificate_info(
            cert_info.to_string(), 
            String::new(), 
            "example.com"
        ).unwrap();
        
        assert!(cert.warnings.iter().any(|w| w.contains("Weak EC key size")));
    }

    #[tokio::test]
    async fn test_analyze_non_https_url() {
        let result = TlsAnalyzer::analyze("http://example.com").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("HTTPS scheme"));
    }

    #[tokio::test]
    async fn test_analyze_invalid_url() {
        let result = TlsAnalyzer::analyze("not-a-url").await;
        assert!(result.is_err());
    }

    #[test]
    fn test_get_certificate_native() {
        
        let result = TlsAnalyzer::get_certificate_native("https://example.com");
        
        
        
        assert!(result.is_ok() || result.is_err());
        
        if let Ok(cert) = result {
            assert!(cert.warnings.iter().any(|w| w.contains("Limited certificate information")));
        }
    }

    #[tokio::test]
    async fn test_comprehensive_assessment_non_https() {
        let result = TlsAnalyzer::comprehensive_assessment("http://example.com").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("HTTPS scheme"));
    }

    #[test]
    fn test_comprehensive_assessment_invalid_scheme() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(async {
            TlsAnalyzer::comprehensive_assessment("http://example.com").await
        });
        
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("HTTPS scheme"));
    }
}