// File: tls_analyzer.rs
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2025
// - Volker Schwaberow <volker@schwaberow.de>

use chrono::{DateTime, Utc};
use log::{debug, info, warn};
use reqwest::Url;
use serde::Serialize;
use std::collections::HashMap;
use std::error::Error;
use std::process::Command;
use std::str;
use tokio::process::Command as TokioCommand;
use tokio::time::timeout;
use std::time::Duration as StdDuration;

#[derive(Debug, Clone, Serialize)]
pub struct Certificate {
    pub subject: String,
    pub issuer: String,
    pub version: String,
    pub serial_number: String,
    pub signature_algorithm: String,
    pub valid_from: DateTime<Utc>,
    pub valid_to: DateTime<Utc>,
    pub days_until_expiry: i64,
    pub subject_alternative_names: Vec<String>,
    pub key_type: String,
    pub key_size: Option<u32>,
    pub is_self_signed: bool,
    pub is_expired: bool,
    pub is_wildcard: bool,
    pub is_extended_validation: bool,
    pub tls_version: String,
    pub cipher_suite: String,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}

impl Default for Certificate {
    fn default() -> Self {
        Self {
            subject: String::new(),
            issuer: String::new(),
            version: String::new(),
            serial_number: String::new(),
            signature_algorithm: String::new(),
            valid_from: Utc::now(),
            valid_to: Utc::now(),
            days_until_expiry: 0,
            subject_alternative_names: Vec::new(),
            key_type: String::new(),
            key_size: None,
            is_self_signed: false,
            is_expired: false,
            is_wildcard: false,
            is_extended_validation: false,
            tls_version: String::new(),
            cipher_suite: String::new(),
            warnings: Vec::new(),
            errors: Vec::new(),
        }
    }
}

pub struct TlsAnalyzer;

impl TlsAnalyzer {
    pub async fn analyze(url_str: &str) -> Result<Certificate, Box<dyn Error>> {
        let url = Url::parse(url_str)?;
        
        if url.scheme() != "https" {
            return Err("URL must use HTTPS scheme".into());
        }
        
        let host = url.host_str().ok_or("Failed to extract host from URL")?;
        let port = url.port().unwrap_or(443);
        
        debug!("Analyzing TLS certificate for {}:{}", host, port);
        
        match Self::get_certificate_openssl(host, port).await {
            Ok(cert) => Ok(cert),
            Err(e) => {
                warn!("OpenSSL analysis failed: {}, falling back to native TLS", e);
                Self::get_certificate_native(url_str)
            }
        }
    }
    
    async fn get_certificate_openssl(host: &str, port: u16) -> Result<Certificate, Box<dyn Error>> {
        let openssl_check = Command::new("openssl").arg("version").output();
        if openssl_check.is_err() {
            return Err("OpenSSL command not available".into());
        }
        
        let timeout_duration = StdDuration::from_secs(10);
        
        let text_result = timeout(
            timeout_duration,
            TokioCommand::new("openssl")
                .args(["s_client", "-connect", &format!("{}:{}", host, port), "-servername", host, "-showcerts"])
                .output()
        ).await??;
        
        if !text_result.status.success() {
            let stderr = String::from_utf8_lossy(&text_result.stderr);
            return Err(format!("OpenSSL s_client command failed: {}", stderr).into());
        }
        
        let output = String::from_utf8_lossy(&text_result.stdout);
        let cert_text = Self::extract_certificate(&output);
        
        if cert_text.is_empty() {
            return Err("Failed to extract certificate from OpenSSL output".into());
        }
        
        let temp_file = tempfile::NamedTempFile::new()?;
        let temp_path = temp_file.path().to_string_lossy().to_string();
        std::fs::write(&temp_path, cert_text)?;
        
        let cert_info = Command::new("openssl")
            .args(["x509", "-in", &temp_path, "-text", "-noout"])
            .output()?;
        
        if !cert_info.status.success() {
            let stderr = String::from_utf8_lossy(&cert_info.stderr);
            return Err(format!("OpenSSL x509 command failed: {}", stderr).into());
        }
        
        let info_text = String::from_utf8_lossy(&cert_info.stdout).to_string();
        
        let tls_info = timeout(
            timeout_duration,
            TokioCommand::new("openssl")
                .args(["s_client", "-connect", &format!("{}:{}", host, port), 
                      "-servername", host, "-tls1_2", "-status"])
                .output()
        ).await??;
        
        let tls_output = String::from_utf8_lossy(&tls_info.stdout).to_string();
        
        Self::parse_certificate_info(info_text, tls_output, host)
    }
    
    fn extract_certificate(openssl_output: &str) -> String {
        let begin_cert = "-----BEGIN CERTIFICATE-----";
        let end_cert = "-----END CERTIFICATE-----";
        
        if let Some(begin_idx) = openssl_output.find(begin_cert) {
            if let Some(end_idx) = openssl_output[begin_idx..].find(end_cert) {
                return openssl_output[begin_idx..begin_idx + end_idx + end_cert.len()].to_string();
            }
        }
        
        String::new()
    }
    
    fn parse_certificate_info(cert_info: String, tls_info: String, host: &str) -> Result<Certificate, Box<dyn Error>> {
        let mut cert = Certificate::default();
        let mut warnings = Vec::new();
        let mut errors = Vec::new();
        
        if let Some(subject_line) = cert_info.lines().find(|l| l.contains("Subject:")) {
            cert.subject = subject_line.trim().replace("Subject:", "").trim().to_string();
        }
        
        if let Some(issuer_line) = cert_info.lines().find(|l| l.contains("Issuer:")) {
            cert.issuer = issuer_line.trim().replace("Issuer:", "").trim().to_string();
            
            cert.is_self_signed = cert.subject == cert.issuer;
            if cert.is_self_signed {
                warnings.push("Certificate is self-signed".to_string());
            }
        }
        
        if let Some(version_line) = cert_info.lines().find(|l| l.contains("Version:")) {
            cert.version = version_line.trim().replace("Version:", "").trim().to_string();
        }
        
        if let Some(serial_line) = cert_info.lines().find(|l| l.contains("Serial Number:")) {
            cert.serial_number = serial_line.trim().replace("Serial Number:", "").trim().to_string();
        }
        
        if let Some(sig_line) = cert_info.lines().find(|l| l.contains("Signature Algorithm:")) {
            cert.signature_algorithm = sig_line.trim().replace("Signature Algorithm:", "").trim().to_string();
            
            if cert.signature_algorithm.contains("md5") || cert.signature_algorithm.contains("sha1") {
                warnings.push(format!("Weak signature algorithm: {}", cert.signature_algorithm));
            }
        }
        
        let mut valid_from_str = String::new();
        let mut valid_to_str = String::new();
        
        let mut in_validity_section = false;
        for line in cert_info.lines() {
            if line.contains("Validity") {
                in_validity_section = true;
                continue;
            }
            
            if in_validity_section {
                if line.contains("Not Before:") {
                    valid_from_str = line.trim().replace("Not Before:", "").trim().to_string();
                } else if line.contains("Not After :") {
                    valid_to_str = line.trim().replace("Not After :", "").trim().to_string();
                    break;
                }
            }
        }
        
        if let Ok(valid_from) = Self::parse_openssl_date(&valid_from_str) {
            cert.valid_from = valid_from;
        }
        
        if let Ok(valid_to) = Self::parse_openssl_date(&valid_to_str) {
            cert.valid_to = valid_to;
            
            let now = Utc::now();
            cert.days_until_expiry = (valid_to - now).num_days();
            
            cert.is_expired = now > valid_to;
            if cert.is_expired {
                errors.push("Certificate has expired".to_string());
            } else if cert.days_until_expiry < 30 {
                warnings.push(format!("Certificate expires soon: {} days", cert.days_until_expiry));
            }
        }
        
        let mut in_san_section = false;
        for line in cert_info.lines() {
            if line.contains("X509v3 Subject Alternative Name:") {
                in_san_section = true;
                continue;
            }
            
            if in_san_section && line.trim().starts_with("DNS:") {
                let sans = line.trim().split(',').map(|s| s.trim().to_string()).collect::<Vec<String>>();
                cert.subject_alternative_names = sans;
                
                for san in &cert.subject_alternative_names {
                    if san.contains("DNS:*.") {
                        cert.is_wildcard = true;
                        break;
                    }
                }
                
                break;
            }
        }
        
        let host_match = cert.subject_alternative_names.iter().any(|san| {
            let san_host = san.trim_start_matches("DNS:");
            san_host == host || (san_host.starts_with("*.") && host.ends_with(&san_host[1..]))
        });
        
        if !host_match && !cert.subject_alternative_names.is_empty() {
            errors.push(format!("Host {} not found in certificate SANs", host));
        }
        
        let mut in_pubkey_section = false;
        for line in cert_info.lines() {
            if line.contains("Public Key Algorithm:") {
                in_pubkey_section = true;
                cert.key_type = line.trim().replace("Public Key Algorithm:", "").trim().to_string();
                continue;
            }
            
            if in_pubkey_section && line.contains("Key:") {
                if let Some(bits_str) = line.trim().strip_prefix("Public-Key:") {
                    if let Some(bits_val) = bits_str.trim().strip_suffix("bit") {
                        if let Ok(bits) = bits_val.trim().parse::<u32>() {
                            cert.key_size = Some(bits);
                            
                            if (cert.key_type.contains("RSA") || cert.key_type.contains("DSA")) && bits < 2048 {
                                warnings.push(format!("Weak key size: {} bits", bits));
                            } else if cert.key_type.contains("EC") && bits < 256 {
                                warnings.push(format!("Weak EC key size: {} bits", bits));
                            }
                        }
                    }
                }
                break;
            }
        }
        
        for line in tls_info.lines() {
            if line.contains("Protocol  :") {
                cert.tls_version = line.trim().replace("Protocol  :", "").trim().to_string();
                
                if cert.tls_version == "TLSv1" || cert.tls_version == "TLSv1.1" {
                    warnings.push(format!("Weak TLS version: {}", cert.tls_version));
                }
            }
            
            if line.contains("Cipher    :") {
                cert.cipher_suite = line.trim().replace("Cipher    :", "").trim().to_string();
                
                if cert.cipher_suite.contains("NULL") || 
                   cert.cipher_suite.contains("DES") || 
                   cert.cipher_suite.contains("RC4") || 
                   cert.cipher_suite.contains("MD5") {
                    warnings.push(format!("Weak cipher suite: {}", cert.cipher_suite));
                }
            }
        }
        
        cert.is_extended_validation = cert.subject.contains("jurisdictionC=") &&
                                     cert.subject.contains("businessCategory=");
        
        cert.warnings = warnings;
        cert.errors = errors;
        
        Ok(cert)
    }
    
    fn parse_openssl_date(date_str: &str) -> Result<DateTime<Utc>, Box<dyn Error>> {
        let parse_result = chrono::NaiveDateTime::parse_from_str(date_str, "%b %d %H:%M:%S %Y GMT");
        
        if let Ok(naive) = parse_result {
            Ok(DateTime::from_naive_utc_and_offset(naive, Utc))
        } else {
            Err(format!("Failed to parse date: {}", date_str).into())
        }
    }
    
    fn get_certificate_native(url_str: &str) -> Result<Certificate, Box<dyn Error>> {
        let mut cert = Certificate::default();
        let mut warnings = Vec::new();
        let errors = Vec::new();
        
        let client = reqwest::blocking::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()?;

        let _response = client.head(url_str).send()?;

        
        cert.subject = "Limited information available without OpenSSL".to_string();
        cert.issuer = "Limited information available without OpenSSL".to_string();
        
        let url = Url::parse(url_str)?;
        let host = url.host_str().ok_or("Failed to extract host from URL")?;
        
        cert.subject_alternative_names = vec![format!("DNS:{}", host)];
        
        cert.is_wildcard = host.starts_with("*.");
        
        warnings.push("Limited certificate information available without OpenSSL".to_string());
        
        cert.warnings = warnings;
        cert.errors = errors;
        
        Ok(cert)
    }
    
    pub async fn comprehensive_assessment(url_str: &str) -> Result<HashMap<String, String>, Box<dyn Error>> {
        let mut results = HashMap::new();
        let url = Url::parse(url_str)?;
        
        if url.scheme() != "https" {
            return Err("URL must use HTTPS scheme for TLS assessment".into());
        }
        
        let host = url.host_str().ok_or("Failed to extract host from URL")?;
        let port = url.port().unwrap_or(443);
        
        if let Ok(output) = Command::new("testssl.sh").arg("--version").output() {
            if output.status.success() {
                info!("Using testssl.sh for comprehensive TLS assessment");
                
                let timeout_duration = StdDuration::from_secs(120);
                
                let result = timeout(
                    timeout_duration, 
                    TokioCommand::new("testssl.sh")
                        .args(["--quiet", "--color", "0", format!("{}:{}", host, port).as_str()])
                        .output()
                ).await;
                
                if let Ok(Ok(output)) = result {
                    if output.status.success() {
                        let stdout = String::from_utf8_lossy(&output.stdout).to_string();

                        results.insert("testssl_summary".to_string(), stdout.clone()); 

                        for line in stdout.lines() {
                            if line.contains("Heartbleed") {
                                results.insert("heartbleed".to_string(), line.trim().to_string());
                            } else if line.contains("POODLE") {
                                results.insert("poodle".to_string(), line.trim().to_string());
                            } else if line.contains("FREAK") {
                                results.insert("freak".to_string(), line.trim().to_string());
                            } else if line.contains("DROWN") {
                                results.insert("drown".to_string(), line.trim().to_string());
                            } else if line.contains("LOGJAM") {
                                results.insert("logjam".to_string(), line.trim().to_string());
                            }
                        }
                    }
                }
            }
        }
        
        if let Ok(output) = Command::new("nmap").arg("--version").output() {
            if output.status.success() {
                info!("Using nmap for TLS vulnerability scanning");
                
                let timeout_duration = StdDuration::from_secs(120);
                
                let result = timeout(
                    timeout_duration,
                    TokioCommand::new("nmap")
                        .args(["-p", &port.to_string(), "--script", "ssl-enum-ciphers,ssl-cert,ssl-heartbleed", host])
                        .output()
                ).await;
                
                if let Ok(Ok(output)) = result {
                    if output.status.success() {
                        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                        results.insert("nmap_tls_scan".to_string(), stdout);
                    }
                }
            }
        }
        
        match Self::analyze(url_str).await {
            Ok(cert) => {
                results.insert("cert_subject".to_string(), cert.subject);
                results.insert("cert_issuer".to_string(), cert.issuer);
                results.insert("cert_validity".to_string(), 
                              format!("Valid from {} to {} ({} days remaining)", 
                                     cert.valid_from, cert.valid_to, cert.days_until_expiry));
                
                results.insert("cert_key_type".to_string(), 
                              format!("{} {} bits", cert.key_type, cert.key_size.unwrap_or(0)));
                
                results.insert("cert_tls_version".to_string(), cert.tls_version);
                results.insert("cert_cipher".to_string(), cert.cipher_suite);
                
                if !cert.warnings.is_empty() {
                    results.insert("cert_warnings".to_string(), cert.warnings.join(", "));
                }
                
                if !cert.errors.is_empty() {
                    results.insert("cert_errors".to_string(), cert.errors.join(", "));
                }
            },
            Err(e) => {
                results.insert("cert_error".to_string(), e.to_string());
            }
        }
        
        Ok(results)
    }
}

#[cfg(test)]
#[path = "tls_analyzer_tests.rs"]
mod tests;
