// File: xml.rs
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023-2025
// - Volker Schwaberow <volker@schwaberow.de>

use anyhow::Result;

use super::{ReportConfig, ReportData, ReportGenerator};

pub struct XmlGenerator;

impl XmlGenerator {
    pub fn new() -> Self {
        Self
    }

    fn escape_xml(&self, input: &str) -> String {
        input
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\"", "&quot;")
            .replace("'", "&apos;")
    }
}

impl ReportGenerator for XmlGenerator {
    fn generate(&self, data: &ReportData, _config: &ReportConfig) -> Result<String> {
        let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        xml.push_str(&format!(
            "<report generated_at=\"{}\" title=\"{}\">\n",
            data.generated_at.to_rfc3339(),
            self.escape_xml(&data.title)
        ));

        xml.push_str("  <summary>\n");
        xml.push_str(&format!(
            "    <total_scans>{}</total_scans>\n",
            data.summary.total_scans
        ));
        xml.push_str(&format!(
            "    <successful_scans>{}</successful_scans>\n",
            data.summary.successful_scans
        ));
        xml.push_str(&format!(
            "    <failed_scans>{}</failed_scans>\n",
            data.summary.failed_scans
        ));
        xml.push_str(&format!(
            "    <unique_urls>{}</unique_urls>\n",
            data.summary.unique_urls
        ));
        xml.push_str(&format!(
            "    <total_detections>{}</total_detections>\n",
            data.summary.total_detections
        ));

        xml.push_str("    <security_findings>\n");
        xml.push_str(&format!(
            "      <total>{}</total>\n",
            data.summary.security_findings.total_findings
        ));
        xml.push_str(&format!(
            "      <critical>{}</critical>\n",
            data.summary.security_findings.critical_count
        ));
        xml.push_str(&format!(
            "      <high>{}</high>\n",
            data.summary.security_findings.high_count
        ));
        xml.push_str(&format!(
            "      <medium>{}</medium>\n",
            data.summary.security_findings.medium_count
        ));
        xml.push_str(&format!(
            "      <low>{}</low>\n",
            data.summary.security_findings.low_count
        ));
        xml.push_str(&format!(
            "      <info>{}</info>\n",
            data.summary.security_findings.info_count
        ));
        xml.push_str("    </security_findings>\n");

        xml.push_str("    <technologies>\n");
        for tech in &data.summary.unique_technologies {
            xml.push_str(&format!(
                "      <technology>{}</technology>\n",
                self.escape_xml(tech)
            ));
        }
        xml.push_str("    </technologies>\n");

        xml.push_str("  </summary>\n");

        xml.push_str("  <scans>\n");
        for scan in &data.scans {
            xml.push_str(&format!(
                "    <scan id=\"{}\" timestamp=\"{}\" url=\"{}\" status=\"{}\">\n",
                self.escape_xml(&scan.id),
                scan.timestamp.to_rfc3339(),
                self.escape_xml(&scan.url),
                self.escape_xml(&scan.status)
            ));

            if !scan.detections.is_empty() {
                xml.push_str("      <detections>\n");
                for detection in &scan.detections {
                    xml.push_str(&format!(
                        "        <detection>{}</detection>\n",
                        self.escape_xml(detection)
                    ));
                }
                xml.push_str("      </detections>\n");
            }

            if !scan.content_findings.is_empty() {
                xml.push_str("      <content_findings>\n");
                for finding in &scan.content_findings {
                    xml.push_str(&format!(
                        "        <finding category=\"{}\" severity=\"{:?}\">\n",
                        self.escape_xml(&finding.category),
                        finding.severity
                    ));
                    xml.push_str(&format!(
                        "          <description>{}</description>\n",
                        self.escape_xml(&finding.description)
                    ));

                    if let Some(ref matched) = finding.matched_text {
                        xml.push_str(&format!(
                            "          <matched_text>{}</matched_text>\n",
                            self.escape_xml(matched)
                        ));
                    }

                    if let Some(ref context) = finding.context {
                        xml.push_str(&format!(
                            "          <context>{}</context>\n",
                            self.escape_xml(context)
                        ));
                    }

                    xml.push_str("        </finding>\n");
                }
                xml.push_str("      </content_findings>\n");
            }

            if !scan.tls_info.is_empty() {
                xml.push_str("      <tls_info>\n");
                for (key, value) in &scan.tls_info {
                    xml.push_str(&format!(
                        "        <{}>{}</{}>\n",
                        self.escape_xml(key),
                        self.escape_xml(value),
                        self.escape_xml(key)
                    ));
                }
                xml.push_str("      </tls_info>\n");
            }

            if let Some(response_time) = scan.response_time_ms {
                xml.push_str(&format!(
                    "      <response_time_ms>{}</response_time_ms>\n",
                    response_time
                ));
            }

            if let Some(content_length) = scan.content_length {
                xml.push_str(&format!(
                    "      <content_length>{}</content_length>\n",
                    content_length
                ));
            }

            xml.push_str("    </scan>\n");
        }
        xml.push_str("  </scans>\n");

        xml.push_str("</report>\n");
        Ok(xml)
    }

    fn file_extension(&self) -> &'static str {
        "xml"
    }

    fn content_type(&self) -> &'static str {
        "application/xml"
    }
}
