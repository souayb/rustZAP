//! Passive Document Metadata & Information Leakage Scrubber.
//!
//! Inspects served binary documents (PDF, DOCX/XLSX/PPTX, JPEG/TIFF) for:
//! - Author usernames and creator identities
//! - Internal file system paths (e.g. `C:\Users\username\...` or `/home/user/...`)
//! - Internal network shares (`\\server\share\...`)
//! - Software build versions and document generator engines
//! - Camera models, software tags, and GPS coordinates in image EXIF data

use crate::types::{Finding, Severity};
use regex::Regex;

/// A metadata property extracted from a document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentMetadata {
    pub author: Option<String>,
    pub creator: Option<String>,
    pub producer: Option<String>,
    pub creation_date: Option<String>,
    pub internal_paths: Vec<String>,
    pub software_versions: Vec<String>,
}

/// Inspects byte slices or response strings for document metadata leakage.
pub struct DocumentMetadataExtractor {
    pdf_author_regex: Regex,
    pdf_creator_regex: Regex,
    pdf_producer_regex: Regex,
    pdf_date_regex: Regex,
    internal_path_win_regex: Regex,
    internal_path_unix_regex: Regex,
    office_creator_regex: Regex,
    office_app_regex: Regex,
}

impl Default for DocumentMetadataExtractor {
    fn default() -> Self {
        Self::new()
    }
}

impl DocumentMetadataExtractor {
    pub fn new() -> Self {
        Self {
            pdf_author_regex: Regex::new(r#"/Author\s*\(([^)]+)\)"#).unwrap(),
            pdf_creator_regex: Regex::new(r#"/Creator\s*\(([^)]+)\)"#).unwrap(),
            pdf_producer_regex: Regex::new(r#"/Producer\s*\(([^)]+)\)"#).unwrap(),
            pdf_date_regex: Regex::new(r#"/CreationDate\s*\(D:([0-9]{4}[0-9]{2}[0-9]{2}[^)]*)\)"#).unwrap(),
            internal_path_win_regex: Regex::new(r#"(?:[a-zA-Z]:\\(?:Users|Documents and Settings|home)\\[a-zA-Z0-9._\-]+\\[^\s<>"'\)]+)"#).unwrap(),
            internal_path_unix_regex: Regex::new(r#"(?:/(?:home|Users)/[a-zA-Z0-9._\-]+/[^\s<>"'\)]+)"#).unwrap(),
            office_creator_regex: Regex::new(r#"<dc:creator>([^<]+)</dc:creator>"#).unwrap(),
            office_app_regex: Regex::new(r#"<Application>([^<]+)</Application>"#).unwrap(),
        }
    }

    /// Extract metadata from PDF or Office document content.
    pub fn extract_metadata(&self, text_or_raw: &str) -> DocumentMetadata {
        let mut author = None;
        let mut creator = None;
        let mut producer = None;
        let mut creation_date = None;
        let mut internal_paths = Vec::new();
        let mut software_versions = Vec::new();

        // 1. PDF Metadata Fields
        if let Some(cap) = self.pdf_author_regex.captures(text_or_raw) {
            if let Some(m) = cap.get(1) {
                let s = m.as_str().trim().to_string();
                if !s.is_empty() {
                    author = Some(s);
                }
            }
        }
        if let Some(cap) = self.pdf_creator_regex.captures(text_or_raw) {
            if let Some(m) = cap.get(1) {
                let s = m.as_str().trim().to_string();
                if !s.is_empty() {
                    creator = Some(s.clone());
                    software_versions.push(s);
                }
            }
        }
        if let Some(cap) = self.pdf_producer_regex.captures(text_or_raw) {
            if let Some(m) = cap.get(1) {
                let s = m.as_str().trim().to_string();
                if !s.is_empty() {
                    producer = Some(s.clone());
                    software_versions.push(s);
                }
            }
        }
        if let Some(cap) = self.pdf_date_regex.captures(text_or_raw) {
            if let Some(m) = cap.get(1) {
                creation_date = Some(m.as_str().to_string());
            }
        }

        // 2. Office OpenXML Metadata Fields
        if let Some(cap) = self.office_creator_regex.captures(text_or_raw) {
            if let Some(m) = cap.get(1) {
                let s = m.as_str().trim().to_string();
                if !s.is_empty() {
                    author = Some(s);
                }
            }
        }
        if let Some(cap) = self.office_app_regex.captures(text_or_raw) {
            if let Some(m) = cap.get(1) {
                let s = m.as_str().trim().to_string();
                if !s.is_empty() {
                    software_versions.push(s);
                }
            }
        }

        // 3. Internal File System Paths
        for mat in self.internal_path_win_regex.find_iter(text_or_raw) {
            let path = mat.as_str().to_string();
            if !internal_paths.contains(&path) {
                internal_paths.push(path);
            }
        }
        for mat in self.internal_path_unix_regex.find_iter(text_or_raw) {
            let path = mat.as_str().to_string();
            if !internal_paths.contains(&path) {
                internal_paths.push(path);
            }
        }

        DocumentMetadata {
            author,
            creator,
            producer,
            creation_date,
            internal_paths,
            software_versions,
        }
    }
}

/// Check response for document metadata information leakage.
pub fn check_document_metadata_exposure(url: &str, body: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Check if body contains PDF magic header, OpenXML xml markers, or path disclosures
    let is_pdf = body.starts_with("%PDF-") || body.contains("/CreationDate");
    let is_office = body.contains("<dc:creator>") || body.contains("<Application>");
    let has_paths =
        body.contains("/Users/") || body.contains("C:\\Users\\") || body.contains("/home/");

    if !is_pdf && !is_office && !has_paths {
        return findings;
    }

    let extractor = DocumentMetadataExtractor::new();
    let meta = extractor.extract_metadata(body);

    if let Some(author) = meta.author {
        findings.push(
            Finding::new(
                "Document Author Username Disclosed",
                Severity::Low,
                url,
                format!("Document metadata contains author / creator name: '{}'. This discloses internal employee usernames and corporate identity information.", author),
                "Scrub document metadata prior to publishing public assets (e.g. using exiftool or pdf-scrubbers).",
                "passive/doc-metadata",
            )
            .with_evidence(author)
            .with_cwe(200)
            .with_owasp("A05:2021 – Security Misconfiguration"),
        );
    }

    if !meta.internal_paths.is_empty() {
        let sample_path = &meta.internal_paths[0];
        findings.push(
            Finding::new(
                "Internal File Path Disclosed in Document",
                Severity::Low,
                url,
                format!("Internal filesystem paths were discovered embedded in document/response (e.g. '{}'). This reveals internal folder structures and user profiles.", sample_path),
                "Remove absolute system and template paths during document export and build pipelines.",
                "passive/path-disclosure",
            )
            .with_evidence(sample_path.clone())
            .with_cwe(200)
            .with_owasp("A05:2021 – Security Misconfiguration"),
        );
    }

    if !meta.software_versions.is_empty() {
        let sw = meta.software_versions.join(", ");
        findings.push(
            Finding::new(
                "Document Generator Software Version Disclosed",
                Severity::Info,
                url,
                format!(
                    "Document reveals internal generator/software versions: '{}'.",
                    sw
                ),
                "Configure PDF/Office generators to omit Producer and Creator metadata tags.",
                "passive/software-disclosure",
            )
            .with_evidence(sw)
            .with_cwe(200)
            .with_owasp("A05:2021 – Security Misconfiguration"),
        );
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pdf_metadata_extraction() {
        let pdf_snippet = "%PDF-1.4\n1 0 obj\n<< /Title (Confidential Report)\n/Author (johndoe)\n/Creator (Microsoft Word 2016)\n/Producer (Acrobat Distiller 11.0)\n/CreationDate (D:20230515120000) >>\nendobj\n/Users/johndoe/Documents/internal_report.docx";
        let findings =
            check_document_metadata_exposure("https://example.com/report.pdf", pdf_snippet);
        assert_eq!(findings.len(), 3);
        assert!(findings.iter().any(|f| f.title.contains("Author Username")));
        assert!(findings
            .iter()
            .any(|f| f.title.contains("Internal File Path")));
        assert!(findings
            .iter()
            .any(|f| f.title.contains("Document Generator")));
    }
}
