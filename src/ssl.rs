use anyhow::{Context, Result};
use chrono::{DateTime, TimeZone, Utc};
use log::info;
use native_tls::TlsConnector;
use serde::Serialize;
use std::io::Write;
use std::net::TcpStream;
use std::time::Duration as StdDuration;
use x509_parser::prelude::*;
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::GeneralName;
use crate::url_parser::ParsedUrl;

// Constants for better readability
const WARNING_DAYS_THRESHOLD: i64 = 30;
const CONNECTION_TIMEOUT_SECS: u64 = 5;
const DEFAULT_PORT: u16 = 443;

/// Represents parsed SSL certificate information
#[derive(Debug, Serialize, Clone)]
pub struct CertificateInfo {
    pub issuer: String,
    pub subject: String,
    pub valid_from: DateTime<Utc>,
    pub valid_to: DateTime<Utc>,
    pub days_remaining: i64,
    // pub subject_alt_names: Vec<String>,
    pub version: u32,
    pub serial_number: String,
    pub security_status: String,
}

/// Fetches and analyzes SSL certificate information for a URL
pub fn get_certificate_info_from_url(url: &str) -> Result<CertificateInfo> {
    // Use your URL parser to extract the domain
    let parsed = ParsedUrl::new(url).context("Failed to parse URL")?;
    let domain = &parsed.domain;
    
    info!("Retrieving SSL certificate for: {}", domain);
    
    // Create TLS connector
    let connector = TlsConnector::builder()
        .danger_accept_invalid_certs(true) // Allow viewing invalid certs
        .build()
        .context("Failed to create TLS connector")?;
    
    // Establish TCP connection (with timeout)
    let stream = TcpStream::connect((domain.as_str(), DEFAULT_PORT))
        .context("Failed to connect to server")?;
    stream.set_read_timeout(Some(StdDuration::from_secs(CONNECTION_TIMEOUT_SECS)))
        .context("Failed to set read timeout")?;
    stream.set_write_timeout(Some(StdDuration::from_secs(CONNECTION_TIMEOUT_SECS)))
        .context("Failed to set write timeout")?;
    
    // Perform TLS handshake
    let mut tls_stream = connector.connect(domain, stream)
        .context("TLS handshake failed")?;
    
    // Force the handshake by writing a simple HTTP request
    tls_stream.write_all(b"HEAD / HTTP/1.0\r\n\r\n")
        .context("Failed to write to TLS stream")?;
    
    // Extract the peer certificate
    let certs = tls_stream.peer_certificate()
        .context("Failed to get peer certificate")?
        .context("No certificate presented by server")?;
    
    // Get the DER-encoded certificate
    let der = certs.to_der()
        .context("Failed to convert certificate to DER format")?;
    
    process_certificate_data(&der)
}

/// Process certificate data into structured information
fn process_certificate_data(der: &[u8]) -> Result<CertificateInfo> {
    // Parse the certificate
    let (_, cert) = X509Certificate::from_der(der)
        .context("Failed to parse X509 certificate")?;
    
    // Extract issuer and subject
    let issuer = cert.issuer().to_string();
    let subject = cert.subject().to_string();
    
    // Extract validity period and convert to chrono::DateTime
    let not_before_offset = cert.validity().not_before.to_datetime();
    let not_after_offset = cert.validity().not_after.to_datetime();
    
    // Convert from time::OffsetDateTime to chrono::DateTime<Utc>
    let not_before = Utc.timestamp_opt(not_before_offset.unix_timestamp(), 0)
        .single()
        .context("Failed to convert not_before to chrono DateTime")?;
    
    let not_after = Utc.timestamp_opt(not_after_offset.unix_timestamp(), 0)
        .single()
        .context("Failed to convert not_after to chrono DateTime")?;
    
    let now = Utc::now();
    let days_remaining = (not_after - now).num_days();
    
    // Determine security status
    let security_status = if now > not_after {
        "EXPIRED - Security Risk!".to_string()
    } else if days_remaining < WARNING_DAYS_THRESHOLD {
        format!("WARNING - Expires soon ({} days)", days_remaining)
    } else {
        format!("Valid ({} days remaining)", days_remaining)
    };
    
    // // Extract Subject Alternative Names
    // let mut subject_alt_names = Vec::new();
    // if let Ok(Some(san_ext)) = cert.subject_alternative_name() {
    //     for name in &san_ext.value.general_names {
    //         if let GeneralName::DNSName(dns) = name {
    //             subject_alt_names.push(dns.to_string());
    //         }
    //     }
    // }
    
    // Extract version and serial number
    let version = cert.version().0 + 1; // X.509 versions are 0-indexed
    let serial_number = cert.tbs_certificate.raw_serial().iter()
        .map(|b| format!("{:02X}", b))
        .collect::<String>();
    
    Ok(CertificateInfo {
        issuer,
        subject,
        valid_from: not_before,
        valid_to: not_after,
        days_remaining,
        // subject_alt_names,
        version,
        serial_number,
        security_status,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    #[ignore]
    fn test_get_certificate_info() {
        let url = "https://www.google.com";
        let cert_info = get_certificate_info_from_url(url).unwrap();
        println!("Issuer: {}", cert_info.issuer);
        println!("Subject: {}", cert_info.subject);
        println!("Valid from: {}", cert_info.valid_from);
        println!("Valid to: {}", cert_info.valid_to);
        println!("Days remaining: {}", cert_info.days_remaining);
        println!("Subject Alt Names: {:?}", cert_info.subject_alt_names);
        println!("Version: {}", cert_info.version);
        println!("Serial Number: {}", cert_info.serial_number);
        println!("Security Status: {}", cert_info.security_status);
        assert!(!cert_info.issuer.is_empty(), "Issuer should not be empty");
        assert!(!cert_info.subject.is_empty(), "Subject should not be empty");
        assert!(cert_info.days_remaining >= -1000, "Certificate should not be expired for too long");
        assert!(!cert_info.subject_alt_names.is_empty(), "Subject Alt Names should not be empty");
        assert_eq!(cert_info.version, 3, "Should be X.509v3 certificate");
    }
}