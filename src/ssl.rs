use anyhow::{Context, Result};
use chrono::{DateTime, TimeZone, Utc};
use tracing::{info, debug, warn, error, trace};
use native_tls::TlsConnector;
use serde::Serialize;
use std::io::Write;
use std::net::TcpStream;
use std::time::Duration as StdDuration;
use x509_parser::prelude::*;
use x509_parser::certificate::X509Certificate;
use crate::url_parser::ParsedUrl;

// Constants for better readability
const WARNING_DAYS_THRESHOLD: i64 = 30;
const CONNECTION_TIMEOUT_SECS: u64 = 5;
const DEFAULT_PORT: u16 = 443;

/// Represents parsed SSL certificate information
/// This struct contains all the relevant details extracted from an X.509 certificate
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


/// Fetches and analyzes SSL certificate information using an already parsed URL
/// 
/// This function avoids redundant URL parsing when the ParsedUrl is already available.
/// 
/// # Arguments
/// * `parsed_url` - Already parsed URL containing the domain
/// 
/// # Returns
/// * `Result<CertificateInfo>` - Structured certificate information or an error
pub fn get_certificate_info_from_parsed(parsed_url: &ParsedUrl) -> Result<CertificateInfo> {
    let domain = &parsed_url.domain;
    
    info!("Retrieving SSL certificate for domain: {}", domain);
    
    // Create TLS connector
    trace!("Building TLS connector with accept_invalid_certs=true");
    let connector = TlsConnector::builder()
        .danger_accept_invalid_certs(true) // Allow viewing invalid certs
        .build()
        .context("Failed to create TLS connector")?;
    
    // Establish TCP connection (with timeout)
    debug!("Establishing TCP connection to {}:{}", domain, DEFAULT_PORT);
    let stream = match TcpStream::connect((domain.as_str(), DEFAULT_PORT)) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to connect to server {}: {}", domain, e);
            return Err(e).context("Failed to connect to server");
        }
    };
    
    debug!("Setting connection timeouts to {} seconds", CONNECTION_TIMEOUT_SECS);
    stream.set_read_timeout(Some(StdDuration::from_secs(CONNECTION_TIMEOUT_SECS)))
        .context("Failed to set read timeout")?;
    stream.set_write_timeout(Some(StdDuration::from_secs(CONNECTION_TIMEOUT_SECS)))
        .context("Failed to set write timeout")?;
    
    // Perform TLS handshake
    debug!("Initiating TLS handshake with {}", domain);
    let mut tls_stream = match connector.connect(domain, stream) {
        Ok(s) => s,
        Err(e) => {
            error!("TLS handshake failed with {}: {}", domain, e);
            return Err(e).context("TLS handshake failed");
        }
    };
    
    // Force the handshake by writing a simple HTTP request
    trace!("Sending HEAD request to complete handshake");
    tls_stream.write_all(b"HEAD / HTTP/1.0\r\n\r\n")
        .context("Failed to write to TLS stream")?;
    
    // Extract the peer certificate
    debug!("Extracting peer certificate");
    let certs = match tls_stream.peer_certificate() {
        Ok(Some(cert)) => cert,
        Ok(None) => {
            error!("No certificate presented by server: {}", domain);
            return Err(anyhow::anyhow!("No certificate presented by server"));
        },
        Err(e) => {
            error!("Failed to get peer certificate: {}", e);
            return Err(e).context("Failed to get peer certificate");
        }
    };
    
    // Get the DER-encoded certificate
    debug!("Converting certificate to DER format");
    let der = certs.to_der()
        .context("Failed to convert certificate to DER format")?;
    
    debug!("Processing certificate data");
    process_certificate_data(&der)
}

/// Process certificate data into structured information
/// 
/// Takes raw DER-encoded certificate data and extracts relevant fields
/// into the CertificateInfo structure
/// 
/// # Arguments
/// * `der` - DER-encoded certificate data
/// 
/// # Returns
/// * `Result<CertificateInfo>` - Structured certificate information or an error
fn process_certificate_data(der: &[u8]) -> Result<CertificateInfo> {
    // Parse the certificate
    trace!("Parsing X509 certificate from DER data");
    let (_, cert) = match X509Certificate::from_der(der) {
        Ok(result) => result,
        Err(e) => {
            error!("Failed to parse X509 certificate: {}", e);
            return Err(anyhow::anyhow!("Failed to parse X509 certificate: {}", e));
        }
    };
    
    // Extract issuer and subject
    debug!("Extracting certificate details");
    let issuer = cert.issuer().to_string();
    let subject = cert.subject().to_string();
    trace!("Certificate issuer: {}", issuer);
    trace!("Certificate subject: {}", subject);
    
    // Extract validity period and convert to chrono::DateTime
    let not_before_offset = cert.validity().not_before.to_datetime();
    let not_after_offset = cert.validity().not_after.to_datetime();
    
    // Convert from time::OffsetDateTime to chrono::DateTime<Utc>
    debug!("Converting validity dates to chrono DateTime");
    let not_before = match Utc.timestamp_opt(not_before_offset.unix_timestamp(), 0).single() {
        Some(dt) => dt,
        None => {
            error!("Failed to convert not_before to chrono DateTime");
            return Err(anyhow::anyhow!("Failed to convert not_before to chrono DateTime"));
        }
    };
    
    let not_after = match Utc.timestamp_opt(not_after_offset.unix_timestamp(), 0).single() {
        Some(dt) => dt,
        None => {
            error!("Failed to convert not_after to chrono DateTime");
            return Err(anyhow::anyhow!("Failed to convert not_after to chrono DateTime"));
        }
    };
    
    trace!("Certificate valid from: {}", not_before);
    trace!("Certificate valid to: {}", not_after);
    
    let now = Utc::now();
    let days_remaining = (not_after - now).num_days();
    debug!("Certificate has {} days remaining until expiration", days_remaining);
    
    // Determine security status
    let security_status = if now > not_after {
        warn!("Certificate has EXPIRED! Expired on {}", not_after);
        "EXPIRED - Security Risk!".to_string()
    } else if days_remaining < WARNING_DAYS_THRESHOLD {
        warn!("Certificate will expire soon! Only {} days remaining", days_remaining);
        format!("WARNING - Expires soon ({} days)", days_remaining)
    } else {
        info!("Certificate is valid with {} days remaining", days_remaining);
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
    debug!("Extracting certificate version and serial number");
    let version = cert.version().0 + 1; // X.509 versions are 0-indexed
    let serial_number = cert.tbs_certificate.raw_serial().iter()
        .map(|b| format!("{:02X}", b))
        .collect::<String>();
    
    trace!("Certificate version: X.509v{}", version);
    trace!("Certificate serial number: {}", serial_number);
    
    info!("Successfully processed certificate data");
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
        // println!("Subject Alt Names: {:?}", cert_info.subject_alt_names);
        println!("Version: {}", cert_info.version);
        println!("Serial Number: {}", cert_info.serial_number);
        println!("Security Status: {}", cert_info.security_status);
        assert!(!cert_info.issuer.is_empty(), "Issuer should not be empty");
        assert!(!cert_info.subject.is_empty(), "Subject should not be empty");
        assert!(cert_info.days_remaining >= -1000, "Certificate should not be expired for too long");
        // assert!(!cert_info.subject_alt_names.is_empty(), "Subject Alt Names should not be empty");
        assert_eq!(cert_info.version, 3, "Should be X.509v3 certificate");
    }
}