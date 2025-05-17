use crate::data_classifier::SensitiveDataType;
use rand::{seq::SliceRandom, thread_rng};

#[derive(Clone)]
pub struct Anonymizer {
    // Pre-allocated fake data vectors
    fake_emails: Vec<&'static str>,
    fake_usernames: Vec<&'static str>,
    fake_phone_numbers: Vec<&'static str>,
}

impl Anonymizer {
    pub fn new() -> Self {
        // Using static strings to avoid allocations
        Anonymizer {
            fake_emails: vec![
                "user@example.com",
                "test@example.com", 
                "demo@example.com",
            ],
            fake_usernames: vec![
                "testuser",
                "demouser",
                "exampleuser",
            ],
            fake_phone_numbers: vec![
                "555-123-4567",
                "555-987-6543",
            ],
        }
    }

    #[inline]
    pub fn anonymize_value(&self, _value: &str, ty: Option<SensitiveDataType>) -> String {
        match ty {
            Some(SensitiveDataType::Email) => self.fake_emails
                .choose(&mut thread_rng())
                .unwrap_or(&"user@example.com")
                .to_string(),
            Some(SensitiveDataType::Phone) => self.fake_phone_numbers
                .choose(&mut thread_rng())
                .unwrap_or(&"555-123-4567")
                .to_string(),
            Some(SensitiveDataType::Username) => self.fake_usernames
                .choose(&mut thread_rng())
                .unwrap_or(&"testuser")
                .to_string(),
            _ => "anonymized_value".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data_classifier::SensitiveDataType;
    
    #[test]
    fn test_anonymize_email() {
        let anonymizer = Anonymizer::new();
        let result = anonymizer.anonymize_value("test@example.com", Some(SensitiveDataType::Email));
        assert!(result.contains("@"));
    }
    
    #[test]
    fn test_anonymize_username() {
        let anonymizer = Anonymizer::new();
        let result = anonymizer.anonymize_value("testuser123", Some(SensitiveDataType::Username));
        assert!(!result.contains('@'));
    }
    
    #[test]
    fn test_anonymize_phone() {
        let anonymizer = Anonymizer::new();
        let result = anonymizer.anonymize_value("+1-555-123-4567", Some(SensitiveDataType::Phone));
        assert!(result.chars().all(|c| c.is_digit(10) || c == '-' ));
    }
    
    #[test]
    fn test_anonymize_default() {
        let anonymizer = Anonymizer::new();
        let result = anonymizer.anonymize_value("something else", None);
        assert_eq!(result, "anonymized_value");
    }
}