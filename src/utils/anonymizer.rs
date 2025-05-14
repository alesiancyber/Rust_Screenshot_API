use log::{debug, info};
use rand::{thread_rng, Rng};
use rand::distributions::Alphanumeric;

pub struct Anonymizer {
    fake_emails: Vec<String>,
    fake_usernames: Vec<String>,
}

impl Anonymizer {
    pub fn new() -> Self {
        Anonymizer {
            fake_emails: vec![
                "user@example.com".to_string(),
                "test@example.com".to_string(),
                "demo@example.com".to_string(),
            ],
            fake_usernames: vec![
                "testuser".to_string(),
                "demouser".to_string(),
                "exampleuser".to_string(),
            ],
        }
    }

    pub fn anonymize_value(&self, value: &str) -> String {
        debug!("Anonymizing value: {}", value);
        
        // Check if it's an email
        if value.contains('@') {
            let random_email = self.fake_emails[thread_rng().gen_range(0..self.fake_emails.len())].clone();
            info!("Replaced email {} with {}", value, random_email);
            return random_email;
        }

        // Check if it's a username (no @ symbol, alphanumeric)
        if value.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') {
            let random_username = self.fake_usernames[thread_rng().gen_range(0..self.fake_usernames.len())].clone();
            info!("Replaced username {} with {}", value, random_username);
            return random_username;
        }

        // For other values, generate a random string
        let random_string: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(10)
            .map(char::from)
            .collect();
        
        info!("Replaced value {} with random string {}", value, random_string);
        random_string
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anonymize_email() {
        let anonymizer = Anonymizer::new();
        let result = anonymizer.anonymize_value("test@example.com");
        assert!(result.contains('@'));
        assert!(result.ends_with("example.com"));
    }

    #[test]
    fn test_anonymize_username() {
        let anonymizer = Anonymizer::new();
        let result = anonymizer.anonymize_value("testuser123");
        assert!(!result.contains('@'));
        assert!(result.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-'));
    }
} 