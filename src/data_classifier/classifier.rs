use super::{SensitiveDataType, patterns::*};

/// Returns Some(SensitiveDataType) if the value matches a sensitive pattern, else None
pub fn classify_sensitive(value: &str) -> Option<SensitiveDataType> {
    if EMAIL_REGEX.is_match(value) {
        Some(SensitiveDataType::Email)
    } else if PHONE_REGEX.is_match(value) {
        Some(SensitiveDataType::Phone)
    } else if !value.contains(' ') && !value.contains('@') {
        Some(SensitiveDataType::Username)
    } else if !value.is_empty() {
        Some(SensitiveDataType::Other)
    } else {
        None
    }
} 