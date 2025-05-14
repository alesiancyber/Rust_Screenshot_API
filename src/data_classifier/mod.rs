pub mod patterns;
pub mod classifier;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SensitiveDataType {
    Email,
    Phone,
    Username,
    Other,
    // Add more as needed
} 