use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

/// Represents a captured screenshot with both file path and base64-encoded data
#[derive(Debug)]
pub struct Screenshot {
    pub file_path: String,      // Path where the screenshot is saved
    pub image_data: String,     // Base64-encoded image data for API responses
}

impl Screenshot {
    /// Creates a new Screenshot instance
    /// 
    /// # Arguments
    /// * `file_path` - Path where the screenshot is saved
    /// * `image_data` - Base64-encoded image data
    pub fn new(file_path: String, image_data: String) -> Self {
        Self { file_path, image_data }
    }

    /// Creates a Screenshot from raw image data
    /// 
    /// # Arguments
    /// * `file_path` - Path where the screenshot is saved
    /// * `raw_data` - Raw image bytes
    pub fn from_raw(file_path: String, raw_data: &[u8]) -> Self {
        let image_data = BASE64.encode(raw_data);
        Self { file_path, image_data }
    }
} 