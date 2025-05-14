pub mod logger;
pub mod anonymizer;

pub fn url_to_snake_case(url: &str) -> String {
    let mut s = url.to_lowercase();
    s = s.replace("https", "");
    s = s.replace("http", "");
    s = s.replace("://", "");
    s = s.replace(|c: char| !c.is_ascii_alphanumeric(), "_");
    while s.contains("__") {
        s = s.replace("__", "_");
    }
    s.trim_matches('_').to_string()
} 