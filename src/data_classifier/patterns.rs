use once_cell::sync::Lazy;
use regex::Regex;

pub static EMAIL_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
        .unwrap()
});

pub static PHONE_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\+?\d[\d -]{8,}\d").unwrap()
});
// Add more patterns as needed 