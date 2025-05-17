// Main module file that re-exports components
mod identifier;
mod parser;
mod url_collection;
mod url_processor;
mod url_reconstructor;
mod url_validator;

// Re-export only what's actually used externally
pub use parser::ParsedUrl;

// These additional exports are kept for API stability but currently not used in tests
// Can be uncommented when needed by external consumers
#[allow(unused_imports)]
pub use url_collection::{DomainInfo};
#[allow(unused_imports)]
pub use identifier::Identifier;

// Re-export processing functions for advanced usage
