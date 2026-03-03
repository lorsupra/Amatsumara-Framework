///! Kanayago (金屋子神): The Goddess of Metalworking
///!
///! Named after the Shinto goddess of metalworking and smelting, this crate provides
///! low-level utilities for penetration testing and exploit development, including:
///! - Text manipulation and pattern generation
///! - Protocol implementations (HTTP, SSH, etc.)
///! - Socket abstractions
///! - Encoding/decoding utilities
///! - Exploitation primitives

pub mod text;
pub mod proto;

// Re-export commonly used modules
pub use text::pattern;
pub use proto::{http, HttpClient, RequestOptions, Response};
