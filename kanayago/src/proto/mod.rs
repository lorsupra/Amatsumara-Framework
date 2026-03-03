///! Protocol implementations for various network protocols
///!
///! This module provides protocol clients and utilities for:
///! - HTTP/HTTPS
///! - SMB
///! - SSH
///! - And more...

pub mod http;

pub use http::{HttpClient, RequestOptions, Response};
