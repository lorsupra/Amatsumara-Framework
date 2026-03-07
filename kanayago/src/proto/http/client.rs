///! HTTP client for exploit modules
///!
///! Provides an async HTTP client with features needed for exploit development:
///! - Custom headers and methods
///! - Timeout support
///! - SSL/TLS with optional verification
///! - Proxy support
///! - Cookie management

use anyhow::{anyhow, Result};
use reqwest::{Client as ReqwestClient, Method, Response as ReqwestResponse};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

/// HTTP response
#[derive(Debug, Clone)]
pub struct Response {
    /// HTTP status code
    pub code: u16,

    /// Response body as string
    pub body: String,

    /// Response headers
    pub headers: HashMap<String, String>,
}

impl Response {
    /// Create response from reqwest response
    pub async fn from_reqwest(resp: ReqwestResponse) -> Result<Self> {
        let code = resp.status().as_u16();

        // Extract headers
        let mut headers = HashMap::new();
        for (key, value) in resp.headers().iter() {
            if let Ok(v) = value.to_str() {
                headers.insert(key.as_str().to_string(), v.to_string());
            }
        }

        // Get body
        let body = resp.text().await?;

        Ok(Self {
            code,
            body,
            headers,
        })
    }

    /// Check if response was successful (2xx status code)
    pub fn is_success(&self) -> bool {
        self.code >= 200 && self.code < 300
    }

    /// Get a header value
    pub fn header(&self, name: &str) -> Option<&String> {
        self.headers.get(&name.to_lowercase())
    }
}

/// HTTP request configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RequestOptions {
    /// HTTP method (GET, POST, etc.)
    pub method: Option<String>,

    /// Request URI/path
    pub uri: Option<String>,

    /// Custom headers
    pub headers: Option<HashMap<String, String>>,

    /// Request body/data
    pub data: Option<String>,

    /// Request timeout in seconds
    pub timeout: Option<u64>,

    /// Follow redirects
    pub redirect: Option<bool>,

    /// Verify SSL certificates
    pub ssl_verify: Option<bool>,
}

/// HTTP client for exploit modules
pub struct HttpClient {
    /// Base URL (scheme://host:port)
    base_url: String,

    /// Underlying reqwest client
    client: ReqwestClient,

    /// Default timeout
    timeout: Duration,

    /// Verify SSL certificates
    ssl_verify: bool,
}

impl HttpClient {
    /// Create a new HTTP client
    ///
    /// # Arguments
    /// * `host` - Target host (IP or hostname)
    /// * `port` - Target port
    /// * `ssl` - Whether to use HTTPS
    pub fn new(host: impl Into<String>, port: u16, ssl: bool) -> Result<Self> {
        let host = host.into();
        let scheme = if ssl { "https" } else { "http" };
        let base_url = format!("{}://{}:{}", scheme, host, port);

        // Build client with default settings
        let client = ReqwestClient::builder()
            .danger_accept_invalid_certs(true)  // Accept invalid certs by default for testing
            .redirect(reqwest::redirect::Policy::limited(5))
            .timeout(Duration::from_secs(10))
            .build()?;

        Ok(Self {
            base_url,
            client,
            timeout: Duration::from_secs(10),
            ssl_verify: false,  // Default to false for exploit development
        })
    }

    /// Set default timeout
    pub fn set_timeout(&mut self, seconds: u64) {
        self.timeout = Duration::from_secs(seconds);
    }

    /// Enable/disable SSL verification
    pub fn set_ssl_verify(&mut self, verify: bool) -> Result<()> {
        self.ssl_verify = verify;

        // Rebuild client with new SSL settings
        self.client = ReqwestClient::builder()
            .danger_accept_invalid_certs(!verify)
            .redirect(reqwest::redirect::Policy::limited(5))
            .timeout(self.timeout)
            .build()?;

        Ok(())
    }

    /// Send an HTTP request
    ///
    /// # Arguments
    /// * `opts` - Request options (uri, method, headers, data, etc.)
    ///
    /// # Examples
    /// ```no_run
    /// use kanayago::proto::http::{HttpClient, RequestOptions};
    /// use std::collections::HashMap;
    ///
    /// #[tokio::main]
    /// async fn main() -> anyhow::Result<()> {
    ///     let client = HttpClient::new("192.168.1.1", 80, false)?;
    ///
    ///     let mut opts = RequestOptions::default();
    ///     opts.method = Some("GET".to_string());
    ///     opts.uri = Some("/".to_string());
    ///
    ///     let resp = client.send_request_cgi(opts).await?;
    ///     println!("Status: {}", resp.code);
    ///     Ok(())
    /// }
    /// ```
    pub async fn send_request_cgi(&self, opts: RequestOptions) -> Result<Response> {
        let method_str = opts.method.unwrap_or_else(|| "GET".to_string());
        let uri = opts.uri.unwrap_or_else(|| "/".to_string());
        let url = format!("{}{}", self.base_url, uri);

        // Parse HTTP method
        let method = Method::from_bytes(method_str.as_bytes())
            .map_err(|_| anyhow!("Invalid HTTP method: {}", method_str))?;

        // Build request
        let mut req = self.client.request(method, &url);

        // Add headers
        if let Some(headers) = opts.headers {
            for (key, value) in headers {
                req = req.header(&key, &value);
            }
        }

        // Add body/data
        if let Some(data) = opts.data {
            req = req.body(data);
        }

        // Set timeout
        if let Some(timeout_secs) = opts.timeout {
            req = req.timeout(Duration::from_secs(timeout_secs));
        }

        // Send request
        let resp = req.send().await?;

        Response::from_reqwest(resp).await
    }

    /// Convenience method for GET requests
    pub async fn get(&self, uri: impl Into<String>) -> Result<Response> {
        let mut opts = RequestOptions::default();
        opts.method = Some("GET".to_string());
        opts.uri = Some(uri.into());
        self.send_request_cgi(opts).await
    }

    /// Convenience method for POST requests
    pub async fn post(&self, uri: impl Into<String>, data: impl Into<String>) -> Result<Response> {
        let mut opts = RequestOptions::default();
        opts.method = Some("POST".to_string());
        opts.uri = Some(uri.into());
        opts.data = Some(data.into());
        self.send_request_cgi(opts).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_construction() {
        let client = HttpClient::new("192.168.1.1", 80, false).unwrap();
        assert_eq!(client.base_url, "http://192.168.1.1:80");

        let client_ssl = HttpClient::new("example.com", 443, true).unwrap();
        assert_eq!(client_ssl.base_url, "https://example.com:443");
    }

    #[test]
    fn test_request_options() {
        let mut opts = RequestOptions::default();
        opts.method = Some("POST".to_string());
        opts.uri = Some("/api/test".to_string());
        opts.data = Some("test=data".to_string());

        assert_eq!(opts.method.unwrap(), "POST");
        assert_eq!(opts.uri.unwrap(), "/api/test");
    }

    #[test]
    fn test_response_helpers() {
        let resp = Response {
            code: 200,
            body: "OK".to_string(),
            headers: HashMap::new(),
        };

        assert!(resp.is_success());

        let resp_err = Response {
            code: 404,
            body: "Not Found".to_string(),
            headers: HashMap::new(),
        };

        assert!(!resp_err.is_success());
    }
}
