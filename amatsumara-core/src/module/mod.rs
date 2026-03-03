///! Core module system for Metasploit
///!
///! This module defines the trait hierarchy for all Metasploit modules including
///! exploits, auxiliary, post-exploitation, payloads, encoders, and evasion modules.

pub mod metadata;
pub mod options;
pub mod check;

pub use metadata::*;
pub use options::*;
pub use check::CheckCode;

use anyhow::Result;
use async_trait::async_trait;
use std::collections::HashMap;

/// Execution context for modules
pub struct Context {
    /// Module-specific datastore
    pub datastore: HashMap<String, String>,

    // Global framework datastore reference would go here:
    // pub framework: &'a Framework,
}

impl Context {
    pub fn new() -> Self {
        Self {
            datastore: HashMap::new(),
        }
    }

    pub fn get(&self, key: &str) -> Option<&String> {
        self.datastore.get(key)
    }

    pub fn set(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.datastore.insert(key.into(), value.into());
    }
}

impl Default for Context {
    fn default() -> Self {
        Self::new()
    }
}

/// Base trait for all Metasploit modules
#[async_trait]
pub trait Module: Send + Sync {
    /// Get module metadata
    fn metadata(&self) -> &ModuleMetadata;

    /// Get module options
    fn options(&self) -> &Options;

    /// Validate module options
    fn validate(&self, ctx: &Context) -> Result<()> {
        self.options().validate(&ctx.datastore)
    }

    /// Module type name
    fn module_type(&self) -> &'static str;
}

/// Exploit module trait
#[async_trait]
pub trait Exploit: Module {
    /// Check if target is vulnerable
    async fn check(&self, ctx: &mut Context) -> Result<CheckCode>;

    /// Execute the exploit
    async fn exploit(&self, ctx: &mut Context) -> Result<SessionHandle>;

    /// Get available targets
    fn targets(&self) -> &[Target];

    /// Get selected target index
    fn target_index(&self) -> usize {
        0  // Default to first target
    }

    /// Get selected target
    fn target(&self) -> &Target {
        &self.targets()[self.target_index()]
    }
}

/// Auxiliary module trait (scanners, fuzzers, DoS, etc.)
#[async_trait]
pub trait Auxiliary: Module {
    /// Run the auxiliary module
    async fn run(&self, ctx: &mut Context) -> Result<()>;

    /// Get available actions (if module supports multiple actions)
    fn actions(&self) -> &[Action] {
        &[]
    }
}

/// Post-exploitation module trait
#[async_trait]
pub trait Post: Module {
    /// Run post-exploitation module on a session
    async fn run(&self, ctx: &mut Context, session: &SessionHandle) -> Result<()>;

    /// Check if compatible with session type
    fn compatible_with(&self, session: &SessionHandle) -> bool;
}

/// Payload module trait
pub trait Payload: Module {
    /// Generate payload bytes
    fn generate(&self, ctx: &Context) -> Result<Vec<u8>>;

    /// Get payload size
    fn size(&self) -> usize;

    /// Whether payload is staged (requires stager)
    fn staged(&self) -> bool {
        false
    }
}

/// Encoder module trait
pub trait Encoder: Module {
    /// Encode payload
    fn encode(&self, data: &[u8], bad_chars: &[u8]) -> Result<Vec<u8>>;

    /// Decoder stub for prepending
    fn decoder_stub(&self) -> &[u8];
}

/// Evasion module trait
#[async_trait]
pub trait Evasion: Module {
    /// Run evasion technique
    async fn run(&self, ctx: &mut Context) -> Result<()>;
}

/// Target definition for exploit modules
#[derive(Debug, Clone)]
pub struct Target {
    pub name: String,
    pub platform: Platform,
    pub arch: Arch,
    pub ret_addr: Option<usize>,
    pub offsets: HashMap<String, usize>,
}

impl Target {
    pub fn new(name: impl Into<String>, platform: Platform, arch: Arch) -> Self {
        Self {
            name: name.into(),
            platform,
            arch,
            ret_addr: None,
            offsets: HashMap::new(),
        }
    }

    pub fn with_ret(mut self, addr: usize) -> Self {
        self.ret_addr = Some(addr);
        self
    }

    pub fn with_offset(mut self, name: impl Into<String>, offset: usize) -> Self {
        self.offsets.insert(name.into(), offset);
        self
    }
}

/// Action for auxiliary modules that support multiple actions
#[derive(Debug, Clone)]
pub struct Action {
    pub name: String,
    pub description: String,
}

impl Action {
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
        }
    }
}

/// Handle to an active session
#[derive(Debug, Clone)]
pub struct SessionHandle {
    pub id: u32,
    pub session_type: SessionType,
}

/// Types of sessions
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionType {
    Shell,
    Meterpreter,
    Ring,
    // More session types as needed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_context() {
        let mut ctx = Context::new();
        ctx.set("RHOST", "192.168.1.1");
        ctx.set("RPORT", "445");

        assert_eq!(ctx.get("RHOST"), Some(&"192.168.1.1".to_string()));
        assert_eq!(ctx.get("RPORT"), Some(&"445".to_string()));
        assert_eq!(ctx.get("NONEXISTENT"), None);
    }

    #[test]
    fn test_target() {
        let target = Target::new("Windows 10 x64", Platform::Windows, Arch::X64)
            .with_ret(0x77701234)
            .with_offset("buffer", 512);

        assert_eq!(target.name, "Windows 10 x64");
        assert_eq!(target.ret_addr, Some(0x77701234));
        assert_eq!(target.offsets.get("buffer"), Some(&512));
    }
}
