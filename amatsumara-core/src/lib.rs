///! Amatsumara-Core: The Divine Blacksmith's Forge
///!
///! Named after Amatsumara (天津麻羅), the Shinto god of ironworking and blacksmiths,
///! this crate provides the foundational components for the Amatsumara framework:
///! - Module trait system (exploits, auxiliary, post, payloads, encoders, evasion)
///! - Session management
///! - Dynamic module loader and registry
///! - Datastore and configuration
///! - Event system

pub mod module;
pub mod registry;
pub mod loader;
pub mod session;

// Re-export commonly used types
pub use module::{
    Module, Exploit, Auxiliary, Post, Payload, Encoder, Evasion,
    Context, Target, Action, SessionHandle, SessionType,
    ModuleMetadata, Author, Reference, ReferenceType,
    Platform, Arch, Ranking, Stability, Reliability, SideEffect,
    CheckCode, ModuleOption, Options, OptionValue, OptionType,
};

pub use registry::{ModuleRegistry, ModuleInfo, ModuleFactory};
pub use loader::{DynamicModule, ModuleDiscovery};
pub use session::{Session, SessionManager, SessionInfo, SessionType as SessionKind, SessionId};

// Re-export session channel from API
pub use amatsumara_api::session_channel::{init_session_channel, init_session_channel_with_callback, take_pending_sessions, PendingSession, SessionCallback};

// Re-export ModuleType from API
pub use amatsumara_api::ModuleType;
