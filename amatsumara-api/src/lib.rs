///! Amatsumara Module API - Stable FFI interface for dynamic modules
///!
///! This crate defines the C-compatible ABI that all dynamically loaded
///! modules must implement. It uses repr(C) types and extern "C" functions
///! to ensure binary compatibility across different Rust versions and
///! allow modules to be loaded at runtime without recompiling the framework.

use std::os::raw::{c_char, c_int};

/// API version - modules must match this to be loaded
pub const MODULE_API_VERSION: u32 = 1;

/// Module types
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum ModuleType {
    Exploit = 0,
    Auxiliary = 1,
    Post = 2,
    Payload = 3,
    Encoder = 4,
    Evasion = 5,
    Utility = 6,
}

/// Platform types
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum Platform {
    Linux = 0,
    Windows = 1,
    MacOS = 2,
    BSD = 3,
    Solaris = 4,
    Multi = 5,
}

/// Architecture types
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum Arch {
    X86 = 0,
    X64 = 1,
    ARM = 2,
    ARM64 = 3,
    MIPS = 4,
}

/// Module ranking
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, PartialOrd)]
pub enum Ranking {
    Manual = 0,
    Low = 100,
    Average = 200,
    Normal = 300,
    Good = 400,
    Great = 500,
    Excellent = 600,
}

/// C-compatible string (null-terminated)
#[repr(C)]
pub struct CString {
    pub ptr: *const c_char,
    pub len: usize,
}

// SAFETY: CString is used in FFI and should be Sync for static use
unsafe impl Sync for CString {}

impl CString {
    pub fn from_str(s: &str) -> Self {
        Self {
            ptr: s.as_ptr() as *const c_char,
            len: s.len(),
        }
    }

    pub unsafe fn as_str(&self) -> &str {
        std::str::from_utf8_unchecked(std::slice::from_raw_parts(
            self.ptr as *const u8,
            self.len,
        ))
    }
}

/// C-compatible array of platforms
#[repr(C)]
pub struct PlatformArray {
    pub ptr: *const Platform,
    pub len: usize,
}

// SAFETY: PlatformArray is used in FFI and should be Sync for static use
unsafe impl Sync for PlatformArray {}

/// C-compatible array of architectures
#[repr(C)]
pub struct ArchArray {
    pub ptr: *const Arch,
    pub len: usize,
}

// SAFETY: ArchArray is used in FFI and should be Sync for static use
unsafe impl Sync for ArchArray {}

/// Module metadata (C-compatible)
#[repr(C)]
pub struct ModuleMetadata {
    pub name: CString,
    pub description: CString,
    pub author: CString,
    pub module_type: ModuleType,
    pub platforms: PlatformArray,
    pub archs: ArchArray,
    pub ranking: Ranking,
    pub privileged: bool,
}

// SAFETY: ModuleMetadata is used in FFI and should be Sync for static use
unsafe impl Sync for ModuleMetadata {}

/// Module option type
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum OptionType {
    String = 0,
    Int = 1,
    Bool = 2,
    Address = 3,
    Port = 4,
}

/// Module option (C-compatible)
#[repr(C)]
pub struct ModuleOption {
    pub name: CString,
    pub description: CString,
    pub required: bool,
    pub option_type: OptionType,
    pub default_value: CString,
}

// SAFETY: ModuleOption is used in FFI and should be Sync for static use
unsafe impl Sync for ModuleOption {}

/// Array of module options
#[repr(C)]
pub struct OptionArray {
    pub ptr: *const ModuleOption,
    pub len: usize,
}

// SAFETY: OptionArray is used in FFI and should be Sync for static use
unsafe impl Sync for OptionArray {}

/// Check result codes
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum CheckCode {
    Unknown = 0,
    Safe = 1,
    Detected = 2,
    Appears = 3,
    Vulnerable = 4,
    Unsupported = 5,
}

/// Module registration info
#[repr(C)]
pub struct ModuleInfo {
    pub api_version: u32,
    pub metadata: ModuleMetadata,
    pub options: OptionArray,
}

// SAFETY: ModuleInfo is used in FFI and should be Sync for static use
unsafe impl Sync for ModuleInfo {}

/// Module vtable - function pointers for module operations
#[repr(C)]
pub struct ModuleVTable {
    /// Get module info
    pub get_info: extern "C" fn() -> *const ModuleInfo,

    /// Initialize module instance
    pub init: extern "C" fn() -> *mut c_void,

    /// Destroy module instance
    pub destroy: extern "C" fn(*mut c_void),

    /// Check if target is vulnerable (for exploits)
    pub check: Option<extern "C" fn(*mut c_void, *const c_char) -> CheckCode>,

    /// Run the module
    pub run: extern "C" fn(*mut c_void, *const c_char) -> c_int,
}

// Re-export c_void for modules to use
pub use std::ffi::c_void;

// Session channel for module-framework communication
pub mod session_channel;

/// Macro to implement module registration
#[macro_export]
macro_rules! register_module {
    ($info:expr, $vtable:expr) => {
        #[no_mangle]
        pub extern "C" fn amatsumara_module_init() -> *const $crate::ModuleVTable {
            &$vtable as *const $crate::ModuleVTable
        }
    };
}
