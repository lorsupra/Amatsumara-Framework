///! Session Interaction API for post-exploitation modules
///!
///! Provides a C-compatible function pointer table that the framework injects
///! into modules before calling run(). Modules call these function pointers
///! to execute commands on remote sessions and read output back.
///!
///! The module never owns the API — it stores a raw pointer to framework-owned
///! data for the duration of run(). This avoids static duplication issues
///! between .so files and the main executable.

use std::os::raw::{c_char, c_int};

/// Session ID handle — matches SessionId in amatsumara-core
pub type SessionHandle = u32;

/// Sentinel string appended after each command to detect end of output
pub const SESSION_OUTPUT_SENTINEL: &str = "__AMATSUMARA_DONE__";

/// Result of executing a command on a session
#[repr(C)]
pub struct CommandResult {
    /// Output as a single null-terminated UTF-8 string (newline-separated lines).
    /// Allocated by the framework. Module must call `free_result` when done.
    pub output: *const c_char,
    /// Length of output in bytes (excluding null terminator)
    pub output_len: usize,
    /// 0 = success, nonzero = error
    pub status: c_int,
}

/// Session interaction function table — set by framework before run()
#[repr(C)]
pub struct SessionApi {
    /// Execute a command on the session and wait for output.
    ///
    /// `session_id`: which session to target
    /// `command`: null-terminated command string
    /// `timeout_ms`: max milliseconds to wait for output (0 = default 10s)
    ///
    /// Returns a CommandResult. Caller must call `free_result` when done.
    pub exec_cmd: extern "C" fn(
        session_id: SessionHandle,
        command: *const c_char,
        timeout_ms: u32,
    ) -> CommandResult,

    /// Free a CommandResult's output buffer.
    pub free_result: extern "C" fn(result: *mut CommandResult),

    /// Check if a session is alive.
    /// Returns 1 if alive, 0 if dead or not found.
    pub session_alive: extern "C" fn(session_id: SessionHandle) -> c_int,
}

/// Convenience wrapper for modules to execute a command on a session.
///
/// # Safety
/// `api` must be a valid pointer to a `SessionApi` that the framework
/// injected via `amatsumara_set_session_api`. Only call this during `run()`.
pub unsafe fn session_exec(
    api: *const SessionApi,
    session_id: u32,
    command: &str,
    timeout_ms: u32,
) -> Result<String, &'static str> {
    if api.is_null() {
        return Err("Session API not initialized");
    }

    let api_ref = &*api;

    let cmd_cstr = match std::ffi::CString::new(command) {
        Ok(c) => c,
        Err(_) => return Err("Command contains null byte"),
    };

    let mut result = (api_ref.exec_cmd)(session_id, cmd_cstr.as_ptr(), timeout_ms);

    if result.status != 0 {
        (api_ref.free_result)(&mut result as *mut CommandResult);
        return Err("Command execution failed");
    }

    let output = if result.output.is_null() || result.output_len == 0 {
        String::new()
    } else {
        let slice = std::slice::from_raw_parts(result.output as *const u8, result.output_len);
        String::from_utf8_lossy(slice).to_string()
    };

    (api_ref.free_result)(&mut result as *mut CommandResult);
    Ok(output)
}

/// Convenience wrapper to check if a session is alive.
///
/// # Safety
/// Same requirements as `session_exec`.
pub unsafe fn session_is_alive(api: *const SessionApi, session_id: u32) -> bool {
    if api.is_null() {
        return false;
    }
    ((*api).session_alive)(session_id) == 1
}

/// Macro to generate the `amatsumara_set_session_api` export and an AtomicPtr
/// storage for post-exploitation modules.
///
/// Usage: `register_post_module!(INFO, VTABLE);`
///
/// This generates:
/// - `amatsumara_module_init()` (same as `register_module!`)
/// - `amatsumara_set_session_api()` export
/// - `SESSION_API` AtomicPtr accessible via `get_session_api()`
#[macro_export]
macro_rules! register_post_module {
    ($info:expr, $vtable:expr) => {
        static SESSION_API: std::sync::atomic::AtomicPtr<$crate::session_api::SessionApi> =
            std::sync::atomic::AtomicPtr::new(std::ptr::null_mut());

        #[no_mangle]
        pub extern "C" fn amatsumara_module_init() -> *const $crate::ModuleVTable {
            &$vtable as *const $crate::ModuleVTable
        }

        #[no_mangle]
        pub extern "C" fn amatsumara_set_session_api(
            api: *const $crate::session_api::SessionApi,
        ) {
            SESSION_API.store(
                api as *mut $crate::session_api::SessionApi,
                std::sync::atomic::Ordering::Release,
            );
        }

        /// Get the session API pointer. Returns null if not injected.
        #[allow(dead_code)]
        fn get_session_api() -> *const $crate::session_api::SessionApi {
            SESSION_API.load(std::sync::atomic::Ordering::Acquire)
        }
    };
}
