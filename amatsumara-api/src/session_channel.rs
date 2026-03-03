///! Session channel for communication between modules and framework
///!
///! This uses file-based IPC to work around static variable duplication
///! issues between .so files and the main executable.

use std::net::TcpStream;
use std::os::raw::{c_char, c_int};
use std::fs;
use std::io::Write;
use serde::{Serialize, Deserialize};

/// Pending session information from a module
pub struct PendingSession {
    pub stream: TcpStream,
    pub remote_host: String,
    pub remote_port: u16,
    pub description: String,
}

/// Session data for file-based IPC
#[derive(Serialize, Deserialize)]
struct SessionFile {
    stream_fd: i32,
    remote_host: String,
    remote_port: u16,
    description: String,
}

/// Session registration callback type (unused but kept for API compatibility)
pub type SessionCallback = extern "C" fn(
    stream_fd: c_int,
    remote_host: *const c_char,
    remote_port: u16,
    description: *const c_char,
) -> c_int;

/// Get the session IPC directory
fn get_session_dir() -> std::path::PathBuf {
    std::path::PathBuf::from("/tmp/amatsumara_sessions")
}

/// Initialize the session channel (creates IPC directory)
pub fn init_session_channel() {
    let dir = get_session_dir();
    if !dir.exists() {
        let _ = fs::create_dir_all(&dir);
    }
}

/// Initialize with callback (kept for compatibility, does same as init_session_channel)
pub fn init_session_channel_with_callback(_callback: SessionCallback) {
    init_session_channel();
}

/// Register a session (call from module) - writes to file
pub fn register_session(stream: TcpStream, remote_host: String, remote_port: u16, description: String) {
    use std::os::unix::io::AsRawFd;

    let stream_fd = stream.as_raw_fd();

    // Create session data
    let session_data = SessionFile {
        stream_fd,
        remote_host,
        remote_port,
        description,
    };

    // Write to file in IPC directory
    let dir = get_session_dir();
    let filename = format!("session_{}.json", std::process::id());
    let filepath = dir.join(&filename);

    match serde_json::to_string(&session_data) {
        Ok(json) => {
            match fs::File::create(&filepath) {
                Ok(mut file) => {
                    if file.write_all(json.as_bytes()).is_ok() {
                        eprintln!("[+] Session registered via file: {}", filepath.display());
                        // Don't drop the stream - ownership transferred
                        std::mem::forget(stream);
                    } else {
                        eprintln!("[-] Failed to write session file");
                    }
                }
                Err(e) => {
                    eprintln!("[-] Failed to create session file: {}", e);
                }
            }
        }
        Err(e) => {
            eprintln!("[-] Failed to serialize session data: {}", e);
        }
    }
}

/// Take all pending sessions (reads from files and cleans up)
pub fn take_pending_sessions() -> Vec<PendingSession> {
    use std::os::unix::io::FromRawFd;

    let dir = get_session_dir();
    let mut sessions = Vec::new();

    if !dir.exists() {
        return sessions;
    }

    // Read all session files
    if let Ok(entries) = fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                // Read and parse the file
                if let Ok(contents) = fs::read_to_string(&path) {
                    if let Ok(session_data) = serde_json::from_str::<SessionFile>(&contents) {
                        // Recreate TcpStream from file descriptor
                        let stream = unsafe { TcpStream::from_raw_fd(session_data.stream_fd) };

                        sessions.push(PendingSession {
                            stream,
                            remote_host: session_data.remote_host,
                            remote_port: session_data.remote_port,
                            description: session_data.description,
                        });

                        eprintln!("[+] Loaded session from file: {}", path.display());
                    }
                }

                // Delete the file
                let _ = fs::remove_file(&path);
            }
        }
    }

    sessions
}
