///! Session management system
///!
///! Manages active sessions (shells, meterpreter, etc.) from successful exploits

use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// Session ID type
pub type SessionId = u32;

/// Types of sessions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionType {
    Shell,
    Meterpreter,
    Bind,
    Reverse,
}

/// Session information
#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub id: SessionId,
    pub session_type: SessionType,
    pub remote_host: String,
    pub remote_port: u16,
    pub local_port: Option<u16>,
    pub description: String,
    pub opened_at: std::time::SystemTime,
}

/// Active session with I/O capabilities
pub struct Session {
    pub info: SessionInfo,
    tx: mpsc::UnboundedSender<String>,
    output_buffer: Arc<Mutex<Vec<String>>>,
}

impl Session {
    /// Create a new session from a TCP connection
    pub async fn from_tcp(
        id: SessionId,
        session_type: SessionType,
        stream: TcpStream,
        description: String,
    ) -> Result<Self> {
        let peer_addr = stream.peer_addr()?;
        let remote_host = peer_addr.ip().to_string();
        let remote_port = peer_addr.port();

        let (tx, mut rx) = mpsc::unbounded_channel::<String>();
        let output_buffer = Arc::new(Mutex::new(Vec::new()));
        let output_buffer_clone = output_buffer.clone();

        // Split the stream for reading and writing
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);

        // Spawn task to handle incoming data
        let reader_buffer = output_buffer.clone();
        tokio::spawn(async move {
            let mut line = String::new();
            loop {
                match reader.read_line(&mut line).await {
                    Ok(0) => break, // EOF
                    Ok(_) => {
                        let output = line.trim_end().to_string();
                        if !output.is_empty() {
                            reader_buffer.lock().unwrap().push(output);
                        }
                        line.clear();
                    }
                    Err(_) => break,
                }
            }
        });

        // Spawn task to handle outgoing commands
        tokio::spawn(async move {
            while let Some(command) = rx.recv().await {
                let cmd_with_newline = format!("{}\n", command);
                if writer.write_all(cmd_with_newline.as_bytes()).await.is_err() {
                    break;
                }
                if writer.flush().await.is_err() {
                    break;
                }
            }
        });

        let info = SessionInfo {
            id,
            session_type,
            remote_host,
            remote_port,
            local_port: None,
            description,
            opened_at: std::time::SystemTime::now(),
        };

        Ok(Self {
            info,
            tx,
            output_buffer: output_buffer_clone,
        })
    }

    /// Send a command to the session
    pub fn send_command(&self, command: impl Into<String>) -> Result<()> {
        self.tx
            .send(command.into())
            .map_err(|e| anyhow!("Failed to send command: {}", e))
    }

    /// Read all available output from the session
    pub fn read_output(&self) -> Vec<String> {
        let mut buffer = self.output_buffer.lock().unwrap();
        let output = buffer.clone();
        buffer.clear();
        output
    }

    /// Check if session has new output
    pub fn has_output(&self) -> bool {
        !self.output_buffer.lock().unwrap().is_empty()
    }
}

/// Session manager - tracks all active sessions
pub struct SessionManager {
    sessions: Arc<Mutex<HashMap<SessionId, Arc<Mutex<Session>>>>>,
    next_id: Arc<Mutex<SessionId>>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            next_id: Arc::new(Mutex::new(1)),
        }
    }

    /// Register a new session
    pub fn register(&self, session: Session) -> SessionId {
        let id = session.info.id;
        self.sessions
            .lock()
            .unwrap()
            .insert(id, Arc::new(Mutex::new(session)));
        id
    }

    /// Get the next available session ID
    pub fn next_id(&self) -> SessionId {
        let mut next = self.next_id.lock().unwrap();
        let id = *next;
        *next += 1;
        id
    }

    /// Get a session by ID
    pub fn get(&self, id: SessionId) -> Option<Arc<Mutex<Session>>> {
        self.sessions.lock().unwrap().get(&id).cloned()
    }

    /// List all active sessions
    pub fn list(&self) -> Vec<SessionInfo> {
        self.sessions
            .lock()
            .unwrap()
            .values()
            .map(|s| s.lock().unwrap().info.clone())
            .collect()
    }

    /// Remove a session
    pub fn remove(&self, id: SessionId) -> Option<Arc<Mutex<Session>>> {
        self.sessions.lock().unwrap().remove(&id)
    }

    /// Get count of active sessions
    pub fn count(&self) -> usize {
        self.sessions.lock().unwrap().len()
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_manager() {
        let manager = SessionManager::new();
        assert_eq!(manager.count(), 0);

        let id1 = manager.next_id();
        let id2 = manager.next_id();
        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
    }
}
