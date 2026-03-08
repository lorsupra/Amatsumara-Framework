///! SSH Login - Auxiliary module
///!
///! Authenticates to a target via SSH using password or key-based credentials,
///! opens an interactive shell channel, and registers it as a framework session.
///! The session is bridged through a local TCP socketpair so it integrates with
///! SessionManager identically to a reverse shell session.

use amatsumara_api::*;
use amatsumara_api::session_channel::{init_session_channel, register_session};
use std::ffi::{c_char, c_int, c_void, CStr};
use std::io::{Read as IoRead, Write as IoWrite};
use std::net::{TcpListener, TcpStream, SocketAddr};
use std::time::Duration;

// --- Static metadata ---

static NAME: &str = "SSH Login";
static DESCRIPTION: &str =
    "Authenticate to a target via SSH and register an interactive session for post-exploitation";
static AUTHOR: &str = "Amatsumara Project";

static PLATFORMS: &[Platform] = &[Platform::Linux, Platform::Windows, Platform::MacOS];
static ARCHS: &[Arch] = &[Arch::X64, Arch::X86, Arch::ARM64];

// --- Option definitions ---

static RHOSTS_NAME: &str = "RHOSTS";
static RHOSTS_DESC: &str = "Target IP";
static RHOSTS_DEFAULT: &str = "";

static PORT_NAME: &str = "PORT";
static PORT_DESC: &str = "SSH port";
static PORT_DEFAULT: &str = "22";

static USERNAME_NAME: &str = "USERNAME";
static USERNAME_DESC: &str = "SSH username";
static USERNAME_DEFAULT: &str = "";

static PASSWORD_NAME: &str = "PASSWORD";
static PASSWORD_DESC: &str = "SSH password (mutually exclusive with KEYFILE)";
static PASSWORD_DEFAULT: &str = "";

static KEYFILE_NAME: &str = "KEYFILE";
static KEYFILE_DESC: &str = "Path to private key file";
static KEYFILE_DEFAULT: &str = "";

static TIMEOUT_NAME: &str = "TIMEOUT";
static TIMEOUT_DESC: &str = "Connection timeout in seconds";
static TIMEOUT_DEFAULT: &str = "10";

static OPTIONS: &[ModuleOption] = &[
    ModuleOption {
        name: CString { ptr: RHOSTS_NAME.as_ptr() as *const c_char, len: RHOSTS_NAME.len() },
        description: CString { ptr: RHOSTS_DESC.as_ptr() as *const c_char, len: RHOSTS_DESC.len() },
        required: true,
        option_type: OptionType::Address,
        default_value: CString { ptr: RHOSTS_DEFAULT.as_ptr() as *const c_char, len: RHOSTS_DEFAULT.len() },
    },
    ModuleOption {
        name: CString { ptr: PORT_NAME.as_ptr() as *const c_char, len: PORT_NAME.len() },
        description: CString { ptr: PORT_DESC.as_ptr() as *const c_char, len: PORT_DESC.len() },
        required: false,
        option_type: OptionType::Port,
        default_value: CString { ptr: PORT_DEFAULT.as_ptr() as *const c_char, len: PORT_DEFAULT.len() },
    },
    ModuleOption {
        name: CString { ptr: USERNAME_NAME.as_ptr() as *const c_char, len: USERNAME_NAME.len() },
        description: CString { ptr: USERNAME_DESC.as_ptr() as *const c_char, len: USERNAME_DESC.len() },
        required: true,
        option_type: OptionType::String,
        default_value: CString { ptr: USERNAME_DEFAULT.as_ptr() as *const c_char, len: USERNAME_DEFAULT.len() },
    },
    ModuleOption {
        name: CString { ptr: PASSWORD_NAME.as_ptr() as *const c_char, len: PASSWORD_NAME.len() },
        description: CString { ptr: PASSWORD_DESC.as_ptr() as *const c_char, len: PASSWORD_DESC.len() },
        required: false,
        option_type: OptionType::String,
        default_value: CString { ptr: PASSWORD_DEFAULT.as_ptr() as *const c_char, len: PASSWORD_DEFAULT.len() },
    },
    ModuleOption {
        name: CString { ptr: KEYFILE_NAME.as_ptr() as *const c_char, len: KEYFILE_NAME.len() },
        description: CString { ptr: KEYFILE_DESC.as_ptr() as *const c_char, len: KEYFILE_DESC.len() },
        required: false,
        option_type: OptionType::String,
        default_value: CString { ptr: KEYFILE_DEFAULT.as_ptr() as *const c_char, len: KEYFILE_DEFAULT.len() },
    },
    ModuleOption {
        name: CString { ptr: TIMEOUT_NAME.as_ptr() as *const c_char, len: TIMEOUT_NAME.len() },
        description: CString { ptr: TIMEOUT_DESC.as_ptr() as *const c_char, len: TIMEOUT_DESC.len() },
        required: false,
        option_type: OptionType::Int,
        default_value: CString { ptr: TIMEOUT_DEFAULT.as_ptr() as *const c_char, len: TIMEOUT_DEFAULT.len() },
    },
];

static MODULE_INFO: ModuleInfo = ModuleInfo {
    api_version: MODULE_API_VERSION,
    metadata: ModuleMetadata {
        name: CString { ptr: NAME.as_ptr() as *const c_char, len: NAME.len() },
        description: CString { ptr: DESCRIPTION.as_ptr() as *const c_char, len: DESCRIPTION.len() },
        author: CString { ptr: AUTHOR.as_ptr() as *const c_char, len: AUTHOR.len() },
        module_type: ModuleType::Auxiliary,
        platforms: PlatformArray { ptr: PLATFORMS.as_ptr(), len: PLATFORMS.len() },
        archs: ArchArray { ptr: ARCHS.as_ptr(), len: ARCHS.len() },
        ranking: Ranking::Normal,
        privileged: false,
    },
    options: OptionArray { ptr: OPTIONS.as_ptr(), len: OPTIONS.len() },
};

// --- Module state ---

struct SshLoginModule {
    rhosts: String,
    port: u16,
    username: String,
    password: String,
    keyfile: String,
    timeout: u64,
}

impl SshLoginModule {
    fn new() -> Box<Self> {
        Box::new(Self {
            rhosts: String::new(),
            port: 22,
            username: String::new(),
            password: String::new(),
            keyfile: String::new(),
            timeout: 10,
        })
    }
}

fn parse_options(module: &mut SshLoginModule, options_json: *const c_char) {
    if options_json.is_null() {
        return;
    }
    let c_str = unsafe { CStr::from_ptr(options_json) };
    let json_str = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return,
    };
    let opts: serde_json::Value = match serde_json::from_str(json_str) {
        Ok(v) => v,
        Err(_) => return,
    };

    if let Some(v) = opts.get("RHOSTS").and_then(|v| v.as_str()) {
        module.rhosts = v.to_string();
    }
    if let Some(v) = opts.get("PORT").and_then(|v| v.as_str()) {
        if let Ok(p) = v.parse::<u16>() {
            module.port = p;
        }
    }
    if let Some(v) = opts.get("USERNAME").and_then(|v| v.as_str()) {
        module.username = v.to_string();
    }
    if let Some(v) = opts.get("PASSWORD").and_then(|v| v.as_str()) {
        module.password = v.to_string();
    }
    if let Some(v) = opts.get("KEYFILE").and_then(|v| v.as_str()) {
        module.keyfile = v.to_string();
    }
    if let Some(v) = opts.get("TIMEOUT").and_then(|v| v.as_str()) {
        if let Ok(t) = v.parse::<u64>() {
            module.timeout = t;
        }
    }
}

// --- SSH bridge ---
//
// The bridge thread owns the SSH session and channel (avoiding lifetime/Send
// issues), and shuttles bytes between the SSH channel and a local TCP socket.
// The other end of that socket is registered with the framework as a session,
// so SessionManager reads/writes it exactly like a reverse shell stream.

fn ssh_bridge_thread(
    tx: std::sync::mpsc::Sender<Result<(), String>>,
    mut client_stream: TcpStream,
    host: String,
    port: u16,
    username: String,
    password: String,
    keyfile: String,
    timeout: u64,
) {
    macro_rules! fail {
        ($($arg:tt)*) => {{
            let _ = tx.send(Err(format!($($arg)*)));
            return;
        }};
    }

    let addr: SocketAddr = match format!("{}:{}", host, port).parse() {
        Ok(a) => a,
        Err(e) => fail!("Invalid address {}:{} - {}", host, port, e),
    };

    let tcp = match TcpStream::connect_timeout(&addr, Duration::from_secs(timeout)) {
        Ok(t) => t,
        Err(e) => fail!("Connection to {}:{} failed: {}", host, port, e),
    };

    let mut sess = match ssh2::Session::new() {
        Ok(s) => s,
        Err(e) => fail!("SSH session init failed: {}", e),
    };
    sess.set_tcp_stream(tcp);

    if let Err(e) = sess.handshake() {
        fail!("SSH handshake failed: {}", e);
    }

    // Authenticate
    if !keyfile.is_empty() {
        if let Err(e) = sess.userauth_pubkey_file(
            &username,
            None,
            std::path::Path::new(&keyfile),
            None,
        ) {
            fail!("Public key authentication failed: {}", e);
        }
    } else if !password.is_empty() {
        if let Err(e) = sess.userauth_password(&username, &password) {
            fail!("Password authentication failed: {}", e);
        }
    } else {
        fail!("No PASSWORD or KEYFILE provided");
    }

    if !sess.authenticated() {
        fail!("Authentication failed for user '{}'", username);
    }

    let mut channel = match sess.channel_session() {
        Ok(c) => c,
        Err(e) => fail!("Failed to open SSH channel: {}", e),
    };

    // Merge stderr into stdout so the framework sees all output on one stream
    if let Err(e) = channel.handle_extended_data(ssh2::ExtendedData::Merge) {
        fail!("Failed to configure extended data: {}", e);
    }

    if let Err(e) = channel.shell() {
        fail!("Failed to start shell: {}", e);
    }

    // Signal success to main thread
    let _ = tx.send(Ok(()));

    // Enter bidirectional bridge loop (non-blocking)
    sess.set_blocking(false);
    if client_stream.set_nonblocking(true).is_err() {
        return;
    }

    let mut buf = [0u8; 4096];
    loop {
        let mut activity = false;

        // SSH channel -> local socket (remote output -> framework)
        match channel.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if client_stream.write_all(&buf[..n]).is_err() {
                    break;
                }
                activity = true;
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => break,
        }

        if channel.eof() {
            break;
        }

        // Local socket -> SSH channel (framework commands -> remote)
        match client_stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if channel.write_all(&buf[..n]).is_err() {
                    break;
                }
                let _ = channel.flush();
                activity = true;
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => break,
        }

        if !activity {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

// --- FFI entry points ---

extern "C" fn get_info() -> *const ModuleInfo {
    &MODULE_INFO
}

extern "C" fn init() -> *mut c_void {
    let module = SshLoginModule::new();
    Box::into_raw(module) as *mut c_void
}

extern "C" fn destroy(instance: *mut c_void) {
    if !instance.is_null() {
        unsafe {
            let _ = Box::from_raw(instance as *mut SshLoginModule);
        }
    }
}

extern "C" fn run(instance: *mut c_void, options_json: *const c_char) -> c_int {
    if instance.is_null() {
        eprintln!("[-] Module instance is null");
        return -1;
    }
    let module = unsafe { &mut *(instance as *mut SshLoginModule) };
    parse_options(module, options_json);

    if module.rhosts.is_empty() {
        eprintln!("[-] RHOSTS not set");
        return -1;
    }
    if module.username.is_empty() {
        eprintln!("[-] USERNAME not set");
        return -1;
    }
    if module.password.is_empty() && module.keyfile.is_empty() {
        eprintln!("[-] Either PASSWORD or KEYFILE must be set");
        return -1;
    }
    if !module.password.is_empty() && !module.keyfile.is_empty() {
        eprintln!("[-] PASSWORD and KEYFILE are mutually exclusive, set only one");
        return -1;
    }

    init_session_channel();

    let auth_method = if !module.keyfile.is_empty() { "key" } else { "password" };
    eprintln!(
        "[*] {}:{} - Connecting as '{}' ({} auth)...",
        module.rhosts, module.port, module.username, auth_method
    );

    // Create a local TCP loopback pair. One end (server_stream) is registered
    // with the framework as a session; the other (client_stream) is bridged
    // to the SSH channel by a background thread.
    let listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[-] Failed to create bridge listener: {}", e);
            return -1;
        }
    };
    let local_addr = listener.local_addr().unwrap();
    let client_stream = match TcpStream::connect(local_addr) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[-] Failed to create bridge socket: {}", e);
            return -1;
        }
    };
    let (server_stream, _) = match listener.accept() {
        Ok(pair) => pair,
        Err(e) => {
            eprintln!("[-] Failed to accept bridge connection: {}", e);
            return -1;
        }
    };
    drop(listener);

    // Spawn bridge thread (owns SSH session + channel + client socket)
    let (tx, rx) = std::sync::mpsc::channel();
    let host = module.rhosts.clone();
    let port = module.port;
    let username = module.username.clone();
    let password = module.password.clone();
    let keyfile = module.keyfile.clone();
    let timeout = module.timeout;

    std::thread::spawn(move || {
        ssh_bridge_thread(tx, client_stream, host, port, username, password, keyfile, timeout);
    });

    // Wait for SSH connection result
    let wait_timeout = Duration::from_secs(module.timeout + 5);
    match rx.recv_timeout(wait_timeout) {
        Ok(Ok(())) => {
            let description = format!(
                "SSH {}@{}:{}",
                module.username, module.rhosts, module.port
            );
            register_session(server_stream, module.rhosts.clone(), module.port, description);
            eprintln!("[+] SSH session opened ({}:{})", module.rhosts, module.port);
            0
        }
        Ok(Err(e)) => {
            eprintln!("[-] {}", e);
            -1
        }
        Err(_) => {
            eprintln!("[-] SSH connection timed out");
            -1
        }
    }
}

// --- VTable and registration ---

static VTABLE: ModuleVTable = ModuleVTable {
    get_info,
    init,
    destroy,
    check: None,
    run,
};

#[no_mangle]
pub extern "C" fn amatsumara_module_init() -> *const ModuleVTable {
    &VTABLE
}
