use amatsumara_api::*;
use std::ffi::{c_char, c_int, c_void, CStr};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

// Static metadata
static NAME: &str = "TCP Port Scanner";
static DESCRIPTION: &str = "Scans TCP ports on a target host to identify open services";
static AUTHOR: &str = "Amatsumara Project";

static PLATFORMS: &[Platform] = &[Platform::Linux, Platform::Windows, Platform::MacOS];
static ARCHS: &[Arch] = &[Arch::X64, Arch::X86, Arch::ARM64];

// Option definitions
static RHOSTS_NAME: &str = "RHOSTS";
static RHOSTS_DESC: &str = "Target host(s) to scan";
static RHOSTS_DEFAULT: &str = "";

static PORTS_NAME: &str = "PORTS";
static PORTS_DESC: &str = "Ports to scan (e.g. 1-1000, 22,80,443)";
static PORTS_DEFAULT: &str = "1-1000";

static TIMEOUT_NAME: &str = "TIMEOUT";
static TIMEOUT_DESC: &str = "Connection timeout in milliseconds";
static TIMEOUT_DEFAULT: &str = "1000";

static OPTIONS: &[ModuleOption] = &[
    ModuleOption {
        name: CString { ptr: RHOSTS_NAME.as_ptr() as *const c_char, len: RHOSTS_NAME.len() },
        description: CString { ptr: RHOSTS_DESC.as_ptr() as *const c_char, len: RHOSTS_DESC.len() },
        required: true,
        option_type: OptionType::String,
        default_value: CString { ptr: RHOSTS_DEFAULT.as_ptr() as *const c_char, len: RHOSTS_DEFAULT.len() },
    },
    ModuleOption {
        name: CString { ptr: PORTS_NAME.as_ptr() as *const c_char, len: PORTS_NAME.len() },
        description: CString { ptr: PORTS_DESC.as_ptr() as *const c_char, len: PORTS_DESC.len() },
        required: true,
        option_type: OptionType::String,
        default_value: CString { ptr: PORTS_DEFAULT.as_ptr() as *const c_char, len: PORTS_DEFAULT.len() },
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

struct ScannerModule {
    rhost: String,
    ports: String,
    timeout_ms: u64,
}

impl ScannerModule {
    fn new() -> Box<Self> {
        Box::new(Self {
            rhost: String::new(),
            ports: String::from("1-1000"),
            timeout_ms: 1000,
        })
    }

    fn parse_ports(&self) -> Vec<u16> {
        let mut ports = Vec::new();

        for part in self.ports.split(',') {
            let part = part.trim();
            if part.contains('-') {
                // Range like "1-1000"
                let range: Vec<&str> = part.split('-').collect();
                if range.len() == 2 {
                    if let (Ok(start), Ok(end)) = (range[0].parse::<u16>(), range[1].parse::<u16>()) {
                        for port in start..=end {
                            ports.push(port);
                        }
                    }
                }
            } else {
                // Single port
                if let Ok(port) = part.parse::<u16>() {
                    ports.push(port);
                }
            }
        }

        ports
    }

    async fn scan_port(&self, host: &str, port: u16) -> bool {
        let addr = format!("{}:{}", host, port);
        if let Ok(sock_addr) = addr.parse::<SocketAddr>() {
            match timeout(
                Duration::from_millis(self.timeout_ms),
                TcpStream::connect(sock_addr)
            ).await {
                Ok(Ok(_)) => true,
                _ => false,
            }
        } else {
            false
        }
    }

    async fn run_scan(&self) -> i32 {
        eprintln!("[*] Starting TCP port scan on {}", self.rhost);
        eprintln!("[*] Ports: {}", self.ports);
        eprintln!("[*] Timeout: {}ms", self.timeout_ms);
        eprintln!();

        let ports = self.parse_ports();
        eprintln!("[*] Scanning {} ports...", ports.len());
        eprintln!();

        let mut open_ports = Vec::new();

        for port in ports {
            if self.scan_port(&self.rhost, port).await {
                open_ports.push(port);
                eprintln!("[+] {}: {}  OPEN", self.rhost, port);
            }
        }

        eprintln!();
        if open_ports.is_empty() {
            eprintln!("[-] No open ports found");
        } else {
            eprintln!("[+] Found {} open port(s): {:?}", open_ports.len(), open_ports);
        }

        0
    }
}

extern "C" fn get_info() -> *const ModuleInfo {
    &MODULE_INFO
}

extern "C" fn init() -> *mut c_void {
    let module = ScannerModule::new();
    Box::into_raw(module) as *mut c_void
}

extern "C" fn destroy(instance: *mut c_void) {
    if !instance.is_null() {
        unsafe {
            let _ = Box::from_raw(instance as *mut ScannerModule);
        }
    }
}

extern "C" fn run(instance: *mut c_void, options_json: *const c_char) -> c_int {
    if instance.is_null() {
        eprintln!("[-] Module instance is null");
        return -1;
    }

    let module = unsafe { &mut *(instance as *mut ScannerModule) };

    // Parse options from JSON
    if !options_json.is_null() {
        let c_str = unsafe { CStr::from_ptr(options_json) };
        if let Ok(json_str) = c_str.to_str() {
            // Simple JSON parsing for RHOSTS, PORTS, TIMEOUT
            for line in json_str.split(',') {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() == 2 {
                    let key = parts[0].trim().trim_matches(|c| c == '{' || c == '"' || c == '}');
                    let value = parts[1].trim().trim_matches(|c| c == '"' || c == '}');

                    match key {
                        "RHOSTS" => module.rhost = value.to_string(),
                        "PORTS" => module.ports = value.to_string(),
                        "TIMEOUT" => {
                            if let Ok(timeout) = value.parse::<u64>() {
                                module.timeout_ms = timeout;
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    if module.rhost.is_empty() {
        eprintln!("[-] RHOSTS not set");
        return -1;
    }

    // Run async scan
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(module.run_scan())
}

static VTABLE: ModuleVTable = ModuleVTable {
    get_info,
    init,
    destroy,
    check: None,
    run,
};

#[no_mangle]
pub extern "C" fn msf_module_init() -> *const ModuleVTable {
    &VTABLE
}
