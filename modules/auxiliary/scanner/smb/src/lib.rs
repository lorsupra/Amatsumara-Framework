use amatsumara_api::*;
use std::ffi::{c_char, c_int, c_void, CStr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

// Static metadata
static NAME: &str = "SMB Version Scanner";
static DESCRIPTION: &str = "Detects SMB protocol version and OS information";
static AUTHOR: &str = "Amatsumara Project";

static PLATFORMS: &[Platform] = &[Platform::Linux, Platform::Windows, Platform::MacOS];
static ARCHS: &[Arch] = &[Arch::X64, Arch::X86, Arch::ARM64];

// Option definitions
static RHOSTS_NAME: &str = "RHOSTS";
static RHOSTS_DESC: &str = "Target host(s) to scan";
static RHOSTS_DEFAULT: &str = "";

static RPORT_NAME: &str = "RPORT";
static RPORT_DESC: &str = "Target SMB port";
static RPORT_DEFAULT: &str = "445";

static TIMEOUT_NAME: &str = "TIMEOUT";
static TIMEOUT_DESC: &str = "Connection timeout in seconds";
static TIMEOUT_DEFAULT: &str = "5";

static OPTIONS: &[ModuleOption] = &[
    ModuleOption {
        name: CString { ptr: RHOSTS_NAME.as_ptr() as *const c_char, len: RHOSTS_NAME.len() },
        description: CString { ptr: RHOSTS_DESC.as_ptr() as *const c_char, len: RHOSTS_DESC.len() },
        required: true,
        option_type: OptionType::Address,
        default_value: CString { ptr: RHOSTS_DEFAULT.as_ptr() as *const c_char, len: RHOSTS_DEFAULT.len() },
    },
    ModuleOption {
        name: CString { ptr: RPORT_NAME.as_ptr() as *const c_char, len: RPORT_NAME.len() },
        description: CString { ptr: RPORT_DESC.as_ptr() as *const c_char, len: RPORT_DESC.len() },
        required: false,
        option_type: OptionType::Port,
        default_value: CString { ptr: RPORT_DEFAULT.as_ptr() as *const c_char, len: RPORT_DEFAULT.len() },
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
    rport: u16,
    timeout: u64,
}

impl ScannerModule {
    fn new() -> Box<Self> {
        Box::new(Self {
            rhost: String::new(),
            rport: 445,
            timeout: 5,
        })
    }

    async fn probe_smb(&self) -> Result<String, String> {
        let addr = format!("{}:{}", self.rhost, self.rport);

        let stream = tokio::time::timeout(
            Duration::from_secs(self.timeout),
            TcpStream::connect(&addr)
        )
        .await
        .map_err(|_| "Connection timeout".to_string())?
        .map_err(|e| format!("Connection failed: {}", e))?;

        // SMB Negotiate Protocol Request (simplified)
        let negotiate = vec![
            0x00, 0x00, 0x00, 0x85,  // NetBIOS Session Service
            0xff, 0x53, 0x4d, 0x42,  // SMB magic "\xffSMB"
            0x72,                      // Negotiate Protocol
            0x00, 0x00, 0x00, 0x00,    // Status
            0x18,                       // Flags
            0x53, 0xc8,                // Flags2
            0x00, 0x00,                // PID High
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Signature
            0x00, 0x00,                // Reserved
            0x00, 0x00,                // TID
            0xff, 0xfe,                // PID
            0x00, 0x00,                // UID
            0x00, 0x00,                // MID
        ];

        let mut stream = stream;

        if let Err(e) = stream.write_all(&negotiate).await {
            return Err(format!("Write failed: {}", e));
        }

        let mut response = vec![0u8; 1024];
        match tokio::time::timeout(
            Duration::from_secs(self.timeout),
            stream.read(&mut response)
        ).await {
            Ok(Ok(n)) if n > 0 => {
                // Check for SMB response
                if n > 8 && &response[4..8] == b"\xffSMB" {
                    Ok(format!("SMB service detected (response: {} bytes)", n))
                } else if n > 8 && &response[4..8] == b"\xfeSMB" {
                    Ok("SMB2/SMB3 service detected".to_string())
                } else {
                    Ok("Unknown SMB-like service detected".to_string())
                }
            }
            Ok(Ok(_)) => Err("No response received".to_string()),
            Ok(Err(e)) => Err(format!("Read failed: {}", e)),
            Err(_) => Err("Read timeout".to_string()),
        }
    }

    async fn run_scan(&self) -> i32 {
        eprintln!("[*] Starting SMB version scan on {}:{}", self.rhost, self.rport);
        eprintln!();

        match self.probe_smb().await {
            Ok(info) => {
                eprintln!("[+] {}: {}", self.rhost, info);
                0
            }
            Err(e) => {
                eprintln!("[-] {}: {}", self.rhost, e);
                -1
            }
        }
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
            for line in json_str.split(',') {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() == 2 {
                    let key = parts[0].trim().trim_matches(|c| c == '{' || c == '"' || c == '}');
                    let value = parts[1].trim().trim_matches(|c| c == '"' || c == '}');

                    match key {
                        "RHOSTS" => module.rhost = value.to_string(),
                        "RPORT" => {
                            if let Ok(port) = value.parse::<u16>() {
                                module.rport = port;
                            }
                        }
                        "TIMEOUT" => {
                            if let Ok(timeout) = value.parse::<u64>() {
                                module.timeout = timeout;
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
