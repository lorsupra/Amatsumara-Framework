use amatsumara_api::*;
use std::ffi::{c_char, c_int, c_void, CStr};

// Static metadata
static NAME: &str = "HTTP Directory Scanner";
static DESCRIPTION: &str = "Scans web servers for common directories and files";
static AUTHOR: &str = "Amatsumara Project";

static PLATFORMS: &[Platform] = &[Platform::Linux, Platform::Windows, Platform::MacOS];
static ARCHS: &[Arch] = &[Arch::X64, Arch::X86, Arch::ARM64];

// Option definitions
static RHOSTS_NAME: &str = "RHOSTS";
static RHOSTS_DESC: &str = "Target host(s) to scan";
static RHOSTS_DEFAULT: &str = "";

static RPORT_NAME: &str = "RPORT";
static RPORT_DESC: &str = "Target port";
static RPORT_DEFAULT: &str = "80";

static SSL_NAME: &str = "SSL";
static SSL_DESC: &str = "Use HTTPS instead of HTTP";
static SSL_DEFAULT: &str = "false";

static VHOST_NAME: &str = "VHOST";
static VHOST_DESC: &str = "Virtual host header";
static VHOST_DEFAULT: &str = "";

static THREADS_NAME: &str = "THREADS";
static THREADS_DESC: &str = "Number of concurrent threads";
static THREADS_DEFAULT: &str = "10";

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
        name: CString { ptr: SSL_NAME.as_ptr() as *const c_char, len: SSL_NAME.len() },
        description: CString { ptr: SSL_DESC.as_ptr() as *const c_char, len: SSL_DESC.len() },
        required: false,
        option_type: OptionType::Bool,
        default_value: CString { ptr: SSL_DEFAULT.as_ptr() as *const c_char, len: SSL_DEFAULT.len() },
    },
    ModuleOption {
        name: CString { ptr: VHOST_NAME.as_ptr() as *const c_char, len: VHOST_NAME.len() },
        description: CString { ptr: VHOST_DESC.as_ptr() as *const c_char, len: VHOST_DESC.len() },
        required: false,
        option_type: OptionType::String,
        default_value: CString { ptr: VHOST_DEFAULT.as_ptr() as *const c_char, len: VHOST_DEFAULT.len() },
    },
    ModuleOption {
        name: CString { ptr: THREADS_NAME.as_ptr() as *const c_char, len: THREADS_NAME.len() },
        description: CString { ptr: THREADS_DESC.as_ptr() as *const c_char, len: THREADS_DESC.len() },
        required: false,
        option_type: OptionType::Int,
        default_value: CString { ptr: THREADS_DEFAULT.as_ptr() as *const c_char, len: THREADS_DEFAULT.len() },
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
    ssl: bool,
    vhost: String,
    threads: usize,
}

impl ScannerModule {
    fn new() -> Box<Self> {
        Box::new(Self {
            rhost: String::new(),
            rport: 80,
            ssl: false,
            vhost: String::new(),
            threads: 10,
        })
    }

    fn get_common_paths() -> Vec<&'static str> {
        vec![
            "/admin",
            "/admin/",
            "/administrator",
            "/login",
            "/login.php",
            "/wp-admin",
            "/wp-login.php",
            "/phpmyadmin",
            "/phpMyAdmin",
            "/cpanel",
            "/cgi-bin",
            "/backup",
            "/backups",
            "/db",
            "/database",
            "/sql",
            "/mysql",
            "/config",
            "/conf",
            "/api",
            "/uploads",
            "/upload",
            "/images",
            "/img",
            "/files",
            "/docs",
            "/test",
            "/testing",
            "/dev",
            "/debug",
            "/.git",
            "/.svn",
            "/.env",
            "/robots.txt",
            "/sitemap.xml",
            "/.well-known",
            "/console",
            "/manager",
            "/status",
            "/server-status",
        ]
    }

    fn scan_path(&self, path: &str) -> Option<(String, u16)> {
        let scheme = if self.ssl { "https" } else { "http" };
        let url = format!("{}://{}:{}{}", scheme, self.rhost, self.rport, path);

        let client = reqwest::blocking::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .ok()?;

        let mut req = client.get(&url);

        if !self.vhost.is_empty() {
            req = req.header("Host", &self.vhost);
        }

        match req.send() {
            Ok(response) => {
                let status = response.status().as_u16();
                if status != 404 {
                    Some((url, status))
                }
                else {
                    None
                }
            }
            Err(_) => None,
        }
    }

    fn run_scan(&self) -> i32 {
        let scheme = if self.ssl { "https" } else { "http" };
        eprintln!("[*] Starting HTTP directory scan on {}://{}:{}", scheme, self.rhost, self.rport);
        if !self.vhost.is_empty() {
            eprintln!("[*] Using virtual host: {}", self.vhost);
        }
        eprintln!();

        let paths = Self::get_common_paths();
        eprintln!("[*] Scanning {} common paths...", paths.len());
        eprintln!();

        let mut found = Vec::new();

        for path in paths {
            if let Some((url, status)) = self.scan_path(path) {
                found.push((url.clone(), status));
                eprintln!("[+] {} [{}]", url, status);
            }
        }

        eprintln!();
        if found.is_empty() {
            eprintln!("[-] No interesting paths found");
        } else {
            eprintln!("[+] Found {} interesting path(s)", found.len());
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
            if let Ok(opts) = serde_json::from_str::<serde_json::Value>(json_str) {
                if let Some(v) = opts.get("RHOSTS").and_then(|v| v.as_str()) {
                    module.rhost = v.to_string();
                }
                if let Some(v) = opts.get("RPORT").and_then(|v| v.as_str()) {
                    if let Ok(p) = v.parse::<u16>() { module.rport = p; }
                }
                if let Some(v) = opts.get("SSL").and_then(|v| v.as_str()) {
                    module.ssl = v.eq_ignore_ascii_case("true");
                }
                if let Some(v) = opts.get("VHOST").and_then(|v| v.as_str()) {
                    module.vhost = v.to_string();
                }
                if let Some(v) = opts.get("THREADS").and_then(|v| v.as_str()) {
                    if let Ok(t) = v.parse::<usize>() { module.threads = t; }
                }
            }
        }
    }

    if module.rhost.is_empty() {
        eprintln!("[-] RHOSTS not set");
        return -1;
    }

    module.run_scan()
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
