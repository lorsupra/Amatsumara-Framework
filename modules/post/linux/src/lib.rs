///! Linux System Enumeration Post-Exploitation Module

use amatsumara_api::*;
use std::os::raw::{c_char, c_int, c_void};
use serde::Deserialize;
use std::ffi::CStr;
use std::process::Command;
use std::fs;

static NAME: &str = "Linux System Enumeration";
static DESCRIPTION: &str = "Gather system information, users, and network config";
static AUTHOR: &str = "Amatsumara Project";
static PLATFORMS: &[Platform] = &[Platform::Linux];
static ARCHS: &[Arch] = &[Arch::X64, Arch::X86, Arch::ARM, Arch::MIPS];

static SESSION_NAME: &str = "SESSION";
static SESSION_DESC: &str = "Session ID to run on";
static SESSION_DEFAULT: &str = "1";

static OPTIONS: &[ModuleOption] = &[
    ModuleOption {
        name: CString { ptr: SESSION_NAME.as_ptr() as *const c_char, len: SESSION_NAME.len() },
        description: CString { ptr: SESSION_DESC.as_ptr() as *const c_char, len: SESSION_DESC.len() },
        required: false,
        option_type: OptionType::String,
        default_value: CString { ptr: SESSION_DEFAULT.as_ptr() as *const c_char, len: SESSION_DEFAULT.len() },
    },
];

static MODULE_INFO: ModuleInfo = ModuleInfo {
    api_version: MODULE_API_VERSION,
    metadata: ModuleMetadata {
        name: CString { ptr: NAME.as_ptr() as *const c_char, len: NAME.len() },
        description: CString { ptr: DESCRIPTION.as_ptr() as *const c_char, len: DESCRIPTION.len() },
        author: CString { ptr: AUTHOR.as_ptr() as *const c_char, len: AUTHOR.len() },
        module_type: ModuleType::Post,
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
struct PostOptions {
    #[serde(rename = "SESSION")]
    session: Option<String>,
}

extern "C" fn get_info() -> *const ModuleInfo { &MODULE_INFO }
extern "C" fn init() -> *mut c_void { Box::into_raw(Box::new(ModuleInstance { _dummy: 0 })) as *mut c_void }
extern "C" fn destroy(instance: *mut c_void) { if !instance.is_null() { unsafe { let _ = Box::from_raw(instance as *mut ModuleInstance); } } }

extern "C" fn run(_instance: *mut c_void, config: *const c_char) -> c_int {
    let _options: PostOptions = match parse_options(config) {
        Ok(opts) => opts,
        Err(e) => { eprintln!("[-] Parse error: {}", e); return 1; }
    };

    println!("[*] Starting Linux system enumeration...\n");

    // System information
    println!("[+] System Information:");
    run_command("uname -a");
    run_command("hostname");
    run_command("cat /etc/os-release");

    // Current user
    println!("\n[+] Current User:");
    run_command("whoami");
    run_command("id");
    run_command("groups");

    // Users and groups
    println!("\n[+] Users:");
    run_command("cat /etc/passwd | cut -d: -f1");
    println!("\n[+] Groups:");
    run_command("cat /etc/group");

    // Network configuration
    println!("\n[+] Network Configuration:");
    run_command("ip addr show");
    run_command("ip route show");
    run_command("cat /etc/resolv.conf");

    // Listening services
    println!("\n[+] Listening Ports:");
    run_command("ss -tulpn");

    // Environment variables
    println!("\n[+] Environment Variables:");
    run_command("env");

    // Scheduled tasks
    println!("\n[+] Cron Jobs:");
    run_command("crontab -l");
    if let Ok(entries) = fs::read_dir("/etc/cron.d") {
        for entry in entries.flatten() {
            println!("  - {:?}", entry.path());
        }
    }

    // SUID binaries
    println!("\n[+] SUID Binaries:");
    run_command("find / -perm -4000 -type f 2>/dev/null");

    // Writable directories
    println!("\n[+] World-Writable Directories:");
    run_command("find / -writable -type d 2>/dev/null | head -20");

    // Loaded kernel modules
    println!("\n[+] Loaded Kernel Modules:");
    run_command("lsmod");

    println!("\n[*] Enumeration complete!");
    0
}

fn run_command(cmd: &str) {
    let output = if cmd.contains("|") || cmd.contains(">") {
        Command::new("sh").arg("-c").arg(cmd).output()
    } else {
        Command::new("sh").arg("-c").arg(cmd).output()
    };

    match output {
        Ok(output) => {
            if !output.stdout.is_empty() {
                println!("{}", String::from_utf8_lossy(&output.stdout));
            }
            if !output.stderr.is_empty() {
                eprintln!("{}", String::from_utf8_lossy(&output.stderr));
            }
        }
        Err(e) => eprintln!("[-] Command failed: {}", e),
    }
}

fn parse_options(config: *const c_char) -> Result<PostOptions, Box<dyn std::error::Error>> {
    if config.is_null() {
        return Ok(PostOptions { session: None });
    }
    Ok(serde_json::from_str(unsafe { CStr::from_ptr(config).to_str()? })?)
}

#[no_mangle]
pub extern "C" fn msf_module_init() -> *const ModuleVTable { &VTABLE }
