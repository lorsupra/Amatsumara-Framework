use amatsumara_api::*;
use std::ffi::{c_char, c_int, c_void, CStr};
use std::process::Command;

static NAME: &str = "Linux System Enumeration";
static DESCRIPTION: &str = "Enumerates Linux system information including OS, kernel, users, and network config";
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

    fn run_cmd(&self, cmd: &str) -> String {
        match Command::new("sh").arg("-c").arg(cmd).output() {
            Ok(output) => String::from_utf8_lossy(&output.stdout).to_string(),
            Err(e) => format!("[Error: {}]", e),
        }
    }

    fn enumerate(&self) -> i32 {
        eprintln!("[*] Linux System Enumeration");
        eprintln!();

        eprintln!("[+] OS Information:");
        eprintln!("{}", self.run_cmd("cat /etc/os-release 2>/dev/null || cat /etc/*-release 2>/dev/null | head -5"));

        eprintln!("[+] Kernel:");
        eprintln!("{}", self.run_cmd("uname -a"));

        eprintln!("[+] Current User:");
        eprintln!("{}", self.run_cmd("id"));

        eprintln!("[+] Users:");
        eprintln!("{}", self.run_cmd("cat /etc/passwd | grep -v nologin | grep -v /false | cut -d: -f1,3,6"));

        eprintln!("[+] Network Interfaces:");
        eprintln!("{}", self.run_cmd("ip addr 2>/dev/null || ifconfig"));

        eprintln!("[+] Listening Ports:");
        eprintln!("{}", self.run_cmd("netstat -tlnp 2>/dev/null || ss -tlnp"));

        eprintln!("[+] Environment:");
        eprintln!("{}", self.run_cmd("env | grep -E 'PATH|HOME|USER|SHELL'"));

        eprintln!("[+] Sudo Permissions:");
        eprintln!("{}", self.run_cmd("sudo -l 2>/dev/null"));

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
    module.enumerate()
}

static VTABLE: ModuleVTable = ModuleVTable { get_info, init, destroy, check: None, run };

#[no_mangle]
pub extern "C" fn amatsumara_module_init() -> *const ModuleVTable { &VTABLE }
