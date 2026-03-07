# Changelog

## v2.1.0 - Quality of Life + New Modules

### New Exploit Modules (6 total, all confirmed working against live targets)
- Apache Log4j RCE (Log4Shell / CVE-2021-44228)
  Tested: TryHackMe Solar room
- Erlang/OTP SSH Pre-Auth RCE (CVE-2025-32433)
  Tested: TryHackMe Erlang/OTP SSH room
- MS17-010 EternalBlue SMB RCE
  Tested: TryHackMe Blue room
- Multi Handler
  Generic reverse shell listener
- PaperCut MF/NG Auth Bypass + RCE (CVE-2023-27350)
  Tested: TryHackMe PaperCut room
- React Server Components RCE (React2Shell / CVE-2025-55182)
  Tested: TryHackMe React2Shell room

### New Auxiliary Modules (1 total, confirmed working against live targets)
- SimpleHelp Path Traversal File Read (CVE-2024-57727)
  Tested: TryHackMe SimpleHelp room
  Uses raw TCP to preserve ../ sequences (reqwest normalizes them away)
  Covers both Windows and Linux targets via ordered directory iteration
  Parses and highlights credentials from serverconfig.xml

### Console Improvements
- AutoLHOST: automatically detects tun0/tap0 and populates LHOST on module
  load - no more running `ip a` before every exploit
- Fixed two-column display wrapping in show exploits / show auxiliary / search
  output - descriptions now stay in the right column on wrap instead of
  falling to column 0

### Philosophy
Quality over quantity. Every module in this framework has been tested against
a real target before being included. No dead weight.

## v2.0.0

Removed non-functioning exploit modules. Quality over quantity. Starting fresh with 3 confirmed working exploits.

## v1.4.1

Audit and bug fixes across 10 modules (port defaults, protocol formatting, nonce extraction, payload targeting).

## v1.3.0

Full MS17-010 EternalBlue implementation with kernel shellcode and automatic session registration.

## v1.2.0

8 new exploit modules.

## v1.1.0

8 new HTTP-based exploit modules.

## v1.0.1

HTTPS transport fix across 22 modules.

## v1.0.0

Initial release. Dynamic module loading, interactive console, session management, background jobs, 9 payload generators, pattern utilities.
