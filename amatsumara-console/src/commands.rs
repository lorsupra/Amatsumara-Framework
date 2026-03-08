use amatsumara_core::session_api::{CommandResult, SessionApi, SessionHandle};
use anyhow::{anyhow, Result};
use chrono::{DateTime, Local};
use colored::Colorize;
use crate::context::ConsoleContext;
use std::ffi::CString;
use std::os::raw::{c_char, c_int};
use std::sync::atomic::{AtomicPtr, Ordering};
use std::ptr;

fn term_width() -> usize {
    terminal_size::terminal_size()
        .map(|(w, _)| w.0 as usize)
        .unwrap_or(120)
}

/// Word-wrap `text` to fit in `max_width` columns. Returns lines.
fn wrap_text(text: &str, max_width: usize) -> Vec<String> {
    if max_width == 0 || text.len() <= max_width {
        return vec![text.to_string()];
    }
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        if current.is_empty() {
            current = word.to_string();
        } else if current.len() + 1 + word.len() <= max_width {
            current.push(' ');
            current.push_str(word);
        } else {
            lines.push(current);
            current = word.to_string();
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

/// Wrap a module path at `/` boundaries to fit in `max_width` columns.
fn wrap_path(path: &str, max_width: usize) -> Vec<String> {
    if max_width == 0 || path.len() <= max_width {
        return vec![path.to_string()];
    }
    let parts: Vec<&str> = path.split('/').collect();
    let mut lines = Vec::new();
    let mut current = String::new();
    for (i, part) in parts.iter().enumerate() {
        let sep = if i > 0 { "/" } else { "" };
        let candidate = format!("{}{}{}", current, sep, part);
        if candidate.len() <= max_width || current.is_empty() {
            current = candidate;
        } else {
            current.push('/');
            lines.push(current);
            current = part.to_string();
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

/// Wrap a module name: use word boundaries if it has spaces, path boundaries otherwise.
fn wrap_name(name: &str, max_width: usize) -> Vec<String> {
    if max_width == 0 || name.len() <= max_width {
        return vec![name.to_string()];
    }
    if name.contains(' ') {
        wrap_text(name, max_width)
    } else {
        wrap_path(name, max_width)
    }
}

// --- Session API trampoline infrastructure ---
//
// These extern "C" functions are called by post modules via the SessionApi
// function pointer table. They bridge the FFI boundary back into the framework's
// SessionManager. A raw pointer to the SessionManager is stored in an AtomicPtr
// and set before each run() call.

static SESSION_MGR_PTR: AtomicPtr<amatsumara_core::SessionManager> =
    AtomicPtr::new(ptr::null_mut());

/// The SessionApi instance whose pointers we pass to modules.
/// Lives for the duration of the process; function pointers are stable.
static SESSION_API_INSTANCE: SessionApi = SessionApi {
    exec_cmd: trampoline_exec_cmd,
    free_result: trampoline_free_result,
    session_alive: trampoline_session_alive,
};

extern "C" fn trampoline_exec_cmd(
    session_id: SessionHandle,
    command: *const c_char,
    timeout_ms: u32,
) -> CommandResult {
    let mgr_ptr = SESSION_MGR_PTR.load(Ordering::Acquire);
    if mgr_ptr.is_null() || command.is_null() {
        return CommandResult {
            output: ptr::null(),
            output_len: 0,
            status: -1,
        };
    }

    let mgr = unsafe { &*mgr_ptr };
    let cmd_str = match unsafe { std::ffi::CStr::from_ptr(command) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            return CommandResult {
                output: ptr::null(),
                output_len: 0,
                status: -2,
            };
        }
    };

    let timeout = if timeout_ms == 0 {
        std::time::Duration::from_secs(10)
    } else {
        std::time::Duration::from_millis(timeout_ms as u64)
    };

    match mgr.exec_blocking(session_id, cmd_str, timeout) {
        Ok(output) => {
            let bytes = output.into_bytes();
            let len = bytes.len();
            let boxed = bytes.into_boxed_slice();
            let ptr = Box::into_raw(boxed) as *const c_char;
            CommandResult {
                output: ptr,
                output_len: len,
                status: 0,
            }
        }
        Err(_) => CommandResult {
            output: ptr::null(),
            output_len: 0,
            status: -3,
        },
    }
}

extern "C" fn trampoline_free_result(result: *mut CommandResult) {
    if result.is_null() {
        return;
    }
    let result_ref = unsafe { &mut *result };
    if !result_ref.output.is_null() && result_ref.output_len > 0 {
        // Reconstruct the Box<[u8]> and drop it
        unsafe {
            let slice = std::slice::from_raw_parts_mut(
                result_ref.output as *mut u8,
                result_ref.output_len,
            );
            let _ = Box::from_raw(slice as *mut [u8]);
        }
        result_ref.output = ptr::null();
        result_ref.output_len = 0;
    }
}

extern "C" fn trampoline_session_alive(session_id: SessionHandle) -> c_int {
    let mgr_ptr = SESSION_MGR_PTR.load(Ordering::Acquire);
    if mgr_ptr.is_null() {
        return 0;
    }
    let mgr = unsafe { &*mgr_ptr };
    if mgr.is_alive(session_id) { 1 } else { 0 }
}

// --- End trampoline infrastructure ---

pub struct CommandHandler<'a> {
    ctx: &'a mut ConsoleContext,
}

impl<'a> CommandHandler<'a> {
    pub fn new(ctx: &'a mut ConsoleContext) -> Self {
        Self { ctx }
    }

    /// Use command - select a module
    pub fn cmd_use(&mut self, args: &[&str]) -> Result<()> {
        if args.is_empty() {
            return Err(anyhow!("Usage: use <module_path> or use <number>"));
        }

        let module_path = if args.len() == 1 {
            // Check if it's a number (from search results)
            if let Ok(idx) = args[0].parse::<usize>() {
                // Look up in last search results
                if idx < self.ctx.last_search_results.len() {
                    self.ctx.last_search_results[idx].clone()
                } else {
                    return Err(anyhow!("Invalid module number: {}. Use 'search' to see available modules.", idx));
                }
            } else {
                args.join(" ")
            }
        } else {
            args.join(" ")
        };

        // Exact match first
        if self.ctx.loaded_modules.contains_key(&module_path) {
            println!("{} module: {}", "Selected".bright_green(), module_path.bright_cyan());
            self.ctx.select_module(module_path);
            return Ok(());
        }

        // Fuzzy match: case-insensitive substring search on module names
        let search_lower = module_path.to_lowercase();
        // Also match against directory-style names by replacing underscores/hyphens
        let search_normalized = search_lower.replace('-', "_");
        let mut matches: Vec<String> = Vec::new();

        for name in self.ctx.loaded_modules.keys() {
            let name_lower = name.to_lowercase();
            // Also check against the .so file path for directory-name matching
            let path_name = self.ctx.loaded_modules.get(name)
                .map(|m| m.path().file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("")
                    .trim_start_matches("lib")
                    .to_lowercase())
                .unwrap_or_default();

            if name_lower.contains(&search_lower) ||
               path_name.contains(&search_normalized) ||
               path_name.contains(&search_lower) {
                matches.push(name.clone());
            }
        }

        match matches.len() {
            0 => Err(anyhow!("Module not found: {}. Use 'search' to find modules.", module_path)),
            1 => {
                let name = matches.into_iter().next().unwrap();
                println!("{} module: {}", "Selected".bright_green(), name.bright_cyan());
                self.ctx.select_module(name);
                Ok(())
            }
            _ => {
                matches.sort();
                println!("{} Multiple modules match '{}':", "Info:".bright_yellow(), module_path);
                for (i, name) in matches.iter().enumerate() {
                    println!("  {} {}", format!("{}.", i).bright_blue(), name.bright_green());
                }
                println!("\nUse a more specific name, or 'search' then 'use <number>'.");
                Ok(())
            }
        }
    }

    /// Set command - set a module option (or global setting like autolhost)
    pub fn cmd_set(&mut self, args: &[&str]) -> Result<()> {
        if args.len() < 2 {
            return Err(anyhow!("Usage: set <option> <value>"));
        }

        let option = args[0].to_uppercase();
        let value = args[1..].join(" ");

        // Handle AutoLHOST as a global toggle (works without a module selected)
        if option == "AUTOLHOST" {
            match value.to_lowercase().as_str() {
                "true" | "1" | "yes" => {
                    self.ctx.auto_lhost = true;
                    println!("{} => {}", "AutoLHOST".bright_yellow(), "true".bright_white());
                }
                "false" | "0" | "no" => {
                    self.ctx.auto_lhost = false;
                    println!("{} => {}", "AutoLHOST".bright_yellow(), "false".bright_white());
                }
                _ => return Err(anyhow!("Invalid value for AutoLHOST. Use true/false.")),
            }
            return Ok(());
        }

        if !self.ctx.has_module() {
            return Err(anyhow!("No module selected. Use 'use <module>' first."));
        }

        // Track manual LHOST set
        if option == "LHOST" {
            self.ctx.lhost_manually_set = true;
        }

        println!("{} => {}", option.bright_yellow(), value.bright_white());
        self.ctx.set_option(option, value);

        Ok(())
    }

    /// Unset command - unset a module option
    pub fn cmd_unset(&mut self, args: &[&str]) -> Result<()> {
        if args.is_empty() {
            return Err(anyhow!("Usage: unset <option>"));
        }

        if !self.ctx.has_module() {
            return Err(anyhow!("No module selected. Use 'use <module>' first."));
        }

        let option = args[0].to_uppercase();

        if self.ctx.unset_option(&option) {
            println!("{} {}", "Unset".bright_green(), option.bright_yellow());
        } else {
            println!("{} Option {} is not set", "Warning:".bright_yellow(), option);
        }

        Ok(())
    }

    /// Setg command - set a global option
    pub fn cmd_setg(&mut self, args: &[&str]) -> Result<()> {
        if args.len() < 2 {
            return Err(anyhow!("Usage: setg <option> <value>"));
        }

        let option = args[0].to_uppercase();
        let value = args[1..].join(" ");

        // Track manual LHOST set
        if option == "LHOST" {
            self.ctx.lhost_manually_set = true;
        }

        println!("{} {} => {}", "Global".bright_magenta(), option.bright_yellow(), value.bright_white());
        self.ctx.set_global_option(option, value);

        Ok(())
    }

    /// Unsetg command - unset a global option
    pub fn cmd_unsetg(&mut self, args: &[&str]) -> Result<()> {
        if args.is_empty() {
            return Err(anyhow!("Usage: unsetg <option>"));
        }

        let option = args[0].to_uppercase();

        if self.ctx.unset_global_option(&option) {
            println!("{} {}", "Unset global".bright_green(), option.bright_yellow());
        } else {
            println!("{} Global option {} is not set", "Warning:".bright_yellow(), option);
        }

        Ok(())
    }

    /// Show command - show various information
    pub fn cmd_show(&mut self, args: &[&str]) -> Result<()> {
        if args.is_empty() {
            return Err(anyhow!("Usage: show <exploits|auxiliary|utilities|payloads|post|options|all>"));
        }

        match args[0] {
            "options" => self.show_options(),
            "exploits" => self.show_modules_by_type("exploit"),
            "auxiliary" => self.show_modules_by_type("auxiliary"),
            "utilities" => self.show_modules_by_type("utility"),
            "payloads" => self.show_modules_by_type("payload"),
            "post" => self.show_modules_by_type("post"),
            "all" => self.show_all_modules(),
            _ => Err(anyhow!("Unknown show argument: {}. Try: exploits, auxiliary, utilities, payloads, post, options, all", args[0])),
        }
    }

    fn show_options(&self) -> Result<()> {
        if !self.ctx.has_module() {
            return Err(anyhow!("No module selected. Use 'use <module>' first."));
        }

        // Get the current module to read its defined options
        let module = self.ctx.get_current_module()
            .ok_or_else(|| anyhow!("Module not loaded"))?;
        let info = module.get_info();

        println!("\n{}", "Module options:".bright_cyan().bold());
        println!();

        // Read options from the module's FFI interface
        let options_slice = unsafe {
            if info.options.ptr.is_null() || info.options.len == 0 {
                &[]
            } else {
                std::slice::from_raw_parts(info.options.ptr, info.options.len)
            }
        };

        if options_slice.is_empty() {
            println!("  {}", "No options defined for this module".bright_black());
        } else {
            // Calculate column widths
            let mut max_name_len = 4;
            let mut max_value_len = 15;
            for opt in options_slice {
                let name = unsafe { opt.name.as_str() };
                max_name_len = max_name_len.max(name.len());

                // Get current value
                let current = self.ctx.module_options.get(name)
                    .or_else(|| self.ctx.global_options.get(name))
                    .map(|s| s.as_str())
                    .unwrap_or_else(|| unsafe { opt.default_value.as_str() });
                max_value_len = max_value_len.max(current.len());
            }
            let name_width = max_name_len + 2;
            let value_width = max_value_len.max(15) + 2;

            println!("  {}{}{}{}",
                format!("{:<width$}", "Name", width = name_width).bright_white().bold(),
                format!("{:<width$}", "Current Setting", width = value_width).bright_white().bold(),
                format!("{:<10}", "Required").bright_white().bold(),
                "Description".bright_white().bold()
            );
            println!("  {}{}{}{}",
                format!("{:<width$}", "----", width = name_width).bright_black(),
                format!("{:<width$}", "---------------", width = value_width).bright_black(),
                format!("{:<10}", "--------").bright_black(),
                "-----------".bright_black()
            );

            for opt in options_slice {
                let name = unsafe { opt.name.as_str() };
                let desc = unsafe { opt.description.as_str() };
                let default = unsafe { opt.default_value.as_str() };
                let required = opt.required;

                // Get current value: check module options, then global, then default
                let current = self.ctx.module_options.get(name)
                    .or_else(|| self.ctx.global_options.get(name))
                    .map(|s| s.as_str())
                    .unwrap_or(default);

                let req_str = if required { "yes" } else { "no" };
                let req_colored = if required {
                    format!("{:<10}", req_str).bright_red()
                } else {
                    format!("{:<10}", req_str).bright_black()
                };

                println!("  {}{}{}{}",
                    format!("{:<width$}", name, width = name_width).bright_yellow(),
                    format!("{:<width$}", current, width = value_width).bright_white(),
                    req_colored,
                    desc
                );
            }
        }

        // Show global settings (AutoLHOST + global options)
        println!();
        println!("{}", "Global settings:".bright_magenta().bold());
        println!();
        println!("  {:<20} {}",
            "AutoLHOST".bright_yellow(),
            if self.ctx.auto_lhost { "true".bright_white() } else { "false".bright_white() }
        );

        if !self.ctx.global_options.is_empty() {
            for (key, value) in &self.ctx.global_options {
                println!("  {:<20} {}",
                    key.bright_yellow(),
                    value.bright_white()
                );
            }
        }

        println!();

        Ok(())
    }

    fn show_modules_by_type(&self, module_type: &str) -> Result<()> {
        // First pass: collect modules and find max name length
        let mut modules: Vec<(String, String)> = Vec::new();
        let mut max_name_len = 4; // minimum width for "Name" header

        for (name, module) in &self.ctx.loaded_modules {
            let info = module.get_info();
            let mod_type = format!("{:?}", info.metadata.module_type).to_lowercase();
            if mod_type == module_type {
                let desc = unsafe { info.metadata.description.as_str().to_string() };
                max_name_len = max_name_len.max(name.len());
                modules.push((name.clone(), desc));
            }
        }

        // Sort by name
        modules.sort_by(|a, b| a.0.cmp(&b.0));

        let tw = term_width();
        let indent = 2usize;
        // Cap name column to half the terminal width
        let name_width = (max_name_len + 2).min(tw / 2);
        let left_total = indent + name_width;
        let desc_width = tw.saturating_sub(left_total).max(20);

        println!("\n{} modules:", module_type.bright_cyan().bold());
        println!();
        println!("  {}{}",
            format!("{:<width$}", "Name", width = name_width).bright_white().bold(),
            "Description".bright_white().bold()
        );
        println!("  {}{}",
            format!("{:<width$}", "----", width = name_width).bright_black(),
            "-----------".bright_black()
        );

        if modules.is_empty() {
            println!("  {}", "No modules loaded yet".bright_black());
        } else {
            // Usable content width for the name column (minus 2 for gap)
            let name_content = name_width.saturating_sub(2);
            for (name, desc) in &modules {
                let name_lines = wrap_name(name, name_content);
                let desc_lines = wrap_text(desc, desc_width);
                let row_count = name_lines.len().max(desc_lines.len());
                for i in 0..row_count {
                    let n = name_lines.get(i).map(|s| s.as_str()).unwrap_or("");
                    let d = desc_lines.get(i).map(|s| s.as_str()).unwrap_or("");
                    println!("  {}{}",
                        format!("{:<width$}", n, width = name_width).bright_green(),
                        d
                    );
                }
            }
        }
        println!();

        Ok(())
    }

    fn show_all_modules(&mut self) -> Result<()> {
        self.show_modules_by_type("exploit")?;
        self.show_modules_by_type("auxiliary")?;
        self.show_modules_by_type("utility")?;
        self.show_modules_by_type("post")?;
        self.show_modules_by_type("payload")?;
        Ok(())
    }

    /// Info command - show detailed module information
    pub fn cmd_info(&mut self, args: &[&str]) -> Result<()> {
        let module_path = if args.is_empty() {
            // Show info for current module
            if let Some(ref path) = self.ctx.current_module {
                path.clone()
            } else {
                return Err(anyhow!("No module selected. Use 'use <module>' or 'info <module_path>'"));
            }
        } else if args.len() == 1 {
            // Check if it's a number (from search results)
            if let Ok(idx) = args[0].parse::<usize>() {
                // Look up in last search results
                if idx < self.ctx.last_search_results.len() {
                    self.ctx.last_search_results[idx].clone()
                } else {
                    return Err(anyhow!("Invalid module number: {}. Use 'search' to see available modules.", idx));
                }
            } else {
                args.join(" ")
            }
        } else {
            args.join(" ")
        };

        // Get the module
        let module = self.ctx.loaded_modules.get(&module_path)
            .ok_or_else(|| anyhow!("Module not found: {}. Use 'search' to find modules.", module_path))?;

        let info = module.get_info();

        // Extract strings from FFI structures safely
        let name = unsafe {
            std::str::from_utf8_unchecked(std::slice::from_raw_parts(
                info.metadata.name.ptr as *const u8,
                info.metadata.name.len
            ))
        };

        let description = unsafe {
            std::str::from_utf8_unchecked(std::slice::from_raw_parts(
                info.metadata.description.ptr as *const u8,
                info.metadata.description.len
            ))
        };

        let author = unsafe {
            std::str::from_utf8_unchecked(std::slice::from_raw_parts(
                info.metadata.author.ptr as *const u8,
                info.metadata.author.len
            ))
        };

        // Get platforms
        let platforms: Vec<String> = (0..info.metadata.platforms.len)
            .map(|i| unsafe {
                let platform_ptr = info.metadata.platforms.ptr.offset(i as isize);
                format!("{:?}", *platform_ptr)
            })
            .collect();

        // Get architectures
        let archs: Vec<String> = (0..info.metadata.archs.len)
            .map(|i| unsafe {
                let arch_ptr = info.metadata.archs.ptr.offset(i as isize);
                format!("{:?}", *arch_ptr)
            })
            .collect();

        println!("\n{}", "Module Information:".bright_cyan().bold());
        println!();
        println!("       {}: {}", "Name".bright_white(), name.bright_cyan());
        println!("     {}: {}", "Module".bright_white(), module_path);
        println!("   {}: {}", "Platform".bright_white(), platforms.join(", "));
        println!("       {}: {}", "Arch".bright_white(), archs.join(", "));
        println!("       {}: {}", "Rank".bright_white(), format!("{:?}", info.metadata.ranking).bright_yellow());
        println!(" {}: {}", "Privileged".bright_white(), info.metadata.privileged);
        println!();

        // Author
        if !author.is_empty() {
            println!("     {}: {}", "Author".bright_white(), author);
            println!();
        }

        println!("{}", "Description:".bright_white());
        println!("  {}", description);
        println!();

        Ok(())
    }

    /// Search command - search for modules
    pub fn cmd_search(&mut self, args: &[&str]) -> Result<()> {
        let search_term = if args.is_empty() {
            String::new()  // Empty search shows all modules
        } else {
            args.join(" ").to_lowercase()
        };

        // First pass: collect matches and find max name length
        let mut matches: Vec<(String, String)> = Vec::new();
        let mut max_name_len = 4; // minimum width for "Name" header

        for (name, module) in &self.ctx.loaded_modules {
            let info = module.get_info();
            let module_name = name.to_lowercase();
            let module_desc = unsafe { info.metadata.description.as_str().to_lowercase() };

            // Match if search term is in name or description (or if no search term)
            if search_term.is_empty() ||
               module_name.contains(&search_term) ||
               module_desc.contains(&search_term) {
                let desc = unsafe { info.metadata.description.as_str().to_string() };
                max_name_len = max_name_len.max(name.len());
                matches.push((name.clone(), desc));
            }
        }

        // Sort by name
        matches.sort_by(|a, b| a.0.cmp(&b.0));

        // Calculate column widths (index is 5 chars, then name with padding)
        let tw = term_width();
        let indent = 2usize;
        let idx_width = 5;
        let name_width = (max_name_len + 2).min(tw / 2);
        let left_total = indent + idx_width + name_width;
        let desc_width = tw.saturating_sub(left_total).max(20);

        println!("\n{} for: {}", "Searching".bright_cyan(),
            if search_term.is_empty() { "*".to_string() } else { search_term.clone() }.bright_yellow());
        println!();
        println!("  {}{}{}",
            format!("{:<width$}", "#", width = idx_width).bright_white().bold(),
            format!("{:<width$}", "Name", width = name_width).bright_white().bold(),
            "Description".bright_white().bold()
        );
        println!("  {}{}{}",
            format!("{:<width$}", "-", width = idx_width).bright_black(),
            format!("{:<width$}", "----", width = name_width).bright_black(),
            "-----------".bright_black()
        );

        if matches.is_empty() {
            println!("  {}", "No matches found".bright_black());
            self.ctx.last_search_results.clear();
        } else {
            // Clear and store results for numbered selection
            self.ctx.last_search_results.clear();
            let name_content = name_width.saturating_sub(2);
            let idx_pad = " ".repeat(idx_width);

            for (idx, (name, desc)) in matches.iter().enumerate() {
                // Store module name for numbered selection
                self.ctx.last_search_results.push(name.clone());

                let name_lines = wrap_name(name, name_content);
                let desc_lines = wrap_text(desc, desc_width);
                let row_count = name_lines.len().max(desc_lines.len());
                for i in 0..row_count {
                    let n = name_lines.get(i).map(|s| s.as_str()).unwrap_or("");
                    let d = desc_lines.get(i).map(|s| s.as_str()).unwrap_or("");
                    if i == 0 {
                        println!("  {}{}{}",
                            format!("{:<width$}", idx, width = idx_width).bright_blue(),
                            format!("{:<width$}", n, width = name_width).bright_green(),
                            d
                        );
                    } else {
                        println!("  {}{}{}",
                            &idx_pad,
                            format!("{:<width$}", n, width = name_width).bright_green(),
                            d
                        );
                    }
                }
            }
        }

        println!();

        Ok(())
    }

    /// Back command - deselect current module
    pub fn cmd_back(&mut self) -> Result<()> {
        if !self.ctx.has_module() {
            println!("{} No module selected", "Warning:".bright_yellow());
            return Ok(());
        }

        println!("{} module", "Deselected".bright_green());
        self.ctx.deselect_module();

        Ok(())
    }

    /// Options command - alias for show options
    pub fn cmd_options(&self) -> Result<()> {
        self.show_options()
    }

    /// Jobs command - list background jobs
    pub fn cmd_jobs(&mut self, _args: &[&str]) -> Result<()> {
        // Clean up finished jobs first
        self.ctx.jobs.retain(|job| !job.handle.is_finished());

        if self.ctx.jobs.is_empty() {
            println!("\n{}\n", "No active jobs.".bright_yellow());
            return Ok(());
        }

        println!("\n{}", "Active jobs".bright_cyan().bold());
        println!();
        println!("  {:<5} {:<40} {}",
            "Id".bright_white().bold(),
            "Name".bright_white().bold(),
            "Running".bright_white().bold()
        );
        println!("  {:<5} {:<40} {}",
            "--".bright_black(),
            "----".bright_black(),
            "-------".bright_black()
        );

        for job in &self.ctx.jobs {
            let elapsed = job.started_at.elapsed();
            let duration = format!("{}s", elapsed.as_secs());
            println!("  {:<5} {:<40} {}",
                job.id.to_string().bright_green(),
                job.name.bright_cyan(),
                duration
            );
        }
        println!();

        Ok(())
    }

    /// Jobs interact - foreground a background job and block until it completes
    pub async fn cmd_jobs_interact(&mut self, args: &[&str]) -> Result<()> {
        if args.is_empty() {
            return Err(anyhow!("Usage: jobs -i <job_id>"));
        }

        let job_id: u32 = args[0].parse()
            .map_err(|_| anyhow!("Invalid job ID"))?;

        let pos = self.ctx.jobs.iter().position(|j| j.id == job_id)
            .ok_or_else(|| anyhow!("Job {} not found", job_id))?;

        let job = self.ctx.jobs.remove(pos);

        if job.handle.is_finished() {
            println!("{}", format!("[*] Job {} ({}) has already completed", job_id, job.name).bright_blue());
            return Ok(());
        }

        println!("{}", format!("[*] Foregrounding job {}: {}", job_id, job.name).bright_blue());
        println!("{}", "[*] Waiting for job to complete...".bright_blue());

        match job.handle.await {
            Ok(code) => {
                if code == 0 {
                    println!("{}", format!("[+] Job {} completed successfully", job_id).bright_green());
                } else {
                    println!("{}", format!("[-] Job {} exited with code {}", job_id, code).bright_red());
                }
            }
            Err(e) if e.is_cancelled() => {
                println!("{}", format!("[*] Job {} was cancelled", job_id).bright_yellow());
            }
            Err(e) => {
                println!("{}", format!("[-] Job {} failed: {}", job_id, e).bright_red());
            }
        }

        // Pick up any sessions the job may have registered
        let pending_sessions = amatsumara_core::take_pending_sessions();
        for pending in pending_sessions {
            if pending.stream.set_nonblocking(true).is_err() {
                continue;
            }

            let tokio_stream = match tokio::net::TcpStream::from_std(pending.stream) {
                Ok(s) => s,
                Err(_) => continue,
            };

            let session_id = self.ctx.session_manager.next_id();
            match amatsumara_core::Session::from_tcp(
                session_id,
                amatsumara_core::SessionKind::Shell,
                tokio_stream,
                pending.description,
            ).await {
                Ok(mut session) => {
                    if !pending.remote_host.is_empty() {
                        session.info.remote_host = pending.remote_host.clone();
                        session.info.remote_port = pending.remote_port;
                    }
                    self.ctx.session_manager.register(session);
                    println!("{}", format!("[+] Session {} opened ({}:{})", session_id, pending.remote_host, pending.remote_port).bright_green().bold());
                }
                Err(e) => {
                    eprintln!("{}", format!("[-] Failed to create session: {}", e).bright_red());
                }
            }
        }

        Ok(())
    }

    /// Kill command - kill a background job
    pub fn cmd_kill(&mut self, args: &[&str]) -> Result<()> {
        if args.is_empty() {
            return Err(anyhow!("Usage: kill <job_id>"));
        }

        let job_id: u32 = args[0].parse()
            .map_err(|_| anyhow!("Invalid job ID"))?;

        if let Some(pos) = self.ctx.jobs.iter().position(|j| j.id == job_id) {
            let job = self.ctx.jobs.remove(pos);
            job.handle.abort();
            println!("{}", format!("[*] Killed job {}: {}", job_id, job.name).bright_blue());
        } else {
            return Err(anyhow!("Job {} not found", job_id));
        }

        Ok(())
    }

    /// Run/Exploit command - execute the module
    pub async fn cmd_run(&mut self, background: bool) -> Result<()> {
        if !self.ctx.has_module() {
            return Err(anyhow!("No module selected. Use 'use <module>' first."));
        }

        let module_path = self.ctx.current_module.as_ref().unwrap();

        // Get the loaded module
        let module = self.ctx.get_current_module()
            .ok_or_else(|| anyhow!("Module not loaded: {}", module_path))?;

        println!();
        println!("{}", format!("[*] Started exploit handler").bright_blue());
        println!("{}", format!("[*] Launching module: {}", module_path).bright_blue());

        // Merge global options with module options (module takes priority)
        let mut merged_options = self.ctx.global_options.clone();
        for (key, value) in &self.ctx.module_options {
            merged_options.insert(key.clone(), value.clone());
        }

        // Show configuration
        println!("{}", "[*] Module options:".bright_blue());
        for (key, value) in &merged_options {
            let source = if self.ctx.module_options.contains_key(key) { "" } else { " (global)" };
            println!("{}", format!("[*]   {} = {}{}", key, value, source).bright_blue());
        }

        // Convert options to JSON
        let options_json = serde_json::to_string(&merged_options)
            .map_err(|e| anyhow!("Failed to serialize options: {}", e))?;

        // Get FFI function pointers (these are 'static and Send)
        let vtable = module.vtable();
        let run_fn = vtable.run;
        let init_fn = vtable.init;
        let destroy_fn = vtable.destroy;
        let module_name = module_path.clone();

        // Inject session API into the module (if it supports it).
        // Set the global SessionManager pointer so trampoline functions work.
        let mgr_ptr = &self.ctx.session_manager as *const amatsumara_core::SessionManager
            as *mut amatsumara_core::SessionManager;
        SESSION_MGR_PTR.store(mgr_ptr, Ordering::Release);
        module.inject_session_api(&SESSION_API_INSTANCE as *const SessionApi);

        if background {
            // Background execution
            let job_id = self.ctx.next_job_id;
            self.ctx.next_job_id += 1;

            let options_json_bg = options_json.clone();
            let handle = tokio::task::spawn_blocking(move || {
                let instance = (init_fn)();
                let options_cstr = CString::new(options_json_bg.as_str()).unwrap();
                let result = (run_fn)(instance, options_cstr.as_ptr());
                (destroy_fn)(instance);
                result as i32
            });

            self.ctx.jobs.push(crate::context::Job {
                id: job_id,
                name: module_name,
                started_at: std::time::Instant::now(),
                handle,
            });

            println!("{}", format!("[*] Job {} started in background", job_id).bright_blue());
            println!();
        } else {
            // Foreground execution
            println!();
            println!("{}", "[*] Executing module...".bright_blue());

            let instance = (init_fn)();
            let options_cstr = CString::new(options_json.as_str())
                .map_err(|e| anyhow!("Failed to create C string: {}", e))?;
            let result = (run_fn)(instance, options_cstr.as_ptr());
            (destroy_fn)(instance);

            if result == 0 {
                println!("{}", "[+] Module executed successfully".bright_green());

                // Check for pending sessions from file-based IPC
                let pending_sessions = amatsumara_core::take_pending_sessions();

                if !pending_sessions.is_empty() {
                    println!("{}", format!("[*] Processing {} pending session(s)...", pending_sessions.len()).bright_blue());
                }

                for pending in pending_sessions {
                    pending.stream.set_nonblocking(true)
                        .expect("Failed to set non-blocking");

                    let tokio_stream = tokio::net::TcpStream::from_std(pending.stream)
                        .expect("Failed to convert to tokio stream");

                    let session_id = self.ctx.session_manager.next_id();
                    match amatsumara_core::Session::from_tcp(
                        session_id,
                        amatsumara_core::SessionKind::Shell,
                        tokio_stream,
                        pending.description
                    ).await {
                        Ok(mut session) => {
                            // Use PendingSession host/port (correct for both
                            // reverse shells and bridged sessions like SSH)
                            if !pending.remote_host.is_empty() {
                                session.info.remote_host = pending.remote_host.clone();
                                session.info.remote_port = pending.remote_port;
                            }
                            self.ctx.session_manager.register(session);
                            println!("{}", format!("[+] Session {} opened ({}:{})", session_id, pending.remote_host, pending.remote_port).bright_green().bold());
                        }
                        Err(e) => {
                            eprintln!("{}", format!("[-] Failed to create session: {}", e).bright_red());
                        }
                    }
                }
            } else {
                println!("{}", format!("[-] Module execution failed with code: {}", result).bright_red());
            }

            println!();
        }

        Ok(())
    }

    /// Check command - check if target is vulnerable
    pub async fn cmd_check(&mut self) -> Result<()> {
        if !self.ctx.has_module() {
            return Err(anyhow!("No module selected. Use 'use <module>' first."));
        }

        let module_path = self.ctx.current_module.as_ref().unwrap();

        // Get the loaded module
        let module = self.ctx.get_current_module()
            .ok_or_else(|| anyhow!("Module not loaded: {}", module_path))?;

        println!();
        println!("{}", "[*] Checking if target is vulnerable...".bright_blue());

        // Merge global options with module options (module takes priority)
        let mut merged_options = self.ctx.global_options.clone();
        for (key, value) in &self.ctx.module_options {
            merged_options.insert(key.clone(), value.clone());
        }

        // Convert options to JSON
        let options_json = serde_json::to_string(&merged_options)
            .map_err(|e| anyhow!("Failed to serialize options: {}", e))?;

        // Call the module's check function via FFI
        let vtable = module.vtable();

        // Check if module has a check function
        if let Some(check_fn) = vtable.check {
            // Create module instance
            let instance = (vtable.init)();

            // Convert options to C string
            let options_cstr = CString::new(options_json.as_str())
                .map_err(|e| anyhow!("Failed to create C string: {}", e))?;

            // Call check
            let check_code = check_fn(instance, options_cstr.as_ptr());

            // Cleanup
            (vtable.destroy)(instance);

            // Display result
            match check_code as u32 {
                0 => println!("{}", "[*] Check code: Unknown".bright_blue()),
                1 => println!("{}", "[+] Target is safe (not vulnerable)".bright_green()),
                2 => println!("{}", "[+] Vulnerability detected!".bright_green()),
                3 => println!("{}", "[+] Target appears to be vulnerable".bright_yellow()),
                4 => println!("{}", "[+] Target is vulnerable!".bright_green().bold()),
                5 => println!("{}", "[-] Target is unsupported".bright_red()),
                _ => println!("{}", format!("[?] Unknown check code: {}", check_code as u32).bright_yellow()),
            }
        } else {
            println!("{}", "[-] Module does not support vulnerability checking".bright_red());
        }

        println!();

        Ok(())
    }

    /// Sessions command - list active sessions
    pub fn cmd_sessions(&self, args: &[&str]) -> Result<()> {
        if !args.is_empty() && args[0] == "-l" {
            // List sessions
            let sessions = self.ctx.session_manager.list();

            if sessions.is_empty() {
                println!("\n{}\n", "No active sessions.".bright_yellow());
                return Ok(());
            }

            println!("\n{}", "Active sessions".bright_cyan().bold());
            println!();
            println!("  {:<5} {:<20} {:<15} {:<10} {}",
                "Id".bright_white().bold(),
                "Type".bright_white().bold(),
                "Info".bright_white().bold(),
                "Tunnel".bright_white().bold(),
                "Opened At".bright_white().bold()
            );
            println!("  {:<5} {:<20} {:<15} {:<10} {}",
                "--".bright_black(),
                "----".bright_black(),
                "----".bright_black(),
                "------".bright_black(),
                "---------".bright_black()
            );

            for session in sessions {
                let session_type = format!("{:?}", session.session_type);
                let info = format!("{}:{}", session.remote_host, session.remote_port);
                let tunnel = format!("{}:{}", session.remote_host, session.remote_port);

                let datetime: DateTime<Local> = session.opened_at.into();
                let opened_at = datetime.format("%Y-%m-%d %H:%M:%S").to_string();

                println!("  {:<5} {:<20} {:<15} {:<10} {}",
                    session.id.to_string().bright_green(),
                    session_type.bright_cyan(),
                    info,
                    tunnel,
                    opened_at
                );
            }

            println!();
        } else {
            // Show usage
            println!("\n{}", "Usage:".bright_cyan());
            println!("  sessions -l             List all active sessions");
            println!("  sessions -i <id>        Interact with session");
            println!("  sessions -k <id>        Kill a session");
            println!();
        }

        Ok(())
    }

    /// Kill session command
    pub fn cmd_kill_session(&mut self, args: &[&str]) -> Result<()> {
        if args.is_empty() {
            return Err(anyhow!("Usage: sessions -k <id>"));
        }

        if args[0] == "all" {
            let sessions = self.ctx.session_manager.list();
            let count = sessions.len();
            for session in sessions {
                self.ctx.session_manager.remove(session.id);
            }
            println!("{}", format!("[*] Killed {} session(s)", count).bright_blue());
            return Ok(());
        }

        let session_id: u32 = args[0].parse()
            .map_err(|_| anyhow!("Invalid session ID. Use a number or 'all'"))?;

        if self.ctx.session_manager.remove(session_id).is_some() {
            println!("{}", format!("[*] Killed session {}", session_id).bright_blue());
        } else {
            return Err(anyhow!("Session {} not found", session_id));
        }

        Ok(())
    }

    /// Interact command - interact with a session
    pub async fn cmd_interact(&mut self, args: &[&str]) -> Result<()> {
        if args.is_empty() {
            return Err(anyhow!("Usage: sessions -i <id>"));
        }

        let session_id: u32 = args[0].parse()
            .map_err(|_| anyhow!("Invalid session ID"))?;

        let session = self.ctx.session_manager.get(session_id)
            .ok_or_else(|| anyhow!("Session {} not found", session_id))?;

        println!();
        println!("{}", format!("[*] Starting interaction with session {}", session_id).bright_blue());
        println!("{}", "[*] Commands:".bright_cyan());
        println!("  {}  - Return to console (keeps session alive)", "background".bright_yellow());
        println!("  {}      - Exit and close session", "exit".bright_yellow());
        println!();

        // Start interactive loop
        self.interact_with_session(session).await?;

        Ok(())
    }

    async fn interact_with_session(
        &mut self,
        session: std::sync::Arc<std::sync::Mutex<amatsumara_core::Session>>
    ) -> Result<()> {
        use tokio::io::{AsyncBufReadExt, BufReader};
        use tokio::time::{sleep, Duration};

        let mut stdin = BufReader::new(tokio::io::stdin());
        let mut line = String::new();
        let mut waiting_for_input = true;

        loop {
            // Check for and display any output from the session
            {
                let sess = session.lock().unwrap();
                if sess.has_output() {
                    let outputs = sess.read_output();
                    for output in outputs {
                        // Display output in white for readability on dark backgrounds
                        println!("{}", output.white());
                    }
                    waiting_for_input = true;
                }
            }

            // Display prompt when waiting for input
            if waiting_for_input {
                print!("{}", "shell> ".bright_green().bold());
                use std::io::Write;
                std::io::stdout().flush()?;
                waiting_for_input = false;
            }

            // Small sleep to prevent busy-waiting
            sleep(Duration::from_millis(50)).await;

            // Try to read from stdin (non-blocking with timeout)
            let read_result = tokio::time::timeout(
                Duration::from_millis(100),
                stdin.read_line(&mut line)
            ).await;

            if let Ok(Ok(n)) = read_result {
                if n == 0 {
                    // EOF
                    break;
                }

                let input = line.trim();

                // Handle special commands
                if input.eq_ignore_ascii_case("background") {
                    println!();
                    println!("{}", "[*] Backgrounding session...".bright_blue());
                    return Ok(());
                }

                if input.eq_ignore_ascii_case("exit") {
                    println!();
                    println!("{}", "[*] Closing session...".bright_blue());
                    drop(session);
                    return Ok(());
                }

                // Send command to session
                if !input.is_empty() {
                    let sess = session.lock().unwrap();
                    if let Err(e) = sess.send_command(input) {
                        eprintln!("{} {}", "Error sending command:".bright_red(), e);
                        break;
                    }
                } else {
                    // Empty input, show prompt again
                    waiting_for_input = true;
                }

                line.clear();
            }
        }

        Ok(())
    }

    /// Help command - show available commands
    pub fn cmd_help(&self) -> Result<()> {
        println!();
        println!("{}", "Amatsumara Console Commands".bright_cyan().bold());
        println!();

        let commands = vec![
            ("use <module>", "Select a module to use"),
            ("back", "Deselect the current module"),
            ("info [module]", "Display detailed information about a module"),
            ("search <term>", "Search for modules"),
            ("", ""),
            ("set <option> <value>", "Set a module option (alias: forge)"),
            ("forge <option> <value>", "Set a module option (alias: set)"),
            ("unset <option>", "Unset a module option"),
            ("setg <option> <value>", "Set a global option"),
            ("unsetg <option>", "Unset a global option"),
            ("set autolhost <true|false>", "Toggle automatic LHOST detection"),
            ("", ""),
            ("show <options|exploits|auxiliary|utilities|all>", "Display options or modules"),
            ("options", "Show current module options"),
            ("", ""),
            ("run", "Execute the selected module (alias: strike)"),
            ("strike", "Execute the selected module (alias: run)"),
            ("run -j", "Execute the module in background"),
            ("check", "Check if target is vulnerable"),
            ("", ""),
            ("sessions -l", "List all active sessions"),
            ("sessions -i <id>", "Interact with a session"),
            ("sessions -k <id>", "Kill a session"),
            ("sessions -k all", "Kill all sessions"),
            ("", ""),
            ("jobs", "List background jobs"),
            ("jobs -i <id>", "Foreground a background job"),
            ("jobs -k <id>", "Kill a background job"),
            ("kill <id>", "Kill a background job"),
            ("", ""),
            ("help", "Show this help message (alias: ?)"),
            ("banner", "Display the banner"),
            ("exit", "Exit the console (alias: quit)"),
        ];

        for (cmd, desc) in commands {
            if cmd.is_empty() {
                println!();
            } else {
                println!("  {:<30} {}", cmd.bright_yellow(), desc);
            }
        }

        println!();

        Ok(())
    }
}
