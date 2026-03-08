use anyhow::Result;
use colored::Colorize;
use rustyline::error::ReadlineError;
use amatsumara_core::{ModuleRegistry, ModuleDiscovery, ModuleType};
use std::sync::{Arc, RwLock};

mod context;
mod commands;
mod banner;
mod completer;

use context::ConsoleContext;
use commands::CommandHandler;
use completer::{ConsoleHelper, CompleterState};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize session channel (creates /tmp/amatsumara_sessions directory)
    amatsumara_core::init_session_channel();

    // Initialize module registry
    let registry = ModuleRegistry::new();

    // Discover and load dynamic modules
    println!("{}", "Initializing Amatsumara Framework...".bright_cyan());
    let discovery = ModuleDiscovery::new();
    let modules = discovery.discover()?;

    // Count modules by type
    let mut exploit_count = 0;
    let mut auxiliary_count = 0;
    let mut post_count = 0;
    let mut payload_count = 0;
    let mut utility_count = 0;

    // Build module map indexed by name and count by type
    // Duplicate .so files discovered from overlapping search paths are
    // deduplicated by name — only the first instance is counted.
    let mut loaded_modules = std::collections::HashMap::new();
    for module in modules {
        let name = module.name();

        if loaded_modules.contains_key(&name) {
            continue;
        }

        // Count by type
        match module.module_type() {
            ModuleType::Exploit => exploit_count += 1,
            ModuleType::Auxiliary => auxiliary_count += 1,
            ModuleType::Post => post_count += 1,
            ModuleType::Payload => payload_count += 1,
            ModuleType::Utility => utility_count += 1,
            _ => {}
        }

        loaded_modules.insert(name, module);
    }

    // Display banner with actual counts
    banner::display_banner_with_counts(exploit_count, auxiliary_count, post_count, payload_count, utility_count);

    println!();

    // Create console context
    let mut ctx = ConsoleContext::new(registry, loaded_modules);

    // Build shared completer state with module names
    let module_names: Vec<String> = ctx.loaded_modules.keys().cloned().collect();
    let completer_state = Arc::new(RwLock::new(CompleterState {
        module_names,
        current_module_options: Vec::new(),
    }));

    // Initialize readline with helper
    let helper = ConsoleHelper::new(Arc::clone(&completer_state));
    let mut rl = rustyline::Editor::new()?;
    rl.set_helper(Some(helper));

    // Load history
    let _ = rl.load_history(".amatsumara_history");

    // Main REPL loop
    loop {
        // Poll for sessions registered by background jobs (e.g. multi_handler)
        let pending_sessions = amatsumara_core::take_pending_sessions();
        for pending in pending_sessions {
            if pending.stream.set_nonblocking(true).is_err() {
                continue; // stale fd from a previous process
            }

            let tokio_stream = match tokio::net::TcpStream::from_std(pending.stream) {
                Ok(s) => s,
                Err(_) => continue,
            };

            let session_id = ctx.session_manager.next_id();
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
                    ctx.session_manager.register(session);
                    println!("{}", format!("[+] Session {} opened ({}:{})", session_id, pending.remote_host, pending.remote_port).bright_green().bold());
                }
                Err(e) => {
                    eprintln!("{}", format!("[-] Failed to create session: {}", e).bright_red());
                }
            }
        }

        let prompt = ctx.get_prompt();

        match rl.readline(&prompt) {
            Ok(line) => {
                let line = line.trim();

                // Skip empty lines
                if line.is_empty() {
                    continue;
                }

                // Add to history
                let _ = rl.add_history_entry(line);

                // Parse and execute command
                match execute_command(&mut ctx, &completer_state, line).await {
                    Ok(should_exit) => {
                        if should_exit {
                            break;
                        }
                    }
                    Err(e) => {
                        println!("{} {}", "Error:".bright_red(), e);
                    }
                }
            }
            Err(ReadlineError::Interrupted) => {
                // Ctrl-C
                continue;
            }
            Err(ReadlineError::Eof) => {
                // Ctrl-D
                println!("exit");
                break;
            }
            Err(err) => {
                println!("{} {:?}", "Error:".bright_red(), err);
                break;
            }
        }
    }

    // Save history
    let _ = rl.save_history(".amatsumara_history");

    println!("\n{}", "Sayonara, blacksmith.".bright_cyan());

    Ok(())
}

fn update_completer_options(ctx: &ConsoleContext, state: &Arc<RwLock<CompleterState>>) {
    let mut s = state.write().unwrap();
    s.current_module_options.clear();
    if let Some(module) = ctx.get_current_module() {
        let info = module.get_info();
        let options_slice = unsafe {
            if info.options.ptr.is_null() || info.options.len == 0 {
                &[]
            } else {
                std::slice::from_raw_parts(info.options.ptr, info.options.len)
            }
        };
        for opt in options_slice {
            let name = unsafe { opt.name.as_str().to_string() };
            s.current_module_options.push(name);
        }
    }
}

async fn execute_command(ctx: &mut ConsoleContext, completer_state: &Arc<RwLock<CompleterState>>, line: &str) -> Result<bool> {
    let parts: Vec<&str> = line.split_whitespace().collect();

    if parts.is_empty() {
        return Ok(false);
    }

    let command = parts[0];
    let args = &parts[1..];

    match command {
        "use" => {
            CommandHandler::new(ctx).cmd_use(args)?;
            update_completer_options(ctx, completer_state);
            ctx.auto_set_lhost();
            Ok(false)
        }
        "set" | "forge" => {
            CommandHandler::new(ctx).cmd_set(args)?;
            Ok(false)
        }
        "unset" => {
            CommandHandler::new(ctx).cmd_unset(args)?;
            Ok(false)
        }
        "setg" => {
            CommandHandler::new(ctx).cmd_setg(args)?;
            Ok(false)
        }
        "unsetg" => {
            CommandHandler::new(ctx).cmd_unsetg(args)?;
            Ok(false)
        }
        "show" => {
            CommandHandler::new(ctx).cmd_show(args)?;
            Ok(false)
        }
        "info" => {
            CommandHandler::new(ctx).cmd_info(args)?;
            Ok(false)
        }
        "search" => {
            CommandHandler::new(ctx).cmd_search(args)?;
            Ok(false)
        }
        "back" => {
            CommandHandler::new(ctx).cmd_back()?;
            update_completer_options(ctx, completer_state);
            Ok(false)
        }
        "options" => {
            CommandHandler::new(ctx).cmd_options()?;
            Ok(false)
        }
        "run" | "strike" => {
            ctx.auto_set_lhost();
            let background = args.contains(&"-j");
            CommandHandler::new(ctx).cmd_run(background).await?;
            Ok(false)
        }
        "jobs" => {
            CommandHandler::new(ctx).cmd_jobs(args)?;
            Ok(false)
        }
        "kill" => {
            CommandHandler::new(ctx).cmd_kill(args)?;
            Ok(false)
        }
        "check" => {
            CommandHandler::new(ctx).cmd_check().await?;
            Ok(false)
        }
        "sessions" => {
            if args.len() > 1 && args[0] == "-i" {
                CommandHandler::new(ctx).cmd_interact(&args[1..]).await?;
            } else if args.len() > 1 && args[0] == "-k" {
                CommandHandler::new(ctx).cmd_kill_session(&args[1..])?;
            } else {
                CommandHandler::new(ctx).cmd_sessions(args)?;
            }
            Ok(false)
        }
        "help" | "?" => {
            CommandHandler::new(ctx).cmd_help()?;
            Ok(false)
        }
        "exit" | "quit" => {
            Ok(true)
        }
        "banner" => {
            banner::display_banner();
            Ok(false)
        }
        _ => {
            println!("{} Unknown command: {}", "Error:".bright_red(), command);
            println!("Type {} for available commands", "help".bright_yellow());
            Ok(false)
        }
    }
}
