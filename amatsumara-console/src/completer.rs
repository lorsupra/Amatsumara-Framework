use rustyline::completion::{Completer, Pair};
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;
use rustyline::{Context, Helper};
use std::sync::{Arc, RwLock};

/// Shared state between the completer and the main console
pub struct CompleterState {
    pub module_names: Vec<String>,
    pub current_module_options: Vec<String>,
}

pub struct ConsoleHelper {
    commands: Vec<String>,
    show_subcommands: Vec<String>,
    session_flags: Vec<String>,
    pub state: Arc<RwLock<CompleterState>>,
}

impl ConsoleHelper {
    pub fn new(state: Arc<RwLock<CompleterState>>) -> Self {
        let commands = vec![
            "use".to_string(),
            "set".to_string(),
            "forge".to_string(),
            "unset".to_string(),
            "setg".to_string(),
            "unsetg".to_string(),
            "show".to_string(),
            "info".to_string(),
            "search".to_string(),
            "back".to_string(),
            "options".to_string(),
            "run".to_string(),
            "strike".to_string(),
            "check".to_string(),
            "sessions".to_string(),
            "jobs".to_string(),
            "kill".to_string(),
            "help".to_string(),
            "exit".to_string(),
            "quit".to_string(),
            "banner".to_string(),
        ];

        let show_subcommands = vec![
            "options".to_string(),
            "exploits".to_string(),
            "auxiliary".to_string(),
            "payloads".to_string(),
            "post".to_string(),
            "all".to_string(),
        ];

        let session_flags = vec![
            "-l".to_string(),
            "-i".to_string(),
            "-k".to_string(),
        ];

        Self { commands, show_subcommands, session_flags, state }
    }
}

impl Completer for ConsoleHelper {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Pair>)> {
        let line = &line[..pos];
        let parts: Vec<&str> = line.split_whitespace().collect();

        // No input yet - complete commands
        if parts.is_empty() || (!line.contains(' ') && parts.len() == 1) {
            let prefix = if parts.is_empty() { "" } else { parts[0] };
            let candidates: Vec<Pair> = self
                .commands
                .iter()
                .filter(|cmd| cmd.starts_with(prefix))
                .map(|cmd| Pair {
                    display: cmd.clone(),
                    replacement: format!("{} ", cmd),
                })
                .collect();
            return Ok((0, candidates));
        }

        let command = parts[0];

        // Complete after a command
        match command {
            "use" | "info" => {
                // Complete module names
                let partial = if parts.len() > 1 {
                    parts[1..].join(" ")
                } else {
                    String::new()
                };
                let start_pos = if line.ends_with(' ') && partial.is_empty() {
                    pos
                } else {
                    line.find(&partial).unwrap_or(pos)
                };

                let state = self.state.read().unwrap();
                let partial_lower = partial.to_lowercase();
                let candidates: Vec<Pair> = state.module_names
                    .iter()
                    .filter(|name| name.to_lowercase().starts_with(&partial_lower))
                    .map(|name| Pair {
                        display: name.clone(),
                        replacement: name.clone(),
                    })
                    .collect();
                Ok((start_pos, candidates))
            }
            "set" | "forge" | "setg" | "unset" | "unsetg" => {
                // Complete option names (only the first arg after set)
                if parts.len() <= 2 && !line.ends_with(' ') || (parts.len() == 1 && line.ends_with(' ')) {
                    let partial = if parts.len() > 1 { parts[1] } else { "" };
                    let start_pos = if partial.is_empty() { pos } else { line.rfind(partial).unwrap_or(pos) };

                    let state = self.state.read().unwrap();
                    let partial_upper = partial.to_uppercase();
                    let mut candidates: Vec<Pair> = state.current_module_options
                        .iter()
                        .filter(|opt| opt.starts_with(&partial_upper))
                        .map(|opt| Pair {
                            display: opt.clone(),
                            replacement: format!("{} ", opt),
                        })
                        .collect();
                    // Add AUTOLHOST as a completable option for set/forge
                    if command == "set" || command == "forge" {
                        if "AUTOLHOST".starts_with(&partial_upper) {
                            candidates.push(Pair {
                                display: "AUTOLHOST".to_string(),
                                replacement: "AUTOLHOST ".to_string(),
                            });
                        }
                    }
                    Ok((start_pos, candidates))
                } else {
                    Ok((pos, vec![]))
                }
            }
            "show" => {
                let partial = if parts.len() > 1 { parts[1] } else { "" };
                let start_pos = if partial.is_empty() { pos } else { line.rfind(partial).unwrap_or(pos) };

                let candidates: Vec<Pair> = self.show_subcommands
                    .iter()
                    .filter(|sub| sub.starts_with(partial))
                    .map(|sub| Pair {
                        display: sub.clone(),
                        replacement: sub.clone(),
                    })
                    .collect();
                Ok((start_pos, candidates))
            }
            "sessions" => {
                let partial = if parts.len() > 1 { parts[1] } else { "" };
                let start_pos = if partial.is_empty() { pos } else { line.rfind(partial).unwrap_or(pos) };

                let candidates: Vec<Pair> = self.session_flags
                    .iter()
                    .filter(|f| f.starts_with(partial))
                    .map(|f| Pair {
                        display: f.clone(),
                        replacement: format!("{} ", f),
                    })
                    .collect();
                Ok((start_pos, candidates))
            }
            _ => Ok((pos, vec![])),
        }
    }
}

impl Hinter for ConsoleHelper {
    type Hint = String;

    fn hint(&self, line: &str, pos: usize, _ctx: &Context<'_>) -> Option<String> {
        if pos < line.len() {
            return None;
        }

        // Only hint for first word (command)
        if !line.contains(' ') {
            self.commands
                .iter()
                .find(|cmd| cmd.starts_with(line) && cmd.len() > line.len())
                .map(|cmd| cmd[line.len()..].to_string())
        } else {
            None
        }
    }
}

impl Highlighter for ConsoleHelper {}

impl Validator for ConsoleHelper {}

impl Helper for ConsoleHelper {}
