use std::collections::HashMap;
use colored::Colorize;
use amatsumara_core::{ModuleRegistry, DynamicModule, SessionManager};
use tokio::task::JoinHandle;

/// Background job tracking
pub struct Job {
    pub id: u32,
    pub name: String,
    pub started_at: std::time::Instant,
    pub handle: JoinHandle<i32>,
}

/// Console context maintains the state of the console session
pub struct ConsoleContext {
    /// The module registry (reserved for future use)
    #[allow(dead_code)]
    pub registry: ModuleRegistry,

    /// Loaded dynamic modules indexed by name
    pub loaded_modules: HashMap<String, DynamicModule>,

    /// Session manager for active sessions
    pub session_manager: SessionManager,

    /// Currently selected module path
    pub current_module: Option<String>,

    /// Module-specific options (cleared when switching modules)
    pub module_options: HashMap<String, String>,

    /// Global options (persist across module switches)
    pub global_options: HashMap<String, String>,

    /// Last search results (for numbered selection)
    pub last_search_results: Vec<String>,

    /// Background jobs
    pub jobs: Vec<Job>,

    /// Next job ID
    pub next_job_id: u32,
}

impl ConsoleContext {
    pub fn new(registry: ModuleRegistry, loaded_modules: HashMap<String, DynamicModule>) -> Self {
        Self {
            registry,
            loaded_modules,
            session_manager: SessionManager::new(),
            current_module: None,
            module_options: HashMap::new(),
            global_options: HashMap::new(),
            last_search_results: Vec::new(),
            jobs: Vec::new(),
            next_job_id: 1,
        }
    }

    /// Get the console prompt
    pub fn get_prompt(&self) -> String {
        match &self.current_module {
            Some(module) => {
                format!("{} {} ({}) > ",
                    "amatsumara".bright_red().bold(),
                    module.bright_cyan(),
                    self.get_module_type_short()
                )
            }
            None => {
                format!("{} > ", "amatsumara".bright_red().bold())
            }
        }
    }

    /// Get the short module type for prompt
    fn get_module_type_short(&self) -> String {
        if let Some(module) = self.get_current_module() {
            match module.module_type() {
                amatsumara_core::ModuleType::Exploit => return "exploit".to_string(),
                amatsumara_core::ModuleType::Auxiliary => return "auxiliary".to_string(),
                amatsumara_core::ModuleType::Post => return "post".to_string(),
                amatsumara_core::ModuleType::Payload => return "payload".to_string(),
                _ => {}
            }
        }
        "module".to_string()
    }

    /// Select a module
    pub fn select_module(&mut self, module_path: String) {
        self.current_module = Some(module_path);
        // Clear module-specific options when switching
        self.module_options.clear();
    }

    /// Deselect current module
    pub fn deselect_module(&mut self) {
        self.current_module = None;
        self.module_options.clear();
    }

    /// Set a module option
    pub fn set_option(&mut self, key: String, value: String) {
        self.module_options.insert(key, value);
    }

    /// Unset a module option
    pub fn unset_option(&mut self, key: &str) -> bool {
        self.module_options.remove(key).is_some()
    }

    /// Set a global option
    pub fn set_global_option(&mut self, key: String, value: String) {
        self.global_options.insert(key, value);
    }

    /// Unset a global option
    pub fn unset_global_option(&mut self, key: &str) -> bool {
        self.global_options.remove(key).is_some()
    }

    /// Get an option value (checks module options first, then global)
    #[allow(dead_code)]
    pub fn get_option(&self, key: &str) -> Option<&String> {
        self.module_options.get(key)
            .or_else(|| self.global_options.get(key))
    }

    /// Check if a module is currently selected
    pub fn has_module(&self) -> bool {
        self.current_module.is_some()
    }

    /// Get the currently selected dynamic module
    pub fn get_current_module(&self) -> Option<&DynamicModule> {
        if let Some(ref module_name) = self.current_module {
            self.loaded_modules.get(module_name)
        } else {
            None
        }
    }
}
