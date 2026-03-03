///! Dynamic module loader
///!
///! Loads modules from .so files at runtime using libloading.
///! Provides a safe wrapper around the C FFI interface.

use anyhow::{anyhow, Result};
use libloading::{Library, Symbol};
use amatsumara_api::{ModuleVTable, MODULE_API_VERSION};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// A dynamically loaded module
pub struct DynamicModule {
    _library: Arc<Library>,
    vtable: &'static ModuleVTable,
    path: PathBuf,
}

impl DynamicModule {
    /// Load a module from a shared library file
    pub unsafe fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        log::info!("Loading module from: {}", path.display());

        // Load the library
        let library = Library::new(path)
            .map_err(|e| anyhow!("Failed to load library {}: {}", path.display(), e))?;

        // Get the module initialization function
        let init_fn: Symbol<extern "C" fn() -> *const ModuleVTable> = library
            .get(b"msf_module_init")
            .map_err(|e| anyhow!("Module missing msf_module_init function: {}", e))?;

        // Call the initialization function to get the vtable
        let vtable_ptr = init_fn();
        if vtable_ptr.is_null() {
            return Err(anyhow!("Module returned null vtable"));
        }

        let vtable = &*vtable_ptr;

        // Get module info to check API version
        let info_ptr = (vtable.get_info)();
        if info_ptr.is_null() {
            return Err(anyhow!("Module returned null info"));
        }

        let info = &*info_ptr;
        if info.api_version != MODULE_API_VERSION {
            return Err(anyhow!(
                "Module API version mismatch: expected {}, got {}",
                MODULE_API_VERSION,
                info.api_version
            ));
        }

        log::info!(
            "Loaded module: {}",
            info.metadata.name.as_str()
        );

        Ok(Self {
            _library: Arc::new(library),
            vtable,
            path: path.to_path_buf(),
        })
    }

    /// Get module metadata
    pub fn get_info(&self) -> &amatsumara_api::ModuleInfo {
        unsafe { &*(self.vtable.get_info)() }
    }

    /// Get module name
    pub fn name(&self) -> String {
        unsafe { self.get_info().metadata.name.as_str().to_string() }
    }

    /// Get module type
    pub fn module_type(&self) -> amatsumara_api::ModuleType {
        self.get_info().metadata.module_type
    }

    /// Get module path
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Get the vtable for direct access
    pub fn vtable(&self) -> &'static ModuleVTable {
        self.vtable
    }
}

/// Module discovery - scans directories for .so files
pub struct ModuleDiscovery {
    search_paths: Vec<PathBuf>,
}

impl ModuleDiscovery {
    /// Create a new module discovery with default search paths
    pub fn new() -> Self {
        let mut search_paths = Vec::new();

        // Add user module directory
        if let Some(home) = std::env::var_os("HOME") {
            let mut user_modules = PathBuf::from(home);
            user_modules.push(".amatsumara");
            user_modules.push("modules");
            search_paths.push(user_modules);
        }

        // Add modules relative to the executable location
        // This allows running the binary from anywhere
        if let Ok(exe_path) = std::env::current_exe() {
            if let Some(exe_dir) = exe_path.parent() {
                // Check for modules in same directory as executable
                let mut exe_modules = exe_dir.to_path_buf();
                exe_modules.push("modules");
                search_paths.push(exe_modules);

                // Check for modules in ../../modules (when running from target/release/)
                let mut project_modules = exe_dir.to_path_buf();
                project_modules.push("../../modules");
                if let Ok(canonical) = project_modules.canonicalize() {
                    search_paths.push(canonical);
                }
            }
        }

        // Add current directory modules (original behavior)
        search_paths.push(PathBuf::from("./modules"));

        Self { search_paths }
    }

    /// Add a custom search path
    pub fn add_path(&mut self, path: impl Into<PathBuf>) {
        self.search_paths.push(path.into());
    }

    /// Discover all modules in search paths
    pub fn discover(&self) -> Result<Vec<DynamicModule>> {
        let mut modules = Vec::new();

        for search_path in &self.search_paths {
            if !search_path.exists() {
                log::debug!("Search path does not exist: {}", search_path.display());
                continue;
            }

            log::info!("Scanning for modules in: {}", search_path.display());
            self.discover_recursive(search_path, &mut modules);
        }

        log::info!("Discovered {} module(s)", modules.len());
        Ok(modules)
    }

    /// Recursively discover modules in a directory
    fn discover_recursive(&self, dir: &Path, modules: &mut Vec<DynamicModule>) {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    // Recurse into subdirectories
                    self.discover_recursive(&path, modules);
                } else if path.extension().and_then(|s| s.to_str()) == Some("so") {
                    match unsafe { DynamicModule::load(&path) } {
                        Ok(module) => {
                            log::info!("Discovered module: {}", module.name());
                            modules.push(module);
                        }
                        Err(e) => {
                            log::warn!("Failed to load module from {}: {}", path.display(), e);
                        }
                    }
                }
            }
        }
    }

    /// Get search paths
    pub fn search_paths(&self) -> &[PathBuf] {
        &self.search_paths
    }
}

impl Default for ModuleDiscovery {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discovery_creation() {
        let discovery = ModuleDiscovery::new();
        assert!(!discovery.search_paths().is_empty());
    }

    #[test]
    fn test_add_path() {
        let mut discovery = ModuleDiscovery::new();
        let initial_count = discovery.search_paths().len();

        discovery.add_path("/custom/path");
        assert_eq!(discovery.search_paths().len(), initial_count + 1);
    }
}
