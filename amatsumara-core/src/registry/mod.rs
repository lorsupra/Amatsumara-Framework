///! Module registry and loader system
///!
///! Manages the collection of available modules and provides
///! discovery, instantiation, and management capabilities.

use crate::module::{Module, ModuleMetadata};
use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::sync::Arc;

/// Type alias for module factory function
pub type ModuleFactory = Arc<dyn Fn() -> Box<dyn Module> + Send + Sync>;

/// Module reference in the registry
pub struct ModuleInfo {
    /// Module full path (e.g., "exploit/linux/http/example")
    pub path: String,

    /// Module type (exploit, auxiliary, post, etc.)
    pub module_type: String,

    /// Cached metadata
    pub metadata: ModuleMetadata,

    /// Factory function to create module instances
    factory: ModuleFactory,
}

impl ModuleInfo {
    pub fn new(
        path: impl Into<String>,
        module_type: impl Into<String>,
        metadata: ModuleMetadata,
        factory: ModuleFactory,
    ) -> Self {
        Self {
            path: path.into(),
            module_type: module_type.into(),
            metadata,
            factory,
        }
    }

    /// Create a new instance of this module
    pub fn instantiate(&self) -> Box<dyn Module> {
        (self.factory)()
    }
}

/// Module registry - the central module management system
pub struct ModuleRegistry {
    /// Registered modules indexed by full path
    modules: HashMap<String, ModuleInfo>,

    /// Index by module type for fast filtering
    by_type: HashMap<String, Vec<String>>,

    /// Index by platform for fast filtering
    by_platform: HashMap<String, Vec<String>>,
}

impl ModuleRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self {
            modules: HashMap::new(),
            by_type: HashMap::new(),
            by_platform: HashMap::new(),
        }
    }

    /// Register a module
    ///
    /// # Arguments
    /// * `path` - Full module path (e.g., "exploit/linux/http/example")
    /// * `module_type` - Module type (exploit, auxiliary, etc.)
    /// * `factory` - Factory function to create module instances
    pub fn register(
        &mut self,
        path: impl Into<String>,
        module_type: impl Into<String>,
        factory: ModuleFactory,
    ) -> Result<()> {
        let path = path.into();
        let module_type = module_type.into();

        // Create a temporary instance to get metadata
        let temp_instance = factory();
        let metadata = temp_instance.metadata().clone();

        // Create module info
        let info = ModuleInfo::new(
            path.clone(),
            module_type.clone(),
            metadata.clone(),
            factory,
        );

        // Index by type
        self.by_type
            .entry(module_type.clone())
            .or_insert_with(Vec::new)
            .push(path.clone());

        // Index by platforms
        for platform in &metadata.platforms {
            let platform_key = format!("{:?}", platform).to_lowercase();
            self.by_platform
                .entry(platform_key)
                .or_insert_with(Vec::new)
                .push(path.clone());
        }

        // Store module info
        self.modules.insert(path.clone(), info);

        Ok(())
    }

    /// Get a module by path
    pub fn get(&self, path: &str) -> Option<&ModuleInfo> {
        self.modules.get(path)
    }

    /// Create an instance of a module by path
    pub fn instantiate(&self, path: &str) -> Result<Box<dyn Module>> {
        self.get(path)
            .ok_or_else(|| anyhow!("Module not found: {}", path))
            .map(|info| info.instantiate())
    }

    /// List all registered modules
    pub fn list_all(&self) -> Vec<&ModuleInfo> {
        self.modules.values().collect()
    }

    /// List modules by type
    pub fn list_by_type(&self, module_type: &str) -> Vec<&ModuleInfo> {
        if let Some(paths) = self.by_type.get(module_type) {
            paths.iter()
                .filter_map(|path| self.modules.get(path))
                .collect()
        } else {
            Vec::new()
        }
    }

    /// List modules by platform
    pub fn list_by_platform(&self, platform: &str) -> Vec<&ModuleInfo> {
        let platform_key = platform.to_lowercase();
        if let Some(paths) = self.by_platform.get(&platform_key) {
            paths.iter()
                .filter_map(|path| self.modules.get(path))
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Search modules by name/description
    pub fn search(&self, query: &str) -> Vec<&ModuleInfo> {
        let query_lower = query.to_lowercase();
        self.modules.values()
            .filter(|info| {
                info.path.to_lowercase().contains(&query_lower) ||
                info.metadata.name.to_lowercase().contains(&query_lower) ||
                info.metadata.description.to_lowercase().contains(&query_lower)
            })
            .collect()
    }

    /// Get count of registered modules
    pub fn count(&self) -> usize {
        self.modules.len()
    }

    /// Get count by type
    pub fn count_by_type(&self, module_type: &str) -> usize {
        self.by_type.get(module_type)
            .map(|v| v.len())
            .unwrap_or(0)
    }
}

impl Default for ModuleRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ModuleMetadata, Platform, Arch, Ranking};

    // Mock module for testing
    struct TestModule {
        metadata: ModuleMetadata,
    }

    impl TestModule {
        fn new() -> Self {
            Self {
                metadata: ModuleMetadata::builder("Test Module")
                    .description("A test module")
                    .author("Test Author")
                    .platform(Platform::Linux)
                    .arch(Arch::X64)
                    .ranking(Ranking::Manual)
                    .build(),
            }
        }
    }

    impl Module for TestModule {
        fn metadata(&self) -> &ModuleMetadata {
            &self.metadata
        }

        fn options(&self) -> &crate::Options {
            use std::sync::OnceLock;
            static OPTIONS: OnceLock<crate::Options> = OnceLock::new();
            OPTIONS.get_or_init(|| crate::Options::new())
        }

        fn module_type(&self) -> &'static str {
            "test"
        }
    }

    #[test]
    fn test_registry_register() {
        let mut registry = ModuleRegistry::new();

        let factory = Arc::new(|| Box::new(TestModule::new()) as Box<dyn Module>);
        registry.register("test/example", "test", factory).unwrap();

        assert_eq!(registry.count(), 1);
        assert_eq!(registry.count_by_type("test"), 1);
    }

    #[test]
    fn test_registry_get() {
        let mut registry = ModuleRegistry::new();
        let factory = Arc::new(|| Box::new(TestModule::new()) as Box<dyn Module>);
        registry.register("test/example", "test", factory).unwrap();

        let info = registry.get("test/example");
        assert!(info.is_some());
        assert_eq!(info.unwrap().path, "test/example");
    }

    #[test]
    fn test_registry_instantiate() {
        let mut registry = ModuleRegistry::new();
        let factory = Arc::new(|| Box::new(TestModule::new()) as Box<dyn Module>);
        registry.register("test/example", "test", factory).unwrap();

        let module = registry.instantiate("test/example").unwrap();
        assert_eq!(module.metadata().name, "Test Module");
    }

    #[test]
    fn test_registry_list_by_type() {
        let mut registry = ModuleRegistry::new();
        let factory = Arc::new(|| Box::new(TestModule::new()) as Box<dyn Module>);

        registry.register("test/example1", "test", factory.clone()).unwrap();
        registry.register("test/example2", "test", factory.clone()).unwrap();
        registry.register("other/example", "other", factory).unwrap();

        let test_modules = registry.list_by_type("test");
        assert_eq!(test_modules.len(), 2);
    }

    #[test]
    fn test_registry_search() {
        let mut registry = ModuleRegistry::new();
        let factory = Arc::new(|| Box::new(TestModule::new()) as Box<dyn Module>);
        registry.register("test/example", "test", factory).unwrap();

        let results = registry.search("test");
        assert_eq!(results.len(), 1);

        let results = registry.search("nonexistent");
        assert_eq!(results.len(), 0);
    }
}
