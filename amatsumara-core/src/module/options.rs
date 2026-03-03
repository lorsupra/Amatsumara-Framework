///! Module options and configuration

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;

/// Option value type
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum OptionValue {
    String(String),
    Int(i64),
    Bool(bool),
    Float(f64),
    Address(IpAddr),
    Port(u16),
}

impl OptionValue {
    pub fn as_string(&self) -> Option<&str> {
        if let OptionValue::String(s) = self {
            Some(s)
        } else {
            None
        }
    }

    pub fn as_int(&self) -> Option<i64> {
        if let OptionValue::Int(i) = self {
            Some(*i)
        } else {
            None
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        if let OptionValue::Bool(b) = self {
            Some(*b)
        } else {
            None
        }
    }

    pub fn as_address(&self) -> Option<IpAddr> {
        if let OptionValue::Address(addr) = self {
            Some(*addr)
        } else {
            None
        }
    }

    pub fn as_port(&self) -> Option<u16> {
        if let OptionValue::Port(p) = self {
            Some(*p)
        } else {
            None
        }
    }
}

/// Module option definition
#[derive(Debug, Clone)]
pub struct ModuleOption {
    pub name: String,
    pub description: String,
    pub required: bool,
    pub default: Option<OptionValue>,
    pub option_type: OptionType,
}

#[derive(Debug, Clone, PartialEq)]
pub enum OptionType {
    String,
    Int,
    Bool,
    Float,
    Address,
    Port,
    Enum(Vec<String>),
}

impl ModuleOption {
    pub fn string(name: impl Into<String>, description: impl Into<String>, required: bool) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            required,
            default: None,
            option_type: OptionType::String,
        }
    }

    pub fn int(name: impl Into<String>, description: impl Into<String>, required: bool) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            required,
            default: None,
            option_type: OptionType::Int,
        }
    }

    pub fn bool(name: impl Into<String>, description: impl Into<String>, default: bool) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            required: false,
            default: Some(OptionValue::Bool(default)),
            option_type: OptionType::Bool,
        }
    }

    pub fn address(name: impl Into<String>, description: impl Into<String>, required: bool) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            required,
            default: None,
            option_type: OptionType::Address,
        }
    }

    pub fn port(name: impl Into<String>, description: impl Into<String>, default: u16) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            required: false,
            default: Some(OptionValue::Port(default)),
            option_type: OptionType::Port,
        }
    }

    pub fn with_default(mut self, value: OptionValue) -> Self {
        self.default = Some(value);
        self.required = false;
        self
    }

    /// Parse a string value according to this option's type
    pub fn parse(&self, value: &str) -> Result<OptionValue> {
        match &self.option_type {
            OptionType::String => Ok(OptionValue::String(value.to_string())),
            OptionType::Int => {
                let i = value.parse::<i64>()
                    .map_err(|_| anyhow!("Invalid integer value: {}", value))?;
                Ok(OptionValue::Int(i))
            }
            OptionType::Bool => {
                let b = value.parse::<bool>()
                    .or_else(|_| {
                        // Handle common bool representations
                        match value.to_lowercase().as_str() {
                            "yes" | "y" | "1" | "on" => Ok(true),
                            "no" | "n" | "0" | "off" => Ok(false),
                            _ => Err(anyhow!("Invalid boolean value: {}", value))
                        }
                    })?;
                Ok(OptionValue::Bool(b))
            }
            OptionType::Float => {
                let f = value.parse::<f64>()
                    .map_err(|_| anyhow!("Invalid float value: {}", value))?;
                Ok(OptionValue::Float(f))
            }
            OptionType::Address => {
                let addr = IpAddr::from_str(value)
                    .map_err(|_| anyhow!("Invalid IP address: {}", value))?;
                Ok(OptionValue::Address(addr))
            }
            OptionType::Port => {
                let p = value.parse::<u16>()
                    .map_err(|_| anyhow!("Invalid port number: {}", value))?;
                Ok(OptionValue::Port(p))
            }
            OptionType::Enum(valid_values) => {
                if valid_values.contains(&value.to_string()) {
                    Ok(OptionValue::String(value.to_string()))
                } else {
                    Err(anyhow!("Invalid value '{}'. Must be one of: {:?}", value, valid_values))
                }
            }
        }
    }
}

/// Container for module options
#[derive(Debug, Clone, Default)]
pub struct Options {
    options: HashMap<String, ModuleOption>,
}

impl Options {
    pub fn new() -> Self {
        Self {
            options: HashMap::new(),
        }
    }

    pub fn add(&mut self, option: ModuleOption) {
        self.options.insert(option.name.clone(), option);
    }

    pub fn get(&self, name: &str) -> Option<&ModuleOption> {
        self.options.get(name)
    }

    pub fn iter(&self) -> impl Iterator<Item = &ModuleOption> {
        self.options.values()
    }

    /// Validate datastore against required options
    pub fn validate(&self, datastore: &HashMap<String, String>) -> Result<()> {
        for option in self.options.values() {
            if option.required && !datastore.contains_key(&option.name) && option.default.is_none() {
                return Err(anyhow!("Required option '{}' is not set", option.name));
            }

            // If value is provided, validate it can be parsed
            if let Some(value) = datastore.get(&option.name) {
                option.parse(value)?;
            }
        }
        Ok(())
    }

    /// Get an option value from datastore or use default
    pub fn get_value(&self, name: &str, datastore: &HashMap<String, String>) -> Result<OptionValue> {
        let option = self.options.get(name)
            .ok_or_else(|| anyhow!("Unknown option: {}", name))?;

        if let Some(value) = datastore.get(name) {
            option.parse(value)
        } else if let Some(default) = &option.default {
            Ok(default.clone())
        } else if option.required {
            Err(anyhow!("Required option '{}' is not set", name))
        } else {
            Err(anyhow!("Option '{}' has no value or default", name))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_option_parsing() {
        let opt = ModuleOption::int("RPORT", "Remote port", true);
        let value = opt.parse("443").unwrap();
        assert_eq!(value, OptionValue::Int(443));

        let opt = ModuleOption::bool("SSL", "Use SSL", false);
        let value = opt.parse("yes").unwrap();
        assert_eq!(value, OptionValue::Bool(true));

        let opt = ModuleOption::address("RHOST", "Remote host", true);
        let value = opt.parse("192.168.1.1").unwrap();
        assert_eq!(value, OptionValue::Address(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
    }

    #[test]
    fn test_options_validation() {
        let mut options = Options::new();
        options.add(ModuleOption::string("RHOST", "Remote host", true));
        options.add(ModuleOption::port("RPORT", "Remote port", 80));

        let mut datastore = HashMap::new();

        // Missing required option
        assert!(options.validate(&datastore).is_err());

        // With required option
        datastore.insert("RHOST".to_string(), "192.168.1.1".to_string());
        assert!(options.validate(&datastore).is_ok());
    }

    #[test]
    fn test_get_value() {
        let mut options = Options::new();
        options.add(ModuleOption::port("RPORT", "Remote port", 80));

        let datastore = HashMap::new();
        let value = options.get_value("RPORT", &datastore).unwrap();
        assert_eq!(value, OptionValue::Port(80));
    }
}
