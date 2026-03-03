///! Check codes for vulnerability assessment

use serde::{Deserialize, Serialize};

/// Result of a vulnerability check
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheckCode {
    /// Exploit will work for sure (100%)
    Vulnerable,

    /// Exploit appears to work but not completely verified
    Appears,

    /// Target is likely vulnerable but couldn't fully verify
    Detected,

    /// Unable to determine vulnerability status
    Unknown,

    /// Target is definitely not vulnerable
    Safe,

    /// Service is not running or not accessible
    Unsupported,
}

impl CheckCode {
    /// Whether the check result indicates the target is exploitable
    pub fn is_vulnerable(&self) -> bool {
        matches!(self, CheckCode::Vulnerable | CheckCode::Appears)
    }

    /// Human-readable message for the check code
    pub fn message(&self) -> &'static str {
        match self {
            CheckCode::Vulnerable => "The target is vulnerable.",
            CheckCode::Appears => "The target appears to be vulnerable.",
            CheckCode::Detected => "The target service has been detected.",
            CheckCode::Unknown => "Unable to determine exploitability.",
            CheckCode::Safe => "The target is not exploitable.",
            CheckCode::Unsupported => "The target service is not supported.",
        }
    }
}

impl std::fmt::Display for CheckCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self, self.message())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_code() {
        assert!(CheckCode::Vulnerable.is_vulnerable());
        assert!(CheckCode::Appears.is_vulnerable());
        assert!(!CheckCode::Safe.is_vulnerable());
        assert!(!CheckCode::Unknown.is_vulnerable());
    }

    #[test]
    fn test_display() {
        let code = CheckCode::Vulnerable;
        assert_eq!(code.to_string(), "Vulnerable: The target is vulnerable.");
    }
}
