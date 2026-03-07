///! Module metadata definitions
///!
///! Defines the metadata structure for Amatsumara modules including
///! name, description, authors, references, platforms, and other attributes.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Module ranking indicates reliability and safety
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Ranking {
    /// The module is low quality, may crash or fail
    Low = 0,
    /// The module is average quality
    Average = 200,
    /// The module is normal quality
    Normal = 300,
    /// The module is good quality, stable and reliable
    Good = 400,
    /// The module is great quality, very stable
    Great = 500,
    /// The module is excellent quality, production-ready
    Excellent = 600,
    /// The module has been manually ranked
    Manual = 800,
}

/// Target platform for a module
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Platform {
    Windows,
    Linux,
    MacOS,
    BSD,
    Solaris,
    Android,
    IOS,
    Hardware,
    Multi,  // Multiple platforms
    Unknown,
}

/// Target architecture
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Arch {
    X86,
    X64,
    ARM,
    ARM64,
    MIPS,
    MIPS64,
    PPC,
    PPC64,
    SPARC,
    Unknown,
}

/// Reference types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReferenceType {
    CVE,
    BID,
    URL,
    EDB,  // Exploit-DB
    OSVDB,
    MSB,  // Microsoft Security Bulletin
    USN,  // Ubuntu Security Notice
    ZDI,  // Zero Day Initiative
}

/// External reference to vulnerability or documentation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reference {
    pub ref_type: ReferenceType,
    pub value: String,
}

impl Reference {
    pub fn cve(id: impl Into<String>) -> Self {
        Self {
            ref_type: ReferenceType::CVE,
            value: id.into(),
        }
    }

    pub fn url(url: impl Into<String>) -> Self {
        Self {
            ref_type: ReferenceType::URL,
            value: url.into(),
        }
    }

    pub fn edb(id: impl Into<String>) -> Self {
        Self {
            ref_type: ReferenceType::EDB,
            value: id.into(),
        }
    }
}

/// Module stability indicators
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Stability {
    /// Crashes the service or system
    CrashSafe,
    /// May crash under certain conditions
    CrashServiceRestarts,
    /// Crashes the service but it restarts
    CrashServiceRestartable,
    /// Crashes the OS or VM
    CrashOSDown,
    /// Crashes but recoverable
    CrashOSRestarts,
}

/// Module reliability indicators
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Reliability {
    /// First-shot reliability
    FirstShot,
    /// Repeatable session creation
    RepeatableSession,
    /// Unreliable
    Unreliable,
}

/// Side effects of running a module
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SideEffect {
    /// Creates artifacts on disk
    ArtifactsOnDisk,
    /// Modifies system configuration
    ConfigChanges,
    /// Creates indicators of compromise in logs
    IOCInLogs,
    /// Modifies account information
    AccountChanges,
    /// Uses system resources
    ServiceResourceLoss,
    /// Writes to screen/display
    ScreenEffects,
}

/// Module author information
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Author {
    pub name: String,
    pub email: Option<String>,
}

impl Author {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            email: None,
        }
    }

    pub fn with_email(name: impl Into<String>, email: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            email: Some(email.into()),
        }
    }
}

impl From<&str> for Author {
    fn from(s: &str) -> Self {
        if let Some((name, email)) = s.split_once('<') {
            let email = email.trim_end_matches('>').trim();
            Self::with_email(name.trim(), email)
        } else {
            Self::new(s)
        }
    }
}

/// Complete module metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleMetadata {
    /// Module name
    pub name: String,

    /// Detailed description
    pub description: String,

    /// Module authors
    pub authors: Vec<Author>,

    /// External references
    pub references: Vec<Reference>,

    /// Supported platforms
    pub platforms: Vec<Platform>,

    /// Supported architectures
    pub archs: Vec<Arch>,

    /// Module ranking
    pub ranking: Ranking,

    /// License (usually BSD-3-Clause)
    pub license: String,

    /// Disclosure date (ISO 8601 format: YYYY-MM-DD)
    pub disclosure_date: Option<String>,

    /// Whether module requires privileged access
    pub privileged: bool,

    /// Stability notes
    pub stability: Vec<Stability>,

    /// Reliability notes
    pub reliability: Vec<Reliability>,

    /// Side effects
    pub side_effects: Vec<SideEffect>,

    /// Additional notes (free-form)
    pub notes: HashMap<String, String>,
}

impl ModuleMetadata {
    pub fn builder(name: impl Into<String>) -> ModuleMetadataBuilder {
        ModuleMetadataBuilder::new(name)
    }
}

/// Builder for module metadata
pub struct ModuleMetadataBuilder {
    metadata: ModuleMetadata,
}

impl ModuleMetadataBuilder {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            metadata: ModuleMetadata {
                name: name.into(),
                description: String::new(),
                authors: Vec::new(),
                references: Vec::new(),
                platforms: Vec::new(),
                archs: Vec::new(),
                ranking: Ranking::Normal,
                license: "BSD-3-Clause".to_string(),
                disclosure_date: None,
                privileged: false,
                stability: Vec::new(),
                reliability: Vec::new(),
                side_effects: Vec::new(),
                notes: HashMap::new(),
            },
        }
    }

    pub fn description(mut self, desc: impl Into<String>) -> Self {
        self.metadata.description = desc.into();
        self
    }

    pub fn author(mut self, author: impl Into<Author>) -> Self {
        self.metadata.authors.push(author.into());
        self
    }

    pub fn reference(mut self, reference: Reference) -> Self {
        self.metadata.references.push(reference);
        self
    }

    pub fn platform(mut self, platform: Platform) -> Self {
        self.metadata.platforms.push(platform);
        self
    }

    pub fn arch(mut self, arch: Arch) -> Self {
        self.metadata.archs.push(arch);
        self
    }

    pub fn ranking(mut self, ranking: Ranking) -> Self {
        self.metadata.ranking = ranking;
        self
    }

    pub fn disclosure_date(mut self, date: impl Into<String>) -> Self {
        self.metadata.disclosure_date = Some(date.into());
        self
    }

    pub fn privileged(mut self, privileged: bool) -> Self {
        self.metadata.privileged = privileged;
        self
    }

    pub fn stability(mut self, stability: Stability) -> Self {
        self.metadata.stability.push(stability);
        self
    }

    pub fn reliability(mut self, reliability: Reliability) -> Self {
        self.metadata.reliability.push(reliability);
        self
    }

    pub fn side_effect(mut self, effect: SideEffect) -> Self {
        self.metadata.side_effects.push(effect);
        self
    }

    pub fn note(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.notes.insert(key.into(), value.into());
        self
    }

    pub fn build(self) -> ModuleMetadata {
        self.metadata
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metadata_builder() {
        let metadata = ModuleMetadata::builder("Test Exploit")
            .description("A test exploit module")
            .author("Test Author <test@example.com>")
            .reference(Reference::cve("2021-1234"))
            .reference(Reference::url("https://example.com/vuln"))
            .platform(Platform::Linux)
            .arch(Arch::X64)
            .ranking(Ranking::Good)
            .disclosure_date("2021-01-01")
            .privileged(false)
            .stability(Stability::CrashSafe)
            .reliability(Reliability::RepeatableSession)
            .side_effect(SideEffect::ArtifactsOnDisk)
            .build();

        assert_eq!(metadata.name, "Test Exploit");
        assert_eq!(metadata.authors.len(), 1);
        assert_eq!(metadata.references.len(), 2);
        assert_eq!(metadata.ranking, Ranking::Good);
    }

    #[test]
    fn test_author_parsing() {
        let author: Author = "John Doe <john@example.com>".into();
        assert_eq!(author.name, "John Doe");
        assert_eq!(author.email, Some("john@example.com".to_string()));

        let author2: Author = "Jane Smith".into();
        assert_eq!(author2.name, "Jane Smith");
        assert_eq!(author2.email, None);
    }
}
