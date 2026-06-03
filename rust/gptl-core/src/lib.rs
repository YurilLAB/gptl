//! GPTL Core Library
//!
//! Provides core anti-surveillance and anonymity protections
//! including traffic shaping, padding, timing protection,
//! circuit obfuscation, and system change tracking.

pub mod anti_surveillance;
pub mod changes;
pub mod relay_registry;
pub mod relay_selector;

// Re-export commonly used types
pub use changes::{
    ChangeBuilder, ChangeCategory, ChangeFilter, ChangeStatistics, ChangeStatus, ChangeTracker,
    ChangeTrackerConfig, ChangeTrackerError, PlatformDetails, SystemChange,
};

// Re-export relay types
pub use relay_registry::{
    HealthStatus, InMemoryRegistry, JsonFileRegistry, Location, RegistryError, RegistryRateLimiter,
    RelayCapabilities, RelayCriteria, RelayInfo, RelayRegistry, SecurityLevel, SignedRelayList,
};

pub use relay_selector::{
    FailureType as RelayFailureType, RelayPool, RelaySelector, SelectionResult, SelectionStrategy,
    SelectorConfig, SelectorError, SelectorStatistics,
};

/// Version of the GPTL core library
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
