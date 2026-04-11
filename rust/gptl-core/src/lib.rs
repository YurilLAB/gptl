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
    ChangeBuilder, ChangeCategory, ChangeFilter, ChangeStatistics, ChangeStatus,
    ChangeTracker, ChangeTrackerConfig, ChangeTrackerError, PlatformDetails, SystemChange,
};

// Re-export relay types
pub use relay_registry::{
    RelayInfo, RelayRegistry, InMemoryRegistry, JsonFileRegistry, RelayCriteria,
    HealthStatus, SecurityLevel, Location, RelayCapabilities, RegistryError,
    SignedRelayList, RegistryRateLimiter,
};

pub use relay_selector::{
    RelaySelector, SelectionStrategy, SelectionResult, SelectorConfig,
    SelectorError, SelectorStatistics, RelayPool, FailureType as RelayFailureType,
};

/// Version of the GPTL core library
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
