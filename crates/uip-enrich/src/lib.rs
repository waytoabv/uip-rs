pub mod target;
pub mod types;
pub use target::{is_enrichable, remote_ip};
pub use types::{GeoSource, IpFacts, RdnsSource, ThreatOutcome, ThreatSource};
