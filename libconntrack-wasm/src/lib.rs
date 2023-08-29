use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[serde_with::serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DnsTrackerEntry {
    pub hostname: String,
    pub created: DateTime<Utc>,
    #[serde_as(as = "Option<serde_with::DurationMicroSeconds<i64>>")]
    pub rtt: Option<chrono::Duration>,
    #[serde_as(as = "Option<serde_with::DurationSeconds<i64>>")]
    pub ttl: Option<chrono::Duration>,
}
