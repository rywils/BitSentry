use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct ScanResult {
    pub scan_id: String,
    pub engine: String,
    pub engine_version: String,
    pub target: Target,
    pub timestamp: DateTime<Utc>,
    pub duration_ms: u64,
    pub findings: Vec<Finding>,
}

impl ScanResult {
    pub fn new(target: Target, duration_ms: u64, findings: Vec<Finding>) -> Self {
        Self {
            scan_id: Uuid::new_v4().to_string(),
            engine: "rust".to_string(),
            engine_version: env!("CARGO_PKG_VERSION").to_string(),
            target,
            timestamp: Utc::now(),
            duration_ms,
            findings,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Target {
    pub input: String,
    pub resolved: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    #[serde(rename = "type")]
    pub finding_type: String,
    pub severity: String,
    pub confidence: f64,
    pub asset: Asset,
    pub details: serde_json::Value,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub evidence: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub references: Vec<String>,
}

impl Finding {
    pub fn open_port(id: String, asset: Asset) -> Self {
        Self {
            id,
            finding_type: "open_port".to_string(),
            severity: "info".to_string(),
            confidence: 0.99,
            asset,
            details: json!({}),
            evidence: vec!["tcp connect succeeded".to_string()],
            references: vec![],
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Asset {
    pub ip: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
}
