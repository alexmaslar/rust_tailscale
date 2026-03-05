use crate::error::{Result, TailscaleError};
use crate::keys::{DiscoKey, MachineKey, NodeKey};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Persistent state saved to disk between restarts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistentState {
    pub machine_key: MachineKey,
    pub node_key: NodeKey,
    pub disco_key: DiscoKey,
}

impl PersistentState {
    pub fn new() -> Self {
        Self {
            machine_key: MachineKey::generate(),
            node_key: NodeKey::generate(),
            disco_key: DiscoKey::generate(),
        }
    }

    pub fn load_or_create(state_dir: Option<&Path>) -> Result<Self> {
        if let Some(dir) = state_dir {
            let path = dir.join("state.json");
            if path.exists() {
                return Self::load(&path);
            }
            let state = Self::new();
            state.save(&path)?;
            Ok(state)
        } else {
            Ok(Self::new())
        }
    }

    pub fn load(path: &Path) -> Result<Self> {
        let data = std::fs::read_to_string(path)
            .map_err(|e| TailscaleError::State(format!("failed to read state: {}", e)))?;
        serde_json::from_str(&data)
            .map_err(|e| TailscaleError::State(format!("failed to parse state: {}", e)))
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| TailscaleError::State(format!("failed to create state dir: {}", e)))?;
        }
        let data = serde_json::to_string_pretty(self)
            .map_err(|e| TailscaleError::State(format!("failed to serialize state: {}", e)))?;
        std::fs::write(path, data)
            .map_err(|e| TailscaleError::State(format!("failed to write state: {}", e)))?;
        Ok(())
    }
}
