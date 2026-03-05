use crate::error::{Result, TailscaleError};
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct TailscaleConfig {
    pub(crate) hostname: String,
    pub(crate) auth_key: String,
    pub(crate) ephemeral: bool,
    pub(crate) state_dir: Option<PathBuf>,
    pub(crate) control_url: String,
}

impl TailscaleConfig {
    pub fn builder() -> TailscaleConfigBuilder {
        TailscaleConfigBuilder::default()
    }

    pub fn hostname(&self) -> &str {
        &self.hostname
    }

    pub fn control_url(&self) -> &str {
        &self.control_url
    }
}

#[derive(Debug, Default)]
pub struct TailscaleConfigBuilder {
    hostname: Option<String>,
    auth_key: Option<String>,
    ephemeral: bool,
    state_dir: Option<PathBuf>,
    control_url: Option<String>,
}

impl TailscaleConfigBuilder {
    pub fn hostname(mut self, hostname: impl Into<String>) -> Self {
        self.hostname = Some(hostname.into());
        self
    }

    pub fn auth_key(mut self, key: impl Into<String>) -> Self {
        self.auth_key = Some(key.into());
        self
    }

    pub fn ephemeral(mut self, ephemeral: bool) -> Self {
        self.ephemeral = ephemeral;
        self
    }

    pub fn state_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.state_dir = Some(path.into());
        self
    }

    pub fn control_url(mut self, url: impl Into<String>) -> Self {
        self.control_url = Some(url.into());
        self
    }

    pub fn build(self) -> Result<TailscaleConfig> {
        let hostname = self
            .hostname
            .ok_or_else(|| TailscaleError::Config("hostname is required".into()))?;

        if hostname.is_empty() {
            return Err(TailscaleError::Config("hostname cannot be empty".into()));
        }

        let auth_key = self
            .auth_key
            .ok_or_else(|| TailscaleError::Config("auth_key is required".into()))?;

        if auth_key.is_empty() {
            return Err(TailscaleError::Config("auth_key cannot be empty".into()));
        }

        Ok(TailscaleConfig {
            hostname,
            auth_key,
            ephemeral: self.ephemeral,
            state_dir: self.state_dir,
            control_url: self
                .control_url
                .unwrap_or_else(|| "https://controlplane.tailscale.com".into()),
        })
    }
}
