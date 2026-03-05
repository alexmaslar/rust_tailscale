use thiserror::Error;

#[derive(Error, Debug)]
pub enum TailscaleError {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("authentication failed: {0}")]
    Auth(String),

    #[error("control plane error: {0}")]
    Control(String),

    #[error("WireGuard tunnel error: {0}")]
    WireGuard(String),

    #[error("network stack error: {0}")]
    Network(String),

    #[error("DERP relay error: {0}")]
    Derp(String),

    #[error("connection error: {0}")]
    Connection(String),

    #[error("key error: {0}")]
    Key(String),

    #[error("state persistence error: {0}")]
    State(String),

    #[error("DNS resolution error: {0}")]
    Dns(String),

    #[error("timeout: {0}")]
    Timeout(String),

    #[error("peer not found: {0}")]
    PeerNotFound(String),

    #[error("not started: call start() before using this method")]
    NotStarted,

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Http(#[from] reqwest::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, TailscaleError>;
