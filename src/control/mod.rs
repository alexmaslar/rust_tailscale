pub mod auth;
pub mod http;
pub mod netmap;
pub mod noise;

pub use auth::{RegisterRequest, RegisterResponse};
pub use http::ControlHttp;
pub use netmap::{DerpMap, DerpRegion, IpNet, NetworkMap, PeerInfo, SelfNode};
pub use noise::NoiseSession;

use crate::config::TailscaleConfig;
use crate::error::{Result, TailscaleError};
use crate::keys::{MachineKey, NodeKey};

/// Client for communicating with the Tailscale control plane.
///
/// Handles Noise handshake, registration via pre-auth key, and
/// receiving the network map.
pub struct ControlClient {
    config: TailscaleConfig,
    machine_key: MachineKey,
    node_key: NodeKey,
    http_client: reqwest::Client,
}

impl ControlClient {
    /// Create a new control client.
    pub fn new(config: TailscaleConfig, machine_key: MachineKey, node_key: NodeKey) -> Self {
        let http_client = reqwest::Client::new();
        Self {
            config,
            machine_key,
            node_key,
            http_client,
        }
    }

    /// Authenticate with the control server and retrieve the initial network map.
    ///
    /// This performs the following steps:
    /// 1. Noise IK handshake to establish an encrypted channel
    /// 2. Register this node using the configured pre-auth key
    /// 3. Receive and parse the initial network map
    pub async fn authenticate(&mut self) -> Result<NetworkMap> {
        tracing::info!(
            control_url = %self.config.control_url(),
            hostname = %self.config.hostname(),
            "authenticating with control server"
        );

        // Step 1: Establish Noise session
        let mut session = noise::perform_handshake(
            &self.machine_key,
            self.config.control_url(),
            &self.http_client,
        )
        .await?;

        // Step 2: Register with pre-auth key
        let reg_req = RegisterRequest {
            auth_key: self.config.auth_key.clone(),
            hostname: self.config.hostname.clone(),
            node_key: self.node_key.public_key_string(),
            ephemeral: self.config.ephemeral,
        };

        let reg_response = auth::register(&mut session, reg_req).await?;
        tracing::info!(
            node_id = %reg_response.node_id,
            login = %reg_response.login_name,
            "registered with control server"
        );

        // Step 3: The registration response typically includes the initial
        // network map. In a full implementation we would parse it here.
        // TODO: Parse the network map from the registration/map response
        Err(TailscaleError::Control(
            "authenticate not yet fully implemented".into(),
        ))
    }
}
