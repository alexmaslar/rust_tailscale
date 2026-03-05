pub mod auth;
pub mod http;
pub mod netmap;
pub mod noise;
pub mod stream;

pub use auth::{RegisterRequest, RegisterResponse};
pub use http::ControlHttp;
pub use netmap::{DerpMap, DerpRegion, IpNet, NetworkMap, PeerInfo, SelfNode};
pub use noise::NoiseSession;
pub use stream::NoiseStream;

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
    /// 1. Noise IK handshake to establish an encrypted channel (HTTP/2 over Noise)
    /// 2. Register this node using the configured pre-auth key
    /// 3. Send a map request to receive the network map
    pub async fn authenticate(&mut self) -> Result<NetworkMap> {
        tracing::info!(
            control_url = %self.config.control_url(),
            hostname = %self.config.hostname(),
            "authenticating with control server"
        );

        // Step 1: Establish HTTP/2-over-Noise connection
        let mut control_http = ControlHttp::connect(
            self.config.control_url().to_string(),
            &self.machine_key,
            &self.http_client,
        )
        .await?;

        // Step 2: Register with pre-auth key
        let reg_req = auth::build_register_request(
            &self.node_key.public_key_string(),
            &self.config.auth_key,
            &self.config.hostname,
            self.config.ephemeral,
        );

        let _reg_response = auth::register(&mut control_http, reg_req).await?;

        // Step 3: Get the network map
        // The registration response may include the node info directly.
        // If so, we still need to send a MapRequest to get the full network map
        // (peers, DERP map, etc.)
        let map_request = serde_json::json!({
            "Version": 68,
            "Stream": false,
            "NodeKey": self.node_key.public_key_string(),
        });

        let map_body = serde_json::to_vec(&map_request)
            .map_err(|e| TailscaleError::Control(format!("failed to serialize map request: {e}")))?;

        let map_response_bytes = control_http
            .post_request("/machine/map", &map_body)
            .await?;

        let network_map = netmap::parse_network_map(&map_response_bytes)?;

        tracing::info!(
            ipv4 = %network_map.self_node.ipv4,
            fqdn = %network_map.self_node.fqdn,
            peers = network_map.peers.len(),
            "received network map"
        );

        Ok(network_map)
    }
}
