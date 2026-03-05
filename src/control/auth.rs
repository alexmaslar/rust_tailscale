use crate::error::{Result, TailscaleError};
use serde::{Deserialize, Serialize};

use super::noise::NoiseSession;

/// Request to register this node with the control server using a pre-auth key.
#[derive(Debug, Clone, Serialize)]
pub struct RegisterRequest {
    pub auth_key: String,
    pub hostname: String,
    pub node_key: String, // "nodekey:base64"
    pub ephemeral: bool,
}

/// Response from a successful registration.
#[derive(Debug, Clone, Deserialize)]
pub struct RegisterResponse {
    #[serde(rename = "NodeID", default)]
    pub node_id: String,
    #[serde(rename = "UserID", default)]
    pub user_id: u64,
    #[serde(rename = "LoginName", default)]
    pub login_name: String,
}

/// Register this node with the control server using a pre-auth key.
///
/// Sends the registration request through the established Noise session
/// and parses the response.
///
/// TODO: The actual Tailscale registration protocol involves:
/// 1. Sending a MapRequest with the auth key to /machine/register
/// 2. The server validates the auth key and assigns addresses
/// 3. The response includes the initial network map
pub async fn register(
    session: &mut NoiseSession,
    req: RegisterRequest,
) -> Result<RegisterResponse> {
    tracing::info!(
        hostname = %req.hostname,
        ephemeral = req.ephemeral,
        "registering node with control server"
    );

    let body = serde_json::to_vec(&req)
        .map_err(|e| TailscaleError::Control(format!("failed to serialize register request: {e}")))?;

    // TODO: Send via the Noise session to /machine/register
    // For now, encrypt to validate the session works, but we cannot
    // actually send without the HTTP transport being fully implemented.
    let _encrypted = session.encrypt(&body)?;

    // TODO: Read and decrypt the response from the control server
    // let response_bytes = session.decrypt(&response_encrypted)?;
    // let response: RegisterResponse = serde_json::from_slice(&response_bytes)?;

    Err(TailscaleError::Control(
        "registration not yet implemented: requires complete HTTP transport".into(),
    ))
}
