use crate::error::{Result, TailscaleError};
use serde::{Deserialize, Serialize};

use super::http::ControlHttp;

/// Request to register this node with the control server.
///
/// Matches Tailscale's `tailcfg.RegisterRequest` wire format.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct RegisterRequest {
    /// Client capability version (required by control server)
    pub version: u64,
    /// Node's WireGuard public key
    pub node_key: String,
    /// Previous node key (empty for first registration)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_node_key: Option<String>,
    /// Pre-auth key for automatic registration
    pub auth: AuthInfo,
    /// Host information
    pub hostinfo: HostInfo,
    /// Whether this node is ephemeral
    pub ephemeral: bool,
}

/// Auth information for registration.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct AuthInfo {
    /// Pre-auth key (tskey-auth-...)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_key: Option<String>,
}

/// Host information sent during registration.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct HostInfo {
    pub hostname: String,
    #[serde(rename = "OS")]
    pub os: String,
    #[serde(rename = "GoArch")]
    pub go_arch: String,
}

/// Response from a successful registration.
///
/// This is a subset of Tailscale's `tailcfg.RegisterResponse`.
#[derive(Debug, Clone, Deserialize)]
pub struct RegisterResponse {
    /// If set, the client should open this URL for interactive auth
    #[serde(rename = "AuthURL", default)]
    pub auth_url: Option<String>,
    /// The node ID assigned by the control server
    #[serde(rename = "NodeID", default)]
    pub node_id: Option<String>,
    /// The user ID
    #[serde(rename = "UserID", default)]
    pub user_id: Option<u64>,
    /// Login name
    #[serde(rename = "Login", default)]
    pub login: Option<LoginInfo>,
    /// The full network map (included in registration response)
    #[serde(rename = "Node", default)]
    pub node: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LoginInfo {
    #[serde(rename = "LoginName", default)]
    pub login_name: String,
}

/// Capability version we advertise to the control server.
/// This should be kept reasonably current with Tailscale's Go client.
const CAPABILITY_VERSION: u64 = 68;

/// Build a RegisterRequest for pre-auth key registration.
pub fn build_register_request(
    node_key: &str,
    auth_key: &str,
    hostname: &str,
    ephemeral: bool,
) -> RegisterRequest {
    RegisterRequest {
        version: CAPABILITY_VERSION,
        node_key: node_key.to_string(),
        old_node_key: None,
        auth: AuthInfo {
            auth_key: Some(auth_key.to_string()),
        },
        hostinfo: HostInfo {
            hostname: hostname.to_string(),
            os: std::env::consts::OS.to_string(),
            go_arch: std::env::consts::ARCH.to_string(),
        },
        ephemeral,
    }
}

/// Register this node with the control server using a pre-auth key.
///
/// Sends the registration request via HTTP/2 over Noise to `/machine/register`
/// and parses the response.
pub async fn register(
    http: &mut ControlHttp,
    req: RegisterRequest,
) -> Result<RegisterResponse> {
    tracing::info!(
        hostname = %req.hostinfo.hostname,
        ephemeral = req.ephemeral,
        "registering node with control server"
    );

    let body = serde_json::to_vec(&req)
        .map_err(|e| TailscaleError::Control(format!("failed to serialize register request: {e}")))?;

    let response_bytes = http.post_request("/machine/register", &body).await?;

    let response: RegisterResponse = serde_json::from_slice(&response_bytes)
        .map_err(|e| TailscaleError::Control(format!("failed to parse register response: {e}")))?;

    // If the server returns an AuthURL, the auth key wasn't accepted or
    // interactive login is required
    if let Some(ref auth_url) = response.auth_url {
        if !auth_url.is_empty() {
            return Err(TailscaleError::Auth(format!(
                "interactive login required: {auth_url}"
            )));
        }
    }

    tracing::info!(
        node_id = ?response.node_id,
        login = ?response.login.as_ref().map(|l| &l.login_name),
        "registered with control server"
    );

    Ok(response)
}
