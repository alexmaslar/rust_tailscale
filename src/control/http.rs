use crate::error::{Result, TailscaleError};
use crate::keys::MachineKey;

use super::noise::NoiseSession;

/// HTTP transport layer for control plane communication.
pub struct ControlHttp {
    base_url: String,
    client: reqwest::Client,
}

impl ControlHttp {
    pub fn new(base_url: String, client: reqwest::Client) -> Self {
        Self { base_url, client }
    }

    /// Upgrade an HTTP connection to a Noise session.
    ///
    /// This initiates the ts2021 protocol by connecting to the /ts2021
    /// endpoint and performing the Noise IK handshake.
    pub async fn noise_upgrade(&self, machine_key: &MachineKey) -> Result<NoiseSession> {
        super::noise::perform_handshake(machine_key, &self.base_url, &self.client).await
    }

    /// Send a POST request through an established Noise session.
    ///
    /// The request body is encrypted with the Noise session, sent to the
    /// control server, and the response is decrypted and returned.
    ///
    /// TODO: The real implementation sends framed Noise messages over the
    /// upgraded HTTP connection. This stub encrypts/decrypts but does not
    /// perform actual network I/O since the HTTP upgrade is not yet implemented.
    pub async fn post_request(
        &self,
        session: &mut NoiseSession,
        endpoint: &str,
        body: &[u8],
    ) -> Result<Vec<u8>> {
        tracing::debug!("control POST {} ({} bytes)", endpoint, body.len());

        let encrypted = session.encrypt(body)?;

        // TODO: Send the encrypted payload over the upgraded connection.
        // The ts2021 protocol uses a framing format:
        //   - 2 bytes: frame type
        //   - 4 bytes: payload length (big-endian)
        //   - N bytes: encrypted payload
        //
        // For now, we cannot actually send since the HTTP upgrade is stubbed.
        let _ = encrypted;

        Err(TailscaleError::Control(format!(
            "HTTP transport not yet implemented for endpoint: {endpoint}"
        )))
    }
}

/// Perform a Noise upgrade on an HTTP connection.
///
/// Convenience function that creates a `ControlHttp` and performs the upgrade.
pub async fn noise_upgrade(
    base_url: &str,
    client: &reqwest::Client,
    machine_key: &MachineKey,
) -> Result<NoiseSession> {
    let http = ControlHttp::new(base_url.to_string(), client.clone());
    http.noise_upgrade(machine_key).await
}

/// Send a POST request through an existing Noise session.
///
/// Convenience function wrapping `ControlHttp::post_request`.
pub async fn post_request(
    http: &ControlHttp,
    session: &mut NoiseSession,
    endpoint: &str,
    body: &[u8],
) -> Result<Vec<u8>> {
    http.post_request(session, endpoint, body).await
}
