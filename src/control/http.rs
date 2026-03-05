use crate::error::{Result, TailscaleError};
use crate::keys::MachineKey;
use bytes::Bytes;

use super::stream::NoiseStream;

/// HTTP/2 transport layer for control plane communication over a Noise session.
///
/// After the Noise handshake completes, this wraps the encrypted stream
/// in an h2 client and sends HTTP/2 requests through it.
pub struct ControlHttp {
    base_url: String,
    sender: h2::client::SendRequest<Bytes>,
    /// Background h2 connection driver task
    _conn_handle: tokio::task::JoinHandle<()>,
}

impl ControlHttp {
    /// Create a new ControlHttp by performing the Noise handshake and
    /// establishing an HTTP/2 connection over the encrypted stream.
    pub async fn connect(
        base_url: String,
        machine_key: &MachineKey,
        http_client: &reqwest::Client,
    ) -> Result<Self> {
        // Perform the Noise IK handshake (includes key fetch + HTTP upgrade)
        let (session, tls_stream) =
            super::noise::perform_handshake(machine_key, &base_url, http_client).await?;

        // Wrap in NoiseStream for transparent encrypt/decrypt
        let noise_stream = NoiseStream::new(tls_stream, session);

        // Establish HTTP/2 connection over the Noise stream
        let (sender, conn) = h2::client::handshake(noise_stream)
            .await
            .map_err(|e| TailscaleError::Control(format!("h2 handshake failed: {e}")))?;

        // Spawn the h2 connection driver
        let conn_handle = tokio::spawn(async move {
            if let Err(e) = conn.await {
                tracing::warn!("h2 connection error: {e}");
            }
        });

        tracing::info!("HTTP/2 over Noise connection established");

        Ok(Self {
            base_url,
            sender,
            _conn_handle: conn_handle,
        })
    }

    /// Send a POST request through the HTTP/2-over-Noise connection.
    ///
    /// The encryption is handled transparently by the NoiseStream layer.
    pub async fn post_request(&mut self, endpoint: &str, body: &[u8]) -> Result<Vec<u8>> {
        tracing::debug!("control POST {} ({} bytes)", endpoint, body.len());

        // Build the HTTP/2 request
        let request = http::Request::builder()
            .method("POST")
            .uri(endpoint)
            .header("content-type", "application/json")
            .body(())
            .map_err(|e| TailscaleError::Control(format!("failed to build request: {e}")))?;

        // Send request headers
        let (response_future, mut send_stream) = self
            .sender
            .send_request(request, false)
            .map_err(|e| TailscaleError::Control(format!("h2 send_request failed: {e}")))?;

        // Send request body
        send_stream
            .send_data(Bytes::copy_from_slice(body), true)
            .map_err(|e| TailscaleError::Control(format!("h2 send_data failed: {e}")))?;

        // Await response headers
        let response = response_future
            .await
            .map_err(|e| TailscaleError::Control(format!("h2 response error: {e}")))?;

        let status = response.status();
        tracing::debug!("control response: HTTP {}", status);

        // Read response body
        let mut body_stream = response.into_body();
        let mut response_bytes = Vec::new();

        while let Some(chunk) = body_stream
            .data()
            .await
        {
            let chunk = chunk
                .map_err(|e| TailscaleError::Control(format!("h2 body read error: {e}")))?;
            response_bytes.extend_from_slice(&chunk);

            // Release flow control capacity
            let _ = body_stream.flow_control().release_capacity(chunk.len());
        }

        if !status.is_success() {
            return Err(TailscaleError::Control(format!(
                "control server returned HTTP {}: {}",
                status,
                String::from_utf8_lossy(&response_bytes)
            )));
        }

        Ok(response_bytes)
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }
}
