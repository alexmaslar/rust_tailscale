use std::sync::Arc;

use bytes::BytesMut;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

use crate::error::{Result, TailscaleError};

use super::frame::DerpFrame;

pub struct DerpClient {
    node_key: [u8; 32],
    stream: Option<TlsStream<TcpStream>>,
    url: String,
}

impl DerpClient {
    pub fn new(node_key: [u8; 32], url: String) -> Self {
        Self {
            node_key,
            stream: None,
            url,
        }
    }

    /// Connect to the DERP server via TLS, perform HTTP upgrade, and exchange
    /// ServerKey/ClientInfo frames.
    pub async fn connect(&mut self) -> Result<()> {
        let parsed = url::Url::parse(&self.url)
            .map_err(|e| TailscaleError::Derp(format!("invalid DERP URL: {}", e)))?;

        let host = parsed
            .host_str()
            .ok_or_else(|| TailscaleError::Derp("missing host in DERP URL".into()))?
            .to_string();

        let port = parsed.port().unwrap_or(443);

        tracing::info!(host = %host, port = port, "connecting to DERP server");

        // Establish TCP connection
        let tcp_stream = TcpStream::connect(format!("{}:{}", host, port)).await?;

        // Set up TLS
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let connector = TlsConnector::from(Arc::new(tls_config));
        let server_name = rustls::pki_types::ServerName::try_from(host.clone())
            .map_err(|e| TailscaleError::Derp(format!("invalid server name: {}", e)))?;

        let mut tls_stream = connector.connect(server_name, tcp_stream).await
            .map_err(|e| TailscaleError::Derp(format!("TLS handshake failed: {}", e)))?;

        tracing::debug!("TLS connection established");

        // Send HTTP upgrade request
        let upgrade_request = format!(
            "GET /derp HTTP/1.1\r\nHost: {}\r\nUpgrade: DERP\r\nConnection: Upgrade\r\n\r\n",
            host
        );
        tls_stream.write_all(upgrade_request.as_bytes()).await?;

        // Read HTTP response
        let mut response_buf = BytesMut::with_capacity(1024);
        loop {
            let n = tls_stream.read_buf(&mut response_buf).await?;
            if n == 0 {
                return Err(TailscaleError::Derp(
                    "connection closed during HTTP upgrade".into(),
                ));
            }
            // Check if we've received the full HTTP response
            if let Some(pos) = find_header_end(&response_buf) {
                let response_line = String::from_utf8_lossy(&response_buf[..pos]);
                if !response_line.contains("101") {
                    return Err(TailscaleError::Derp(format!(
                        "DERP server rejected upgrade: {}",
                        response_line.lines().next().unwrap_or("unknown")
                    )));
                }
                tracing::debug!("HTTP upgrade to DERP protocol successful");
                // Discard the HTTP response headers; keep any remaining data
                let _remaining = response_buf.split_off(pos);
                break;
            }
        }

        self.stream = Some(tls_stream);

        // Read ServerKey frame
        let server_key_frame = self.recv().await?;
        match &server_key_frame {
            DerpFrame::ServerKey { key } => {
                tracing::info!("received DERP server key: {:02x?}", &key[..8]);
            }
            other => {
                return Err(TailscaleError::Derp(format!(
                    "expected ServerKey frame, got {:?}",
                    other.frame_type()
                )));
            }
        }

        // Send ClientInfo frame
        let client_info = DerpFrame::ClientInfo {
            client_public_key: self.node_key,
            info: serde_json::to_vec(&serde_json::json!({
                "version": 2,
            }))
            .unwrap_or_default(),
        };
        self.send_frame(&client_info).await?;

        tracing::info!("DERP connection established");

        Ok(())
    }

    /// Send a packet to a peer through the DERP relay.
    pub async fn send(&mut self, dst_key: [u8; 32], payload: Vec<u8>) -> Result<()> {
        let frame = DerpFrame::SendPacket { dst_key, payload };
        self.send_frame(&frame).await
    }

    /// Receive the next frame from the DERP server.
    pub async fn recv(&mut self) -> Result<DerpFrame> {
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| TailscaleError::Derp("not connected".into()))?;

        let mut header = [0u8; 5];
        stream.read_exact(&mut header).await?;

        let payload_len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;

        let mut frame_buf = Vec::with_capacity(5 + payload_len);
        frame_buf.extend_from_slice(&header);

        if payload_len > 0 {
            let mut payload = vec![0u8; payload_len];
            stream.read_exact(&mut payload).await?;
            frame_buf.extend_from_slice(&payload);
        }

        let (frame, _) = DerpFrame::decode(&frame_buf)?;
        Ok(frame)
    }

    /// Send a keepalive frame.
    pub async fn keepalive(&mut self) -> Result<()> {
        let frame = DerpFrame::KeepAlive;
        self.send_frame(&frame).await
    }

    async fn send_frame(&mut self, frame: &DerpFrame) -> Result<()> {
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| TailscaleError::Derp("not connected".into()))?;

        let encoded = frame.encode();
        stream.write_all(&encoded).await?;
        stream.flush().await?;
        Ok(())
    }
}

/// Find the end of HTTP headers (\r\n\r\n) in a buffer, returning the position
/// after the delimiter.
fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
}
