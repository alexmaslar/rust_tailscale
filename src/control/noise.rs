use crate::error::{Result, TailscaleError};
use crate::keys::MachineKey;
use snow::TransportState;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

/// An established Noise IK session for communicating with the control plane.
pub struct NoiseSession {
    transport: TransportState,
}

impl NoiseSession {
    /// Wrap an already-completed transport state.
    pub(crate) fn from_transport(transport: TransportState) -> Self {
        Self { transport }
    }

    /// Encrypt a message using the Noise session.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; plaintext.len() + 64]; // room for tag
        let len = self
            .transport
            .write_message(plaintext, &mut buf)
            .map_err(|e| TailscaleError::Control(format!("noise encrypt failed: {e}")))?;
        buf.truncate(len);
        Ok(buf)
    }

    /// Decrypt a message using the Noise session.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; ciphertext.len()];
        let len = self
            .transport
            .read_message(ciphertext, &mut buf)
            .map_err(|e| TailscaleError::Control(format!("noise decrypt failed: {e}")))?;
        buf.truncate(len);
        Ok(buf)
    }
}

/// Fetch the control server's Noise public key from /key?v=68.
///
/// Response JSON: `{"LegacyPublicKey":"...","PublicKey":"nodekey:base64..."}`
pub async fn fetch_server_key(
    control_url: &str,
    client: &reqwest::Client,
) -> Result<[u8; 32]> {
    let url = format!("{}/key?v=68", control_url.trim_end_matches('/'));
    tracing::debug!("fetching server noise key from {}", url);

    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| TailscaleError::Control(format!("failed to fetch server key: {e}")))?;

    if !resp.status().is_success() {
        return Err(TailscaleError::Control(format!(
            "server key fetch returned HTTP {}",
            resp.status()
        )));
    }

    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| TailscaleError::Control(format!("failed to parse key response: {e}")))?;

    // The PublicKey field is "nodekey:<base64url>" format
    let key_str = body["PublicKey"]
        .as_str()
        .ok_or_else(|| TailscaleError::Control("key response missing PublicKey field".into()))?;

    let (_prefix, key_bytes) = crate::keys::parse_key(key_str)?;
    tracing::debug!("fetched server noise key");
    Ok(key_bytes)
}

/// Build a snow initiator for the Noise_IK handshake.
///
/// Pattern IK: the initiator knows the responder's static public key.
/// Cipher: ChaChaPoly, DH: 25519, Hash: SHA256
fn build_initiator(
    machine_key: &MachineKey,
    server_public_key: &[u8; 32],
) -> Result<snow::HandshakeState> {
    let params: snow::params::NoiseParams = "Noise_IK_25519_ChaChaPoly_SHA256"
        .parse()
        .map_err(|e| TailscaleError::Control(format!("invalid noise params: {e}")))?;

    let kp = machine_key.key_pair();
    let secret_bytes = kp.secret_bytes();
    let builder = snow::Builder::new(params)
        .local_private_key(&secret_bytes)
        .remote_public_key(server_public_key);

    builder
        .build_initiator()
        .map_err(|e| TailscaleError::Control(format!("failed to build noise initiator: {e}")))
}

/// Perform the Noise IK handshake with the control server via HTTP upgrade.
///
/// Flow:
/// 1. Fetch server's Noise public key from /key?v=68
/// 2. Open TLS connection to control server
/// 3. Send HTTP upgrade: POST /ts2021 with Noise msg1 in body
/// 4. Server responds 101 with Noise msg2 in body
/// 5. Transition to transport mode
///
/// Returns the NoiseSession and the underlying TLS stream for further I/O.
pub async fn perform_handshake(
    machine_key: &MachineKey,
    control_url: &str,
    http_client: &reqwest::Client,
) -> Result<(NoiseSession, TlsStream<TcpStream>)> {
    tracing::info!("initiating Noise IK handshake with control server");

    // Step 1: Fetch server's Noise public key
    let server_key = fetch_server_key(control_url, http_client).await?;

    // Step 2: Build the Noise initiator and generate msg1
    let mut handshake = build_initiator(machine_key, &server_key)?;
    let mut msg1 = vec![0u8; 96];
    let msg1_len = handshake
        .write_message(&[], &mut msg1)
        .map_err(|e| TailscaleError::Control(format!("handshake write failed: {e}")))?;
    msg1.truncate(msg1_len);

    // Step 3: Parse control URL, resolve hostname, open TLS connection
    let parsed = url::Url::parse(control_url)
        .map_err(|e| TailscaleError::Control(format!("invalid control URL: {e}")))?;
    let hostname = parsed
        .host_str()
        .ok_or_else(|| TailscaleError::Control("control URL has no host".into()))?;
    let port = parsed.port().unwrap_or(443);

    // DNS resolve
    let addr = tokio::net::lookup_host(format!("{hostname}:{port}"))
        .await
        .map_err(|e| TailscaleError::Control(format!("DNS resolve failed: {e}")))?
        .next()
        .ok_or_else(|| TailscaleError::Control("DNS returned no addresses".into()))?;

    // TCP connect
    let tcp = TcpStream::connect(addr)
        .await
        .map_err(|e| TailscaleError::Control(format!("TCP connect failed: {e}")))?;

    // TLS handshake
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));
    let server_name = rustls::pki_types::ServerName::try_from(hostname.to_string())
        .map_err(|e| TailscaleError::Control(format!("invalid server name: {e}")))?;
    let mut tls_stream = connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| TailscaleError::Control(format!("TLS connect failed: {e}")))?;

    // Step 4: Send HTTP upgrade request with msg1 as body
    // Tailscale's ts2021 protocol: the machine key is sent as the Upgrade header value
    // to help the server identify which Noise key to use.
    let machine_key_str = machine_key.public_key_string();
    let upgrade_request = format!(
        "POST /ts2021 HTTP/1.1\r\n\
         Host: {hostname}\r\n\
         Upgrade: tailscale-control-protocol\r\n\
         Connection: Upgrade\r\n\
         X-Tailscale-Handshake-Machine-Key: {machine_key_str}\r\n\
         Content-Type: application/octet-stream\r\n\
         Content-Length: {}\r\n\
         \r\n",
        msg1.len()
    );

    tls_stream
        .write_all(upgrade_request.as_bytes())
        .await
        .map_err(|e| TailscaleError::Control(format!("failed to write upgrade request: {e}")))?;
    tls_stream
        .write_all(&msg1)
        .await
        .map_err(|e| TailscaleError::Control(format!("failed to write msg1: {e}")))?;
    tls_stream
        .flush()
        .await
        .map_err(|e| TailscaleError::Control(format!("failed to flush: {e}")))?;

    // Step 5: Read HTTP 101 response
    let mut response_buf = vec![0u8; 4096];
    let mut total_read = 0;
    let header_end;

    loop {
        let n = tls_stream
            .read(&mut response_buf[total_read..])
            .await
            .map_err(|e| TailscaleError::Control(format!("failed to read response: {e}")))?;
        if n == 0 {
            return Err(TailscaleError::Control(
                "connection closed during handshake".into(),
            ));
        }
        total_read += n;

        // Look for end of HTTP headers
        if let Some(pos) = find_header_end(&response_buf[..total_read]) {
            header_end = pos;
            break;
        }

        if total_read >= response_buf.len() {
            return Err(TailscaleError::Control(
                "HTTP response headers too large".into(),
            ));
        }
    }

    // Parse status line
    let headers_str = std::str::from_utf8(&response_buf[..header_end])
        .map_err(|_| TailscaleError::Control("non-UTF8 HTTP response".into()))?;

    let status_line = headers_str
        .lines()
        .next()
        .ok_or_else(|| TailscaleError::Control("empty HTTP response".into()))?;

    if !status_line.contains("101") {
        return Err(TailscaleError::Control(format!(
            "expected HTTP 101, got: {status_line}"
        )));
    }

    tracing::debug!("received HTTP 101 Switching Protocols");

    // Extract Content-Length from response headers (for msg2 body)
    let content_length = parse_content_length(headers_str);

    // The body starts after the header end (\r\n\r\n = 4 bytes)
    let body_start = header_end + 4;
    let mut msg2 = Vec::new();

    // Collect any body bytes already read
    if body_start < total_read {
        msg2.extend_from_slice(&response_buf[body_start..total_read]);
    }

    // Read remaining body bytes if Content-Length tells us we need more
    if let Some(cl) = content_length {
        while msg2.len() < cl {
            let mut tmp = vec![0u8; cl - msg2.len()];
            let n = tls_stream
                .read(&mut tmp)
                .await
                .map_err(|e| TailscaleError::Control(format!("failed to read msg2: {e}")))?;
            if n == 0 {
                break;
            }
            msg2.extend_from_slice(&tmp[..n]);
        }
    } else if msg2.is_empty() {
        // No Content-Length header and no body yet — read a chunk
        // The server should send msg2 (48 bytes for Noise IK responder message)
        let mut tmp = vec![0u8; 256];
        let n = tls_stream
            .read(&mut tmp)
            .await
            .map_err(|e| TailscaleError::Control(format!("failed to read msg2: {e}")))?;
        msg2.extend_from_slice(&tmp[..n]);
    }

    if msg2.is_empty() {
        return Err(TailscaleError::Control(
            "no Noise msg2 in upgrade response".into(),
        ));
    }

    // Step 6: Process msg2 and transition to transport mode
    let mut payload = vec![0u8; 256];
    let payload_len = handshake
        .read_message(&msg2, &mut payload)
        .map_err(|e| TailscaleError::Control(format!("handshake read_message failed: {e}")))?;

    if payload_len > 0 {
        tracing::debug!(
            "handshake payload: {} bytes (protocol version info)",
            payload_len
        );
    }

    let transport = handshake
        .into_transport_mode()
        .map_err(|e| TailscaleError::Control(format!("failed to enter transport mode: {e}")))?;

    tracing::info!("Noise IK handshake complete");

    Ok((NoiseSession::from_transport(transport), tls_stream))
}

/// Find the position of \r\n\r\n in the buffer (returns position of first \r).
fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|w| w == b"\r\n\r\n")
}

/// Parse Content-Length from raw HTTP headers.
fn parse_content_length(headers: &str) -> Option<usize> {
    for line in headers.lines() {
        if let Some(val) = line.strip_prefix("Content-Length:") {
            return val.trim().parse().ok();
        }
        if let Some(val) = line.strip_prefix("content-length:") {
            return val.trim().parse().ok();
        }
    }
    None
}
