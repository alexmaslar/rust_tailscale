use base64::Engine;
use crate::error::{Result, TailscaleError};
use crate::keys::MachineKey;
use snow::TransportState;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

/// Protocol version sent in the initiationMessage and used in the handshake prologue.
const PROTOCOL_VERSION: u16 = 1;

/// An established Noise IK session for communicating with the control plane.
pub struct NoiseSession {
    transport: TransportState,
    send_nonce: u64,
    recv_nonce: u64,
}

impl NoiseSession {
    /// Wrap an already-completed transport state.
    pub(crate) fn from_transport(transport: TransportState) -> Self {
        Self {
            transport,
            send_nonce: 0,
            recv_nonce: 0,
        }
    }

    /// Encrypt a message using the Noise session.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; plaintext.len() + 64]; // room for tag
        let len = self
            .transport
            .write_message(plaintext, &mut buf)
            .map_err(|e| TailscaleError::Control(format!("noise encrypt failed: {e}")))?;
        self.send_nonce += 1;
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
        self.recv_nonce += 1;
        buf.truncate(len);
        Ok(buf)
    }
}

/// Fetch the control server's Noise public key from /key?v=68.
///
/// Response JSON: `{"publicKey":"mkey:base64...","legacyPublicKey":"mkey:base64..."}`
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

    // Accept both camelCase (current API) and PascalCase (legacy)
    let key_str = body["publicKey"]
        .as_str()
        .or_else(|| body["PublicKey"].as_str())
        .ok_or_else(|| TailscaleError::Control("key response missing publicKey field".into()))?;

    let (_prefix, key_bytes) = crate::keys::parse_key(key_str)?;
    tracing::debug!("fetched server noise key");
    Ok(key_bytes)
}

/// Build a snow initiator for the Noise_IK handshake.
///
/// Pattern IK: the initiator knows the responder's static public key.
/// Cipher: ChaChaPoly, DH: 25519, Hash: BLAKE2s (matches Tailscale's control protocol)
///
/// Uses a custom CryptoResolver with big-endian ChaChaPoly nonce encoding
/// to match Tailscale's `controlbase/conn.go` implementation.
fn build_initiator(
    machine_key: &MachineKey,
    server_public_key: &[u8; 32],
) -> Result<snow::HandshakeState> {
    let params: snow::params::NoiseParams = "Noise_IK_25519_ChaChaPoly_BLAKE2s"
        .parse()
        .map_err(|e| TailscaleError::Control(format!("invalid noise params: {e}")))?;

    // Tailscale mixes a protocol-version prologue into the handshake hash
    // before any standard Noise operations. Both sides must agree on this.
    let prologue = format!("Tailscale Control Protocol v{}", PROTOCOL_VERSION);

    let kp = machine_key.key_pair();
    let secret_bytes = kp.secret_bytes();

    // Use TailscaleResolver for big-endian ChaChaPoly nonces
    let resolver = Box::new(super::resolver::TailscaleResolver::new());
    let builder = snow::Builder::with_resolver(params, resolver)
        .local_private_key(&secret_bytes)
        .remote_public_key(server_public_key)
        .prologue(prologue.as_bytes());

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
    let mut noise_msg1 = vec![0u8; 96];
    let noise_msg1_len = handshake
        .write_message(&[], &mut noise_msg1)
        .map_err(|e| TailscaleError::Control(format!("handshake write failed: {e}")))?;
    noise_msg1.truncate(noise_msg1_len);

    // Wrap in Tailscale's initiationMessage framing (5-byte header + payload):
    //   [0-1] protocol version (uint16 BE) = 1
    //   [2]   message type = 0x01 (initiation)
    //   [3-4] payload length (uint16 BE)
    let payload_len = noise_msg1.len() as u16;
    let mut msg1 = Vec::with_capacity(5 + noise_msg1.len());
    msg1.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    msg1.push(0x01); // msgTypeInitiation
    msg1.extend_from_slice(&payload_len.to_be_bytes());
    msg1.extend_from_slice(&noise_msg1);
    tracing::debug!(
        noise_payload_len = noise_msg1_len,
        framed_len = msg1.len(),
        "built initiationMessage"
    );

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

    // Step 4: Send HTTP upgrade request with msg1 in the X-Tailscale-Handshake header.
    // The Go client sends the Noise init message base64-encoded in this header to
    // save an RTT (the server can start the handshake immediately from the header).
    let handshake_b64 = base64::engine::general_purpose::STANDARD.encode(&msg1);
    let upgrade_request = format!(
        "POST /ts2021 HTTP/1.1\r\n\
         Host: {hostname}\r\n\
         Upgrade: tailscale-control-protocol\r\n\
         Connection: Upgrade\r\n\
         X-Tailscale-Handshake: {handshake_b64}\r\n\
         \r\n"
    );

    tls_stream
        .write_all(upgrade_request.as_bytes())
        .await
        .map_err(|e| TailscaleError::Control(format!("failed to write upgrade request: {e}")))?;
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

    tracing::debug!(
        total_read,
        header_end,
        headers = headers_str,
        "received HTTP 101 Switching Protocols"
    );

    // Extract Content-Length from response headers (for msg2 body)
    let content_length = parse_content_length(headers_str);

    // The body starts after the header end (\r\n\r\n = 4 bytes)
    let body_start = header_end + 4;
    let mut msg2 = Vec::new();

    // Collect any body bytes already read
    if body_start < total_read {
        msg2.extend_from_slice(&response_buf[body_start..total_read]);
    }
    tracing::debug!(
        body_start,
        total_read,
        buffered_msg2_len = msg2.len(),
        content_length = ?content_length,
        "post-101 body state"
    );

    // Read the responseMessage (51 bytes: 3-byte header + 48-byte Noise msg2).
    // The server writes this on the raw connection after the HTTP 101 headers.
    let expected_msg2_len = content_length.unwrap_or(51);
    while msg2.len() < expected_msg2_len {
        let mut tmp = vec![0u8; expected_msg2_len - msg2.len()];
        let n = tls_stream
            .read(&mut tmp)
            .await
            .map_err(|e| TailscaleError::Control(format!("failed to read msg2: {e}")))?;
        tracing::debug!(read_bytes = n, total_msg2 = msg2.len() + n, "reading msg2");
        if n == 0 {
            break;
        }
        msg2.extend_from_slice(&tmp[..n]);
    }

    if msg2.is_empty() {
        return Err(TailscaleError::Control(
            "no Noise msg2 in upgrade response".into(),
        ));
    }
    tracing::debug!(
        msg2_len = msg2.len(),
        msg2_hex = hex::encode(&msg2),
        "received msg2"
    );

    // Step 6: Strip Tailscale's responseMessage framing (3-byte header):
    //   [0]   message type = 0x02 (response)
    //   [1-2] payload length (uint16 BE)
    // Then process the Noise payload and transition to transport mode.
    if msg2.len() < 3 {
        return Err(TailscaleError::Control(format!(
            "msg2 too short: {} bytes",
            msg2.len()
        )));
    }
    let noise_msg2 = &msg2[3..];
    let mut payload = vec![0u8; 256];
    let payload_len = handshake
        .read_message(noise_msg2, &mut payload)
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
