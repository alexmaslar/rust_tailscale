use crate::error::{Result, TailscaleError};
use crate::keys::MachineKey;
use snow::TransportState;

/// An established Noise IK session for communicating with the control plane.
pub struct NoiseSession {
    transport: TransportState,
}

/// Tailscale control plane's well-known static public key.
/// This is the key for controlplane.tailscale.com (ts2021 protocol).
/// TODO: Verify this is the correct key; this is a placeholder derived from
/// Tailscale's public documentation and source code.
const CONTROL_PLANE_PUBLIC_KEY: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
]; // TODO: Replace with actual Tailscale control plane public key

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

/// Perform the Noise IK handshake with the control server.
///
/// This upgrades an HTTP connection at the /ts2021 endpoint to a Noise
/// transport. The machine key serves as the initiator's static key.
///
/// TODO: This is a stub. The real implementation needs to:
/// 1. POST to {control_url}/ts2021 with upgrade headers
/// 2. Send handshake message 1 (-> e, es, s, ss)
/// 3. Receive handshake message 2 (<- e, ee, se)
/// 4. Transition to transport mode
pub async fn perform_handshake(
    machine_key: &MachineKey,
    control_url: &str,
    _http_client: &reqwest::Client,
) -> Result<NoiseSession> {
    tracing::info!("initiating Noise IK handshake with control server");

    // TODO: The actual Tailscale ts2021 protocol fetches the server's key
    // from /key?v=... before initiating the handshake. For now we use the
    // placeholder constant.
    let server_key = &CONTROL_PLANE_PUBLIC_KEY;

    let mut handshake = build_initiator(machine_key, server_key)?;

    // Step 1: Build initiator message (-> e, es, s, ss)
    let mut msg1 = vec![0u8; 96]; // 32 (e) + 32 (encrypted s) + 16 (tag) + padding
    let msg1_len = handshake
        .write_message(&[], &mut msg1)
        .map_err(|e| TailscaleError::Control(format!("handshake write failed: {e}")))?;
    msg1.truncate(msg1_len);

    // TODO: Send msg1 to the control server via HTTP upgrade at /ts2021
    // and read back the server's response message.
    //
    // The actual flow:
    //   POST {control_url}/ts2021
    //   Upgrade: tailscale-control-protocol
    //   Content-Type: application/octet-stream
    //   Body: msg1
    //
    //   Response: 101 Switching Protocols with msg2 in body
    //
    // For now, return an error since we cannot complete the handshake
    // without a real server connection.
    tracing::warn!(
        "Noise handshake stub: cannot complete without server connection to {}",
        control_url
    );

    // Step 2: Would read server response and process it
    // let msg2 = ... ; // read from server
    // let mut payload = vec![0u8; 64];
    // handshake.read_message(&msg2, &mut payload)?;

    // Step 3: Transition to transport mode
    // let transport = handshake.into_transport_mode()?;

    Err(TailscaleError::Control(
        "Noise handshake not yet implemented: requires real HTTP upgrade connection".into(),
    ))
}

/// Return the control plane's expected public key.
pub fn control_plane_public_key() -> &'static [u8; 32] {
    &CONTROL_PLANE_PUBLIC_KEY
}
