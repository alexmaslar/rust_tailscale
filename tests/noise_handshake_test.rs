/// Test the Noise handshake + HTTP/2 transport against a real Tailscale control server.
/// Run with: TS_AUTHKEY=tskey-auth-... cargo test --test noise_handshake_test -- --ignored --nocapture
use rust_tailscale::keys::MachineKey;

#[tokio::test]
#[ignore = "requires TS_AUTHKEY environment variable and network access"]
async fn test_noise_h2_connection() {
    // Install rustls crypto provider
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    tracing_subscriber::fmt()
        .with_env_filter("info")
        .init();

    let machine_key = MachineKey::generate();
    let http_client = reqwest::Client::new();
    let control_url = "https://controlplane.tailscale.com".to_string();

    // This tests the full flow: key fetch → Noise IK handshake → HTTP/2 over Noise
    let result = rust_tailscale::control::ControlHttp::connect(
        control_url,
        &machine_key,
        &http_client,
    )
    .await;

    match result {
        Ok(http) => {
            tracing::info!(base_url = %http.base_url(), "HTTP/2 over Noise connection established!");
        }
        Err(e) => {
            panic!("Failed to establish HTTP/2 over Noise connection: {e}");
        }
    }
}
