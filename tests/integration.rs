/// Integration tests requiring a real Tailscale auth key.
/// Run with: TS_AUTHKEY=tskey-auth-... cargo test --test integration -- --ignored
use rust_tailscale::{TailscaleConfig, TailscaleServer};

#[tokio::test]
#[ignore = "requires TS_AUTHKEY environment variable"]
async fn test_server_start_and_identity() {
    let config = TailscaleConfig::builder()
        .hostname("integration-test")
        .auth_key(std::env::var("TS_AUTHKEY").unwrap())
        .ephemeral(true)
        .build()
        .unwrap();

    let server = TailscaleServer::new(config);
    server.start().await.unwrap();

    let identity = server.identity().await.unwrap();
    assert!(!identity.fqdn.is_empty());
    assert!(!identity.ipv4.is_unspecified());
}

#[tokio::test]
async fn test_server_not_started() {
    let config = TailscaleConfig::builder()
        .hostname("test-node")
        .auth_key("tskey-auth-fake")
        .build()
        .unwrap();

    let server = TailscaleServer::new(config);

    // Should fail because start() was not called
    let result = server.listen_tcp(":8080").await;
    assert!(result.is_err());

    let result = server.dial_tcp("100.64.0.1:80").await;
    assert!(result.is_err());

    let result = server.identity().await;
    assert!(result.is_err());
}
