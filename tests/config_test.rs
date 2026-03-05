use rust_tailscale::{TailscaleConfig, TailscaleError};

#[test]
fn test_config_builder_valid() {
    let config = TailscaleConfig::builder()
        .hostname("my-app")
        .auth_key("tskey-auth-test123")
        .ephemeral(true)
        .build();

    assert!(config.is_ok());
    let config = config.unwrap();
    assert_eq!(config.hostname(), "my-app");
    assert_eq!(
        config.control_url(),
        "https://controlplane.tailscale.com"
    );
}

#[test]
fn test_config_builder_custom_control_url() {
    let config = TailscaleConfig::builder()
        .hostname("my-app")
        .auth_key("tskey-auth-test123")
        .control_url("https://headscale.example.com")
        .build()
        .unwrap();

    assert_eq!(config.control_url(), "https://headscale.example.com");
}

#[test]
fn test_config_builder_missing_hostname() {
    let result = TailscaleConfig::builder()
        .auth_key("tskey-auth-test123")
        .build();

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, TailscaleError::Config(_)));
}

#[test]
fn test_config_builder_missing_auth_key() {
    let result = TailscaleConfig::builder()
        .hostname("my-app")
        .build();

    assert!(result.is_err());
}

#[test]
fn test_config_builder_empty_hostname() {
    let result = TailscaleConfig::builder()
        .hostname("")
        .auth_key("tskey-auth-test123")
        .build();

    assert!(result.is_err());
}

#[test]
fn test_config_builder_empty_auth_key() {
    let result = TailscaleConfig::builder()
        .hostname("my-app")
        .auth_key("")
        .build();

    assert!(result.is_err());
}
