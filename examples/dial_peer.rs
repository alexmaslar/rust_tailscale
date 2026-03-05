use rust_tailscale::{TailscaleConfig, TailscaleServer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let peer_addr = std::env::args()
        .nth(1)
        .expect("Usage: dial_peer <peer-fqdn:port>");

    let config = TailscaleConfig::builder()
        .hostname("dial-client")
        .auth_key(std::env::var("TS_AUTHKEY").expect("TS_AUTHKEY must be set"))
        .ephemeral(true)
        .build()?;

    let server = TailscaleServer::new(config);
    server.start().await?;

    println!("Connecting to {peer_addr}...");
    let mut stream = server.dial_tcp(&peer_addr).await?;
    println!("Connected!");

    // Send a test message
    let msg = b"Hello from rust_tailscale!\n";
    stream.write_all(msg).await?;
    println!("Sent: {}", String::from_utf8_lossy(msg).trim());

    // Read echo response
    let mut buf = vec![0u8; 4096];
    let n = stream.read(&mut buf).await?;
    println!("Received: {}", String::from_utf8_lossy(&buf[..n]).trim());

    Ok(())
}
