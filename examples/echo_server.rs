use rust_tailscale::{TailscaleConfig, TailscaleServer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let config = TailscaleConfig::builder()
        .hostname("echo-server")
        .auth_key(std::env::var("TS_AUTHKEY").expect("TS_AUTHKEY must be set"))
        .ephemeral(true)
        .build()?;

    let server = TailscaleServer::new(config);
    server.start().await?;

    let identity = server.identity().await?;
    println!("Echo server running at {}:8080", identity.fqdn);
    println!("  IPv4: {}", identity.ipv4);
    println!("  IPv6: {}", identity.ipv6);

    let mut listener = server.listen_tcp(":8080").await?;

    loop {
        let (mut stream, peer) = listener.accept().await?;
        println!("New connection from {peer}");

        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if let Err(e) = stream.write_all(&buf[..n]).await {
                            eprintln!("Write error: {e}");
                            break;
                        }
                    }
                    Err(e) => {
                        eprintln!("Read error: {e}");
                        break;
                    }
                }
            }
            println!("Connection from {peer} closed");
        });
    }
}
