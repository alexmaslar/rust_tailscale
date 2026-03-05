use crate::error::Result;
use crate::stream::TailscaleStream;
use std::net::SocketAddr;
use tokio::sync::mpsc;

/// Accepts incoming TCP connections on the tailnet.
/// Analogous to `tokio::net::TcpListener`.
pub struct TailscaleListener {
    pub(crate) incoming: mpsc::Receiver<(TailscaleStream, SocketAddr)>,
    pub(crate) local_port: u16,
}

impl TailscaleListener {
    /// Accept the next incoming connection.
    /// Returns the stream and the peer's address.
    pub async fn accept(&mut self) -> Result<(TailscaleStream, SocketAddr)> {
        self.incoming
            .recv()
            .await
            .ok_or_else(|| crate::error::TailscaleError::Connection("listener closed".into()))
    }

    /// The local port this listener is bound to.
    pub fn local_port(&self) -> u16 {
        self.local_port
    }
}

#[cfg(feature = "axum")]
impl axum::serve::Listener for TailscaleListener {
    type Io = TailscaleStream;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            match self.incoming.recv().await {
                Some((stream, addr)) => return (stream, addr),
                None => {
                    // Channel closed — sleep briefly and retry to avoid busy-spinning.
                    // In practice this means the tailnet stack shut down.
                    tracing::warn!("tailscale listener channel closed, retrying...");
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Ok(SocketAddr::new(
            std::net::Ipv4Addr::UNSPECIFIED.into(),
            self.local_port,
        ))
    }
}
