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
