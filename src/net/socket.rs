use crate::listener::TailscaleListener;
use crate::stream::TailscaleStream;
use std::net::SocketAddr;
use tokio::sync::mpsc;

/// Create a TailscaleStream from a pair of channels.
pub(crate) fn stream_from_channels(
    reader_rx: mpsc::Receiver<Vec<u8>>,
    writer_tx: mpsc::Sender<Vec<u8>>,
    peer_addr: SocketAddr,
) -> TailscaleStream {
    TailscaleStream {
        reader: reader_rx,
        writer: writer_tx,
        peer_addr,
        read_buf: Vec::new(),
        read_pos: 0,
    }
}

/// Create a TailscaleListener backed by a channel that receives accepted connections.
pub(crate) fn listener_from_channel(
    incoming: mpsc::Receiver<(TailscaleStream, SocketAddr)>,
    local_port: u16,
) -> TailscaleListener {
    TailscaleListener {
        incoming,
        local_port,
    }
}
