use std::collections::HashMap;
use std::sync::Arc;

use base64::Engine;
use boringtun::noise::{Tunn, TunnResult};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use x25519_dalek::StaticSecret;

use super::peer::WgPeer;
use crate::control::netmap::{NetworkMap, PeerInfo};
use crate::error::{Result, TailscaleError};
use crate::keys::NodeKey;

/// WireGuard tunnel managing encrypted peer connections over UDP.
pub struct WgTunnel {
    private_key: StaticSecret,
    udp_socket: Arc<UdpSocket>,
    /// Peers indexed by their node_key.
    peers: Mutex<HashMap<[u8; 32], WgPeer>>,
    /// Decrypted IP packets waiting to be read.
    inbound_buf: Mutex<Vec<Vec<u8>>>,
}

impl WgTunnel {
    /// Create a new WireGuard tunnel.
    ///
    /// Binds a UDP socket and initializes peers from the network map.
    pub async fn new(node_key: &NodeKey, netmap: &NetworkMap) -> Result<Self> {
        let kp = node_key.key_pair();
        let private_key = StaticSecret::from(kp.secret_bytes());

        // Bind to any available port
        let udp_socket = UdpSocket::bind("0.0.0.0:0").await?;
        let udp_socket = Arc::new(udp_socket);

        let mut peers = HashMap::new();
        for (i, peer_info) in netmap.peers.iter().enumerate() {
            match WgPeer::new(&private_key, peer_info, i as u32 + 1) {
                Ok(peer) => {
                    tracing::info!(
                        peer_key = base64::engine::general_purpose::STANDARD.encode(peer_info.node_key),
                        "added WireGuard peer"
                    );
                    peers.insert(peer_info.node_key, peer);
                }
                Err(e) => {
                    tracing::warn!(
                        peer_key = base64::engine::general_purpose::STANDARD.encode(peer_info.node_key),
                        error = %e,
                        "failed to add WireGuard peer, skipping"
                    );
                }
            }
        }

        Ok(WgTunnel {
            private_key,
            udp_socket,
            peers: Mutex::new(peers),
            inbound_buf: Mutex::new(Vec::new()),
        })
    }

    /// Encrypt an IP packet and send it to the correct peer based on
    /// the destination IP address in the packet header.
    pub async fn send_packet(&self, packet: &[u8]) -> Result<()> {
        let dst_ip = Tunn::dst_address(packet).ok_or_else(|| {
            TailscaleError::WireGuard("cannot determine destination IP from packet".into())
        })?;

        let mut peers = self.peers.lock().await;

        // Find the peer whose allowed_ips covers the destination
        let peer = peers
            .values_mut()
            .find(|p| p.matches_ip(&dst_ip))
            .ok_or_else(|| {
                TailscaleError::PeerNotFound(format!("no peer for destination {dst_ip}"))
            })?;

        let endpoint = peer.endpoint.ok_or_else(|| {
            TailscaleError::WireGuard(format!("peer has no endpoint for {dst_ip}"))
        })?;

        let mut dst_buf = vec![0u8; packet.len() + 148];
        match peer.encrypt(packet, &mut dst_buf)? {
            TunnResult::WriteToNetwork(data) => {
                self.udp_socket.send_to(data, endpoint).await?;
                Ok(())
            }
            TunnResult::Err(e) => {
                Err(TailscaleError::WireGuard(format!("encrypt failed: {e:?}")))
            }
            _ => Ok(()),
        }
    }

    /// Receive a UDP datagram, decrypt it, and return the inner IP packet.
    /// Returns `None` if the received datagram did not produce a data packet
    /// (e.g. it was a handshake message).
    pub async fn recv_packet(&self) -> Result<Option<Vec<u8>>> {
        // Check buffered packets first
        {
            let mut buf = self.inbound_buf.lock().await;
            if let Some(pkt) = buf.pop() {
                return Ok(Some(pkt));
            }
        }

        let mut recv_buf = vec![0u8; 65536];
        let (n, src_addr) = self.udp_socket.recv_from(&mut recv_buf).await?;
        let datagram = &recv_buf[..n];

        let mut peers = self.peers.lock().await;

        // Try to find the peer by source address
        let peer = peers.values_mut().find(|p| p.endpoint == Some(src_addr));
        let peer = match peer {
            Some(p) => p,
            None => {
                tracing::debug!(%src_addr, "received packet from unknown source");
                return Ok(None);
            }
        };

        let mut dst_buf = vec![0u8; 65536];
        match peer.decrypt(datagram, &mut dst_buf)? {
            TunnResult::WriteToTunnelV4(data, _addr) => Ok(Some(data.to_vec())),
            TunnResult::WriteToTunnelV6(data, _addr) => Ok(Some(data.to_vec())),
            TunnResult::WriteToNetwork(data) => {
                // Response packet (e.g. handshake response) - send it back
                self.udp_socket.send_to(data, src_addr).await?;
                Ok(None)
            }
            TunnResult::Err(e) => {
                tracing::debug!(?e, "WireGuard decapsulate error");
                Ok(None)
            }
            TunnResult::Done => Ok(None),
        }
    }

    /// Add a new peer to the tunnel.
    pub async fn add_peer(&self, peer_info: &PeerInfo) -> Result<()> {
        let mut peers = self.peers.lock().await;
        let index = peers.len() as u32 + 1;
        let peer = WgPeer::new(&self.private_key, peer_info, index)?;
        peers.insert(peer_info.node_key, peer);
        tracing::info!(
            peer_key = base64::engine::general_purpose::STANDARD.encode(peer_info.node_key),
            "added WireGuard peer"
        );
        Ok(())
    }

    /// Remove a peer from the tunnel by node key.
    pub async fn remove_peer(&self, node_key: &[u8; 32]) {
        let mut peers = self.peers.lock().await;
        if peers.remove(node_key).is_some() {
            tracing::info!(peer_key = base64::engine::general_purpose::STANDARD.encode(node_key), "removed WireGuard peer");
        }
    }
}
