use std::net::IpAddr;

use boringtun::noise::{Tunn, TunnResult};
use x25519_dalek::StaticSecret;

use crate::control::netmap::{IpNet, PeerInfo};
use crate::error::Result;

/// Per-peer WireGuard state wrapping a boringtun tunnel.
pub struct WgPeer {
    pub node_key: [u8; 32],
    pub endpoint: Option<std::net::SocketAddr>,
    pub allowed_ips: Vec<IpNet>,
    tunn: Tunn,
}

impl WgPeer {
    /// Create a new peer from our private key and the peer's info.
    /// `index` should be a unique value to distinguish this peer's sessions.
    pub fn new(private_key: &StaticSecret, peer_info: &PeerInfo, index: u32) -> Result<Self> {
        let peer_public = x25519_dalek::PublicKey::from(peer_info.node_key);

        // Clone the private key by round-tripping through bytes
        let private_clone = StaticSecret::from(private_key.to_bytes());

        let tunn = Tunn::new(
            private_clone,
            peer_public,
            None,  // no preshared key
            None,  // no persistent keepalive
            index,
            None,  // no custom rate limiter
        );

        let endpoint = peer_info.endpoints.first().copied();

        Ok(WgPeer {
            node_key: peer_info.node_key,
            endpoint,
            allowed_ips: peer_info.allowed_ips.clone(),
            tunn,
        })
    }

    /// Encrypt (encapsulate) an IP packet for sending to this peer.
    /// `dst` must be at least `src.len() + 32` bytes and no less than 148 bytes.
    pub fn encrypt<'a>(&mut self, src: &[u8], dst: &'a mut [u8]) -> Result<TunnResult<'a>> {
        Ok(self.tunn.encapsulate(src, dst))
    }

    /// Decrypt (decapsulate) a UDP datagram received from this peer.
    /// `dst` should be large enough to hold the decrypted IP packet.
    pub fn decrypt<'a>(&mut self, src: &[u8], dst: &'a mut [u8]) -> Result<TunnResult<'a>> {
        Ok(self.tunn.decapsulate(None, src, dst))
    }

    /// Check whether the given IP address falls within this peer's allowed IPs.
    pub fn matches_ip(&self, addr: &IpAddr) -> bool {
        for net in &self.allowed_ips {
            if ip_in_net(addr, net) {
                return true;
            }
        }
        false
    }
}

/// Check if an IP address is within a CIDR network.
fn ip_in_net(addr: &IpAddr, net: &IpNet) -> bool {
    match (addr, &net.addr) {
        (IpAddr::V4(a), IpAddr::V4(n)) => {
            if net.prefix_len == 0 {
                return true;
            }
            if net.prefix_len >= 32 {
                return a == n;
            }
            let mask = u32::MAX << (32 - net.prefix_len);
            (u32::from(*a) & mask) == (u32::from(*n) & mask)
        }
        (IpAddr::V6(a), IpAddr::V6(n)) => {
            if net.prefix_len == 0 {
                return true;
            }
            if net.prefix_len >= 128 {
                return a == n;
            }
            let a_bits = u128::from(*a);
            let n_bits = u128::from(*n);
            let mask = u128::MAX << (128 - net.prefix_len);
            (a_bits & mask) == (n_bits & mask)
        }
        _ => false,
    }
}
