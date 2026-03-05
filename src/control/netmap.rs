use serde::Deserialize;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// A simple IP network (address + prefix length).
#[derive(Debug, Clone)]
pub struct IpNet {
    pub addr: IpAddr,
    pub prefix_len: u8,
}

impl<'de> Deserialize<'de> for IpNet {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let (addr_str, prefix_str) = s
            .split_once('/')
            .ok_or_else(|| serde::de::Error::custom("expected CIDR notation (e.g. 10.0.0.1/32)"))?;
        let addr: IpAddr = addr_str
            .parse()
            .map_err(serde::de::Error::custom)?;
        let prefix_len: u8 = prefix_str
            .parse()
            .map_err(serde::de::Error::custom)?;
        Ok(IpNet { addr, prefix_len })
    }
}

/// The full network map received from the control server.
#[derive(Debug, Clone)]
pub struct NetworkMap {
    pub self_node: SelfNode,
    pub peers: Vec<PeerInfo>,
    pub derp_map: DerpMap,
}

/// This node's own information.
#[derive(Debug, Clone)]
pub struct SelfNode {
    pub ipv4: Ipv4Addr,
    pub ipv6: Ipv6Addr,
    pub fqdn: String,
    pub node_key: [u8; 32],
}

/// Information about a peer on the tailnet.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub node_key: [u8; 32],
    pub disco_key: [u8; 32],
    pub endpoints: Vec<SocketAddr>,
    pub derp_region: u16,
    pub allowed_ips: Vec<IpNet>,
}

/// Map of DERP relay regions.
#[derive(Debug, Clone)]
pub struct DerpMap {
    pub regions: Vec<DerpRegion>,
}

/// A single DERP relay region.
#[derive(Debug, Clone)]
pub struct DerpRegion {
    pub id: u16,
    pub url: String,
}

// --- Wire format types for JSON deserialization ---

#[derive(Deserialize)]
struct WireNetworkMap {
    #[serde(rename = "Node")]
    node: Option<WireNode>,
    #[serde(rename = "Peers")]
    peers: Option<Vec<WirePeer>>,
    #[serde(rename = "DERPMap")]
    derp_map: Option<WireDerpMap>,
}

#[derive(Deserialize)]
struct WireNode {
    #[serde(rename = "Addresses")]
    addresses: Option<Vec<String>>,
    #[serde(rename = "Name")]
    name: Option<String>,
    #[serde(rename = "Key")]
    key: Option<String>,
}

#[derive(Deserialize)]
struct WirePeer {
    #[serde(rename = "Key")]
    key: Option<String>,
    #[serde(rename = "DiscoKey")]
    disco_key: Option<String>,
    #[serde(rename = "Endpoints")]
    endpoints: Option<Vec<String>>,
    #[serde(rename = "DERP")]
    derp: Option<String>,
    #[serde(rename = "AllowedIPs")]
    allowed_ips: Option<Vec<IpNet>>,
}

#[derive(Deserialize)]
struct WireDerpMap {
    #[serde(rename = "Regions")]
    regions: Option<std::collections::HashMap<String, WireDerpRegion>>,
}

#[derive(Deserialize)]
struct WireDerpRegion {
    #[serde(rename = "RegionID")]
    region_id: Option<u16>,
    #[serde(rename = "RegionCode")]
    region_code: Option<String>,
    // We store the first node's hostname as the URL
    #[serde(rename = "Nodes")]
    nodes: Option<Vec<WireDerpNode>>,
}

#[derive(Deserialize)]
struct WireDerpNode {
    #[serde(rename = "HostName")]
    host_name: Option<String>,
}

use crate::error::{Result, TailscaleError};

/// Parse a network map from the control server's JSON response.
pub fn parse_network_map(data: &[u8]) -> Result<NetworkMap> {
    let wire: WireNetworkMap =
        serde_json::from_slice(data).map_err(|e| TailscaleError::Control(format!("failed to parse netmap: {e}")))?;

    let wire_node = wire
        .node
        .ok_or_else(|| TailscaleError::Control("netmap missing Node".into()))?;

    let self_node = parse_self_node(&wire_node)?;

    let peers = wire
        .peers
        .unwrap_or_default()
        .into_iter()
        .map(parse_peer)
        .collect::<Result<Vec<_>>>()?;

    let derp_map = parse_derp_map(wire.derp_map);

    Ok(NetworkMap {
        self_node,
        peers,
        derp_map,
    })
}

fn parse_self_node(node: &WireNode) -> Result<SelfNode> {
    let addresses = node.addresses.as_deref().unwrap_or(&[]);
    let mut ipv4 = Ipv4Addr::UNSPECIFIED;
    let mut ipv6 = Ipv6Addr::UNSPECIFIED;

    for addr_str in addresses {
        // Addresses come as CIDR, strip the prefix
        let ip_str = addr_str.split('/').next().unwrap_or(addr_str);
        if let Ok(v4) = ip_str.parse::<Ipv4Addr>() {
            ipv4 = v4;
        } else if let Ok(v6) = ip_str.parse::<Ipv6Addr>() {
            ipv6 = v6;
        }
    }

    let node_key = parse_key_bytes(node.key.as_deref().unwrap_or(""))?;

    Ok(SelfNode {
        ipv4,
        ipv6,
        fqdn: node.name.clone().unwrap_or_default(),
        node_key,
    })
}

fn parse_peer(peer: WirePeer) -> Result<PeerInfo> {
    let node_key = parse_key_bytes(peer.key.as_deref().unwrap_or(""))?;
    let disco_key = parse_key_bytes(peer.disco_key.as_deref().unwrap_or(""))
        .unwrap_or([0u8; 32]);

    let endpoints = peer
        .endpoints
        .unwrap_or_default()
        .iter()
        .filter_map(|s| s.parse::<SocketAddr>().ok())
        .collect();

    // DERP region is encoded as "127.3.3.40:N" where N is the region ID
    let derp_region = peer
        .derp
        .as_deref()
        .and_then(|s| s.rsplit(':').next())
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(0);

    Ok(PeerInfo {
        node_key,
        disco_key,
        endpoints,
        derp_region,
        allowed_ips: peer.allowed_ips.unwrap_or_default(),
    })
}

fn parse_derp_map(wire: Option<WireDerpMap>) -> DerpMap {
    let regions = wire
        .and_then(|m| m.regions)
        .map(|regions| {
            regions
                .into_values()
                .map(|r| {
                    let url = r
                        .nodes
                        .and_then(|nodes| nodes.into_iter().next())
                        .and_then(|n| n.host_name)
                        .map(|h| format!("https://{h}/derp"))
                        .unwrap_or_default();
                    DerpRegion {
                        id: r.region_id.unwrap_or(0),
                        url,
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    DerpMap { regions }
}

fn parse_key_bytes(s: &str) -> Result<[u8; 32]> {
    if s.is_empty() {
        return Ok([0u8; 32]);
    }
    let (_prefix, bytes) = crate::keys::parse_key(s)?;
    Ok(bytes)
}
