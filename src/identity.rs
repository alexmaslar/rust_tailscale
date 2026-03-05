use std::net::{Ipv4Addr, Ipv6Addr};

/// Identity of this node on the tailnet after joining.
#[derive(Debug, Clone)]
pub struct NodeIdentity {
    pub ipv4: Ipv4Addr,
    pub ipv6: Ipv6Addr,
    pub fqdn: String,
}
