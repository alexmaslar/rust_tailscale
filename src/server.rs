use crate::config::TailscaleConfig;
use crate::control::ControlClient;
use crate::error::{Result, TailscaleError};
use crate::identity::NodeIdentity;
use crate::listener::TailscaleListener;
use crate::net::NetStack;
use crate::state::PersistentState;
use crate::stream::TailscaleStream;
use crate::wg::WgTunnel;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

/// Main entry point for Tailscale networking.
/// Manages the full node lifecycle: authentication, tunneling, and TCP connections.
pub struct TailscaleServer {
    config: TailscaleConfig,
    state: PersistentState,
    identity: RwLock<Option<NodeIdentity>>,
    control: Mutex<Option<ControlClient>>,
    tunnel: Mutex<Option<Arc<WgTunnel>>>,
    net_stack: Mutex<Option<Arc<NetStack>>>,
    started: RwLock<bool>,
}

impl TailscaleServer {
    pub fn new(config: TailscaleConfig) -> Self {
        let state = PersistentState::load_or_create(config.state_dir.as_deref())
            .unwrap_or_else(|_| PersistentState::new());

        Self {
            config,
            state,
            identity: RwLock::new(None),
            control: Mutex::new(None),
            tunnel: Mutex::new(None),
            net_stack: Mutex::new(None),
            started: RwLock::new(false),
        }
    }

    /// Authenticate with the control plane, establish WireGuard tunnels, and start the network stack.
    pub async fn start(&self) -> Result<()> {
        tracing::info!(hostname = %self.config.hostname, "starting Tailscale node");

        // 1. Connect to control plane and authenticate
        let mut control = ControlClient::new(
            self.config.clone(),
            self.state.machine_key.clone(),
            self.state.node_key.clone(),
        );
        let netmap = control.authenticate().await?;
        tracing::info!(
            ipv4 = %netmap.self_node.ipv4,
            ipv6 = %netmap.self_node.ipv6,
            peers = netmap.peers.len(),
            "authenticated with control plane"
        );

        // 2. Set identity
        {
            let mut identity = self.identity.write().await;
            *identity = Some(NodeIdentity {
                ipv4: netmap.self_node.ipv4,
                ipv6: netmap.self_node.ipv6,
                fqdn: netmap.self_node.fqdn.clone(),
            });
        }

        // 3. Set up WireGuard tunnel
        let tunnel: Arc<WgTunnel> = Arc::new(WgTunnel::new(&self.state.node_key, &netmap).await?);

        // 4. Set up userspace TCP/IP stack
        let net_stack = Arc::new(NetStack::new(
            netmap.self_node.ipv4,
            netmap.self_node.ipv6,
            tunnel.clone(),
        )?);

        // 5. Start background tasks (netmap polling, packet routing)
        let tunnel_clone = tunnel.clone();
        let net_stack_clone = net_stack.clone();
        tokio::spawn(async move {
            if let Err(e) = Self::run_packet_loop(tunnel_clone, net_stack_clone).await {
                tracing::error!(error = %e, "packet loop exited");
            }
        });

        // Store components
        *self.control.lock().await = Some(control);
        *self.tunnel.lock().await = Some(tunnel);
        *self.net_stack.lock().await = Some(net_stack);
        *self.started.write().await = true;

        Ok(())
    }

    /// Listen for incoming TCP connections on the given port.
    pub async fn listen_tcp(&self, addr: &str) -> Result<TailscaleListener> {
        if !*self.started.read().await {
            return Err(TailscaleError::NotStarted);
        }

        let port = parse_port(addr)?;
        let net_stack = self.net_stack.lock().await;
        let net_stack = net_stack
            .as_ref()
            .ok_or(TailscaleError::NotStarted)?;

        net_stack.listen_tcp(port).await
    }

    /// Connect to a peer on the tailnet.
    pub async fn dial_tcp(&self, addr: &str) -> Result<TailscaleStream> {
        if !*self.started.read().await {
            return Err(TailscaleError::NotStarted);
        }

        let net_stack = self.net_stack.lock().await;
        let net_stack = net_stack
            .as_ref()
            .ok_or(TailscaleError::NotStarted)?;

        net_stack.dial_tcp(addr).await
    }

    /// Get the identity of this node (IPs, FQDN).
    pub async fn identity(&self) -> Result<NodeIdentity> {
        self.identity
            .read()
            .await
            .clone()
            .ok_or(TailscaleError::NotStarted)
    }

    /// Background loop routing packets between WireGuard and the TCP/IP stack.
    async fn run_packet_loop(tunnel: Arc<WgTunnel>, net_stack: Arc<NetStack>) -> Result<()> {
        loop {
            // Read decrypted packets from WireGuard and feed into smoltcp
            if let Some(packet) = tunnel.recv_packet().await? {
                net_stack.inject_packet(&packet).await?;
            }

            // Read outbound packets from smoltcp and encrypt via WireGuard
            if let Some(packet) = net_stack.poll_outbound().await? {
                tunnel.send_packet(&packet).await?;
            }

            // Small yield to prevent busy-looping
            tokio::task::yield_now().await;
        }
    }
}

fn parse_port(addr: &str) -> Result<u16> {
    let addr = addr.trim();
    let port_str = if addr.starts_with(':') {
        &addr[1..]
    } else if let Some((_host, port)) = addr.rsplit_once(':') {
        port
    } else {
        addr
    };

    port_str
        .parse::<u16>()
        .map_err(|_| TailscaleError::Config(format!("invalid port: {}", port_str)))
}
