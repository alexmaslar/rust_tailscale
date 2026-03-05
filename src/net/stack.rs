use crate::error::{Result, TailscaleError};
use crate::listener::TailscaleListener;
use crate::stream::TailscaleStream;
use crate::wg::WgTunnel;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, Ipv4Address, Ipv6Address};
use std::collections::VecDeque;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};

/// Userspace TCP/IP stack built on smoltcp, bridging WireGuard packets to Tokio streams.
pub struct NetStack {
    inner: Arc<Mutex<NetStackInner>>,
}

struct NetStackInner {
    iface: Interface,
    sockets: SocketSet<'static>,
    device: VirtualDevice,
    ipv4: Ipv4Addr,
    #[allow(dead_code)]
    ipv6: Ipv6Addr,
}

impl NetStackInner {
    /// Poll the smoltcp interface, working around the borrow checker by
    /// destructuring self into separate fields.
    fn poll_iface(&mut self) {
        let now = SmolInstant::from_millis(now_millis());
        let NetStackInner {
            iface,
            sockets,
            device,
            ..
        } = self;
        iface.poll(now, device, sockets);
    }
}

impl NetStack {
    /// Create a new userspace TCP/IP stack with the given addresses.
    pub fn new(ipv4: Ipv4Addr, ipv6: Ipv6Addr, _tunnel: Arc<WgTunnel>) -> Result<Self> {
        let mut device = VirtualDevice::new();

        let config = Config::new(HardwareAddress::Ip);
        let now = SmolInstant::from_millis(now_millis());
        let mut iface = Interface::new(config, &mut device, now);

        // Assign our tailnet addresses
        let ipv4_cidr = IpCidr::new(IpAddress::Ipv4(Ipv4Address::from(ipv4)), 32);
        let ipv6_cidr = IpCidr::new(IpAddress::Ipv6(Ipv6Address::from(ipv6)), 128);
        iface.update_ip_addrs(|addrs| {
            addrs.push(ipv4_cidr).ok();
            addrs.push(ipv6_cidr).ok();
        });

        // Add default routes so we can reach any peer
        iface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Address::new(0, 0, 0, 1))
            .ok();
        iface
            .routes_mut()
            .add_default_ipv6_route(Ipv6Address::new(0, 0, 0, 0, 0, 0, 0, 1))
            .ok();

        let sockets = SocketSet::new(vec![]);

        let inner = NetStackInner {
            iface,
            sockets,
            device,
            ipv4,
            ipv6,
        };

        Ok(Self {
            inner: Arc::new(Mutex::new(inner)),
        })
    }

    /// Listen for incoming TCP connections on the given port.
    pub async fn listen_tcp(&self, port: u16) -> Result<TailscaleListener> {
        let (conn_tx, conn_rx) = mpsc::channel(16);

        {
            let mut inner = self.inner.lock().await;
            let rx_buf = tcp::SocketBuffer::new(vec![0u8; 65535]);
            let tx_buf = tcp::SocketBuffer::new(vec![0u8; 65535]);
            let mut socket = tcp::Socket::new(rx_buf, tx_buf);
            socket.listen(port).map_err(|e| {
                TailscaleError::Network(format!("failed to listen on port {port}: {e}"))
            })?;
            let handle = inner.sockets.add(socket);

            tracing::info!(port, "TCP listener bound");

            tokio::spawn(accept_loop(handle, port, conn_tx, self.inner.clone()));
        }

        Ok(super::socket::listener_from_channel(conn_rx, port))
    }

    /// Connect to a remote peer over TCP.
    pub async fn dial_tcp(&self, addr: &str) -> Result<TailscaleStream> {
        let remote: SocketAddr = addr
            .parse()
            .map_err(|e| TailscaleError::Network(format!("invalid address '{addr}': {e}")))?;

        let (app_reader_tx, app_reader_rx) = mpsc::channel(64);
        let (app_writer_tx, app_writer_rx) = mpsc::channel(64);

        {
            let mut inner = self.inner.lock().await;

            let rx_buf = tcp::SocketBuffer::new(vec![0u8; 65535]);
            let tx_buf = tcp::SocketBuffer::new(vec![0u8; 65535]);
            let socket = tcp::Socket::new(rx_buf, tx_buf);

            let local_port = ephemeral_port();
            let remote_endpoint = (smoltcp_addr_from_std(remote.ip()), remote.port());
            let local_addr = IpAddress::Ipv4(Ipv4Address::from(inner.ipv4));

            let handle = inner.sockets.add(socket);

            // Destructure to avoid double mutable borrow
            let NetStackInner {
                ref mut iface,
                ref mut sockets,
                ..
            } = *inner;
            sockets
                .get_mut::<tcp::Socket>(handle)
                .connect(iface.context(), remote_endpoint, (local_addr, local_port))
                .map_err(|e| {
                    TailscaleError::Network(format!("failed to connect to {addr}: {e}"))
                })?;

            tracing::info!(%addr, "TCP dial initiated");

            tokio::spawn(connection_io_loop(
                handle,
                app_reader_tx,
                app_writer_rx,
                self.inner.clone(),
            ));
        }

        Ok(super::socket::stream_from_channels(
            app_reader_rx,
            app_writer_tx,
            remote,
        ))
    }

    /// Inject a decrypted packet from WireGuard into the network stack.
    pub async fn inject_packet(&self, packet: &[u8]) -> Result<()> {
        let mut inner = self.inner.lock().await;
        inner.device.inject_rx(packet.to_vec());
        inner.poll_iface();
        Ok(())
    }

    /// Poll for an outbound packet that needs to be sent via WireGuard.
    pub async fn poll_outbound(&self) -> Result<Option<Vec<u8>>> {
        let mut inner = self.inner.lock().await;
        inner.poll_iface();
        Ok(inner.device.take_tx())
    }
}

// ---- Background tasks ----

/// Accept loop: monitors a listening smoltcp TCP socket and produces TailscaleStreams.
async fn accept_loop(
    listen_handle: SocketHandle,
    port: u16,
    conn_tx: mpsc::Sender<(TailscaleStream, SocketAddr)>,
    inner: Arc<Mutex<NetStackInner>>,
) {
    loop {
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        let maybe_peer = {
            let mut guard = inner.lock().await;
            guard.poll_iface();

            let socket = guard.sockets.get_mut::<tcp::Socket>(listen_handle);
            if socket.is_active() && socket.may_recv() {
                socket
                    .remote_endpoint()
                    .map(|ep| SocketAddr::new(smoltcp_addr_to_std(ep.addr), ep.port))
            } else {
                None
            }
        };

        if let Some(peer_addr) = maybe_peer {
            let (app_reader_tx, app_reader_rx) = mpsc::channel(64);
            let (app_writer_tx, app_writer_rx) = mpsc::channel(64);

            tokio::spawn(connection_io_loop(
                listen_handle,
                app_reader_tx,
                app_writer_rx,
                inner.clone(),
            ));

            let stream =
                super::socket::stream_from_channels(app_reader_rx, app_writer_tx, peer_addr);

            if conn_tx.send((stream, peer_addr)).await.is_err() {
                tracing::debug!(port, "listener channel closed");
                return;
            }

            // Create a new listening socket for the next connection
            {
                let mut guard = inner.lock().await;
                let rx_buf = tcp::SocketBuffer::new(vec![0u8; 65535]);
                let tx_buf = tcp::SocketBuffer::new(vec![0u8; 65535]);
                let mut socket = tcp::Socket::new(rx_buf, tx_buf);
                if let Err(e) = socket.listen(port) {
                    tracing::error!(port, error = %e, "failed to re-listen");
                    return;
                }
                guard.sockets.add(socket);
            }
        }
    }
}

/// Drives data between a smoltcp TCP socket and application-level channels.
async fn connection_io_loop(
    handle: SocketHandle,
    app_tx: mpsc::Sender<Vec<u8>>,
    mut app_rx: mpsc::Receiver<Vec<u8>>,
    inner: Arc<Mutex<NetStackInner>>,
) {
    let mut buf = vec![0u8; 4096];

    loop {
        tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;

        let mut guard = inner.lock().await;
        guard.poll_iface();

        let socket = guard.sockets.get_mut::<tcp::Socket>(handle);

        if !socket.is_open() {
            tracing::debug!("socket closed");
            return;
        }

        // smoltcp socket -> application
        if socket.can_recv() {
            match socket.recv_slice(&mut buf) {
                Ok(n) if n > 0 => {
                    let data = buf[..n].to_vec();
                    drop(guard);
                    if app_tx.send(data).await.is_err() {
                        tracing::debug!("app reader dropped, closing socket");
                        let mut g = inner.lock().await;
                        g.sockets.get_mut::<tcp::Socket>(handle).close();
                        return;
                    }
                    continue;
                }
                _ => {}
            }
        }

        // application -> smoltcp socket
        if socket.can_send() {
            match app_rx.try_recv() {
                Ok(data) => {
                    if let Err(e) = socket.send_slice(&data) {
                        tracing::warn!(error = %e, "failed to send to smoltcp socket");
                    }
                }
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    socket.close();
                    return;
                }
                Err(mpsc::error::TryRecvError::Empty) => {}
            }
        }
    }
}

// ---- VirtualDevice: smoltcp PHY device backed by packet queues ----

struct VirtualDevice {
    rx_queue: VecDeque<Vec<u8>>,
    tx_queue: VecDeque<Vec<u8>>,
}

impl VirtualDevice {
    fn new() -> Self {
        Self {
            rx_queue: VecDeque::new(),
            tx_queue: VecDeque::new(),
        }
    }

    fn inject_rx(&mut self, packet: Vec<u8>) {
        self.rx_queue.push_back(packet);
    }

    fn take_tx(&mut self) -> Option<Vec<u8>> {
        self.tx_queue.pop_front()
    }
}

impl Device for VirtualDevice {
    type RxToken<'a> = VirtualRxToken;
    type TxToken<'a> = VirtualTxToken<'a>;

    fn receive(
        &mut self,
        _timestamp: SmolInstant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.rx_queue.pop_front()?;
        Some((
            VirtualRxToken { buffer: packet },
            VirtualTxToken {
                tx_queue: &mut self.tx_queue,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(VirtualTxToken {
            tx_queue: &mut self.tx_queue,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = 1500;
        caps
    }
}

struct VirtualRxToken {
    buffer: Vec<u8>,
}

impl RxToken for VirtualRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = self.buffer;
        f(&mut buffer)
    }
}

struct VirtualTxToken<'a> {
    tx_queue: &'a mut VecDeque<Vec<u8>>,
}

impl<'a> TxToken for VirtualTxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);
        self.tx_queue.push_back(buffer);
        result
    }
}

// ---- Helpers ----

fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

fn smoltcp_addr_from_std(addr: std::net::IpAddr) -> IpAddress {
    match addr {
        std::net::IpAddr::V4(v4) => IpAddress::Ipv4(Ipv4Address::from(v4)),
        std::net::IpAddr::V6(v6) => IpAddress::Ipv6(Ipv6Address::from(v6)),
    }
}

fn smoltcp_addr_to_std(addr: IpAddress) -> std::net::IpAddr {
    match addr {
        IpAddress::Ipv4(v4) => std::net::IpAddr::V4(Ipv4Addr::from(v4.0)),
        IpAddress::Ipv6(v6) => std::net::IpAddr::V6(Ipv6Addr::from(v6.0)),
    }
}

fn ephemeral_port() -> u16 {
    use rand::Rng;
    rand::thread_rng().gen_range(49152..=65535)
}
