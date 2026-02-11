use std::net::SocketAddr;
use std::{convert::TryInto, io, net::IpAddr, sync::Arc, time::Duration};

use tokio::net::UdpSocket;

use crate::{
    net::{bind_socket, PacketSocket},
    options::*,
    PassphraseCallback, PassphraseResult,
};

use super::SrtSocket;

#[derive(Default)]
pub struct SrtSocketBuilder {
    options: SocketOptions,
    socket: Option<UdpSocket>,
    passphrase_callback: Option<PassphraseCallback>,
}

/// Struct to build sockets.
///
/// This is the typical way to create instances of [`SrtSocket`], which implements both `Sink + Stream`, as they can be both receivers and senders.
///
/// # Examples:
/// Simple:
/// ```
/// # use srt_tokio::{SrtSocket, options::*};
/// # use std::io;
/// # #[tokio::main]
/// # async fn main() -> Result<(), io::Error> {
/// let (a, b) = futures::try_join!(
///     SrtSocket::builder().listen_on(":3333"),
///     SrtSocket::builder().call("127.0.0.1:3333", Some("stream ID")),
/// )?;
/// # Ok(())
/// # }
/// ```
///
/// Rendezvous example:
///
/// ```
/// # use srt_tokio::{SrtSocket, options::*};
/// # use std::{io, time::Duration};///
/// # #[tokio::main]
/// # async fn main() -> Result<(), io::Error> {
/// let (a, b) = futures::try_join!(
///     SrtSocket::builder().local_port(5555).rendezvous("127.0.0.1:4444"),
///     SrtSocket::builder()
///         .set(|options| {
///             options.connect.timeout = Duration::from_secs(2);
///             options.receiver.buffer_size = ByteCount(120000);
///             options.sender.max_payload_size = PacketSize(1200);
///             options.session.peer_idle_timeout = Duration::from_secs(5);
///         })
///         .local_port(4444)
///         .rendezvous("127.0.0.1:5555"),
/// )?;
/// # Ok(())
/// # }
/// ```
///
/// # Panics:
/// * There is no tokio runtime
impl SrtSocketBuilder {
    /// Sets the local address of the socket. This can be used to bind to just a specific network adapter instead of the default of all adapters.
    pub fn local_ip(mut self, ip: IpAddr) -> Self {
        let local = self.options.connect.local;
        self.options.connect.local = SocketAddr::new(ip, local.port());
        self
    }

    /// Sets the port to bind to. In general, to be used for [`Listen`] and [`Rendezvous`], but generally not [`Call`].
    pub fn local_port(mut self, port: u16) -> Self {
        let local = self.options.connect.local;
        self.options.connect.local = SocketAddr::new(local.ip(), port);
        self
    }

    /// Sets the local address (ip:port) to bind to. In general, to be used for [`Listen`] and [`Rendezvous`], but generally not [`Call`].
    pub fn local(mut self, address: impl TryInto<SocketAddress>) -> Self {
        let address = address
            .try_into()
            .map_err(|_| OptionsError::InvalidLocalAddress)
            .unwrap();

        self.options.connect.local = address
            .try_into()
            .map_err(|_| OptionsError::InvalidLocalAddress)
            .unwrap();

        self
    }

    // SRTO_LATENCY
    /// Set the latency of the connection. The more latency, the more time SRT has to recover lost packets.
    /// This sets both the send and receive latency
    pub fn latency(mut self, latency: Duration) -> Self {
        self.options.sender.peer_latency = latency;
        self.options.receiver.latency = latency;

        self
    }

    /// Set the encryption parameters.
    ///
    /// # Panics:
    /// * size is not 0, 16, 24, or 32.
    pub fn encryption(mut self, key_size: u16, passphrase: impl Into<String>) -> Self {
        self.options.encryption.key_size = key_size.try_into().unwrap();
        self.options.encryption.passphrase = Some(passphrase.into().try_into().unwrap());

        self
    }
    /// the minimum latency to receive at
    pub fn receive_latency(mut self, latency: Duration) -> Self {
        self.options.receiver.latency = latency;
        self
    }

    /// the minimum latency to send at
    pub fn send_latency(mut self, latency: Duration) -> Self {
        self.options.sender.peer_latency = latency;
        self
    }

    pub fn bandwidth(mut self, bandwidth: LiveBandwidthMode) -> Self {
        self.options.sender.bandwidth = bandwidth;
        self
    }

    pub fn socket(mut self, socket: UdpSocket) -> Self {
        self.socket = Some(socket);
        self
    }

    pub fn passphrase_callback(
        mut self,
        callback: impl Fn(Option<&str>, SocketAddr) -> PassphraseResult + Send + Sync + 'static,
    ) -> Self {
        self.passphrase_callback = Some(Arc::new(callback));
        self
    }

    pub fn with<O>(mut self, options: O) -> Self
    where
        SocketOptions: OptionsOf<O>,
        O: Validation<Error = OptionsError>,
    {
        self.options.set_options(options);
        self
    }

    pub fn set(mut self, set_fn: impl FnOnce(&mut SocketOptions)) -> Self {
        set_fn(&mut self.options);
        self
    }

    pub async fn listen_on(
        self,
        local: impl TryInto<SocketAddress>,
    ) -> Result<SrtSocket, io::Error> {
        self.local(local).listen().await
    }

    pub async fn listen(self) -> Result<SrtSocket, io::Error> {
        let mut options = self.options;
        if self.passphrase_callback.is_some() {
            options.encryption.passphrase = None;
        }
        let options = ListenerOptions { socket: options }.try_validate()?;
        match self.passphrase_callback {
            Some(callback) => Self::bind_listen_with_callback(options, self.socket, callback).await,
            None => Self::bind(options.into(), self.socket).await,
        }
    }

    pub async fn call(
        self,
        remote: impl TryInto<SocketAddress>,
        stream_id: Option<&str>,
    ) -> Result<SrtSocket, io::Error> {
        let options = CallerOptions::with(remote, stream_id, self.options)?;
        Self::bind(options.into(), self.socket).await
    }

    pub async fn rendezvous(
        self,
        remote: impl TryInto<SocketAddress>,
    ) -> Result<SrtSocket, io::Error> {
        let options = RendezvousOptions::with(remote, self.options)?;
        Self::bind(options.into(), self.socket).await
    }

    async fn bind(options: BindOptions, socket: Option<UdpSocket>) -> Result<SrtSocket, io::Error> {
        match socket {
            None => SrtSocket::bind(options).await,
            Some(socket) => SrtSocket::bind_with_socket(options, socket).await,
        }
    }

    async fn bind_listen_with_callback(
        options: Valid<ListenerOptions>,
        socket: Option<UdpSocket>,
        passphrase_callback: PassphraseCallback,
    ) -> Result<SrtSocket, io::Error> {
        let socket = match socket {
            None => bind_socket(&options.socket).await?,
            Some(socket) => socket,
        };
        let socket = PacketSocket::from_socket(Arc::new(socket), 1024 * 1024);
        let (socket, connection) =
            super::listen::bind_with(socket, options, Some(passphrase_callback)).await?;

        let (new_socket, new_state) = super::factory::split_new();
        let (task, settings) = new_state.spawn_task(socket, connection);
        Ok(new_socket.create_socket(settings, task))
    }
}
