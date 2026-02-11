use std::{convert::TryInto, io, time::Instant};

use log::{debug, warn};

use srt_protocol::{
    connection::Connection,
    options::*,
    packet::CoreRejectReason,
    protocol::pending_connection::{listen::Listen, AccessControlResponse, ConnectionResult},
    settings::*,
};

use crate::{net::PacketSocket, PassphraseCallback, PassphraseResult};

pub async fn bind_with(
    mut socket: PacketSocket,
    options: Valid<ListenerOptions>,
    passphrase_callback: Option<PassphraseCallback>,
) -> Result<(PacketSocket, Connection), io::Error> {
    let init_settings: ConnInitSettings = options.socket.clone().into();
    let socket_id = init_settings.local_sockid;

    let mut listen = Listen::new(init_settings, passphrase_callback.is_some());
    let mut next_result: Option<ConnectionResult> = None;
    loop {
        let result = match next_result.take() {
            Some(result) => result,
            None => {
                let packet = socket.receive().await;
                debug!("{:?}:listen  - {:?}", socket_id, packet);
                listen.handle_packet(Instant::now(), packet)
            }
        };

        debug!("{:?}:listen  - {:?}", socket_id, result);

        use ConnectionResult::*;
        match result {
            SendPacket(packet) => {
                let _ = socket.send(packet).await?;
            }
            NotHandled(e) => {
                warn!("{:?}", e);
            }
            Reject(packet, e) => {
                warn!("{:?}", e);
                if let Some(packet) = packet {
                    let _ = socket.send(packet).await?;
                }
            }
            Connected(p, connection) => {
                if let Some(packet) = p {
                    let _ = socket.send(packet).await?;
                }
                return Ok((socket, connection));
            }
            NoAction => {}
            RequestAccess(request) => {
                let response = match &passphrase_callback {
                    Some(callback) => {
                        match callback(
                            request.stream_id.as_ref().map(|s| s.as_str()),
                            request.remote,
                        ) {
                            PassphraseResult::Passphrase(passphrase) => {
                                match passphrase.try_into() {
                                    Ok(passphrase) => {
                                        AccessControlResponse::Accepted(Some(KeySettings {
                                            key_size: request.key_size,
                                            passphrase,
                                        }))
                                    }
                                    Err(_) => AccessControlResponse::Rejected(
                                        CoreRejectReason::BadSecret.into(),
                                    ),
                                }
                            }
                            PassphraseResult::None => AccessControlResponse::Accepted(None),
                            PassphraseResult::Unauthorized => {
                                AccessControlResponse::Rejected(CoreRejectReason::BadSecret.into())
                            }
                        }
                    }
                    None => AccessControlResponse::Dropped,
                };
                next_result = Some(listen.handle_access_control_response(Instant::now(), response));
            }
            Failure(error) => return Err(error),
        }
    }
}
