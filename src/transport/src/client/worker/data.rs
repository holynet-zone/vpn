use crate::client::{
    error::RuntimeError,
    request::Request,
    response::Response
};

use crate::{client, server};
use snow::StatelessTransportState;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::broadcast::{Receiver, Sender};
use tokio::sync::mpsc;
use tracing::{info, warn};
use crate::session::SessionId;

fn decrypt_body(
    enc_packet: &server::packet::DataPacket,
    state: &StatelessTransportState
) -> anyhow::Result<server::packet::DataBody> {
    let mut buffer = [0u8; 65536];
    state.read_message(0, &enc_packet.enc_body, &mut buffer)?;
    bincode::deserialize(&buffer).map_err(|e| anyhow::anyhow!(e))
}

fn encrypt_body(body: &client::packet::DataBody,
    state: &StatelessTransportState
) -> anyhow::Result<Vec<u8>> {
    let mut buffer = [0u8; 65536];
    let len = state.write_message(0, &bincode::serialize(body)?, &mut buffer)?;
    Ok(buffer[..len].to_vec())
}


pub(super) async fn data_receiver(
    stop_sender: Sender<RuntimeError>,
    mut stop: Receiver<RuntimeError>,
    mut queue: mpsc::Receiver<server::packet::DataPacket>,
    data_sender: mpsc::Sender<client::packet::DataBody>,
    state: Arc<StatelessTransportState>,
    handler: Option<Arc<dyn Fn(Request) -> Pin<Box<dyn Future<Output = Response> + Send>> + Send + Sync>>
) {
    loop {
        tokio::select! {
            _ = stop.recv() => break,
            data = queue.recv() => match data { // todo: may exec in another thread from pool
                Some(data) => {
                    let body = match decrypt_body(&data, &state) {
                        Ok(data_body) => match data_body {
                            server::packet::DataBody::KeepAlive(ref body) => {
                                info!("keepalive rtt: {} ms; owd: {} ms", body.rtt(), body.owd());
                                data_body
                            },
                            server::packet::DataBody::Disconnect(ref code) => {
                                stop_sender.send(RuntimeError::Disconnect(
                                    format!("server disconnected code {}", code)
                                )).unwrap();
                                data_body
                            },
                            _ => data_body
                        },
                        Err(e) => {
                            warn!("received damaged package: {}", e);
                            continue;
                        }
                    };
                    
                    if let Some(handler) = &handler {
                        match handler(Request{ body }).await {
                            Response::Data(body) => {
                                data_sender.send(body).await.unwrap(); // todo remove await
                            },
                            Response::Close => {
                                stop_sender.send(RuntimeError::Disconnect(
                                    "close connection".into()
                                )).unwrap();
                            },
                            Response::None => {}
                        }
                    }
                },
                None => panic!("data_receiver channel is closed")
            }
        }
    }
}

pub(super) async fn data_sender(
    stop_sender: Sender<RuntimeError>,
    mut stop: Receiver<RuntimeError>,
    mut queue: mpsc::Receiver<client::packet::DataBody>,
    udp_sender: mpsc::Sender<client::packet::Packet>,
    state: Arc<StatelessTransportState>,
    sid: SessionId
) {
    loop {
        tokio::select! {
            _ = stop.recv() => break,
            body = queue.recv() => match body { // todo: may exec in another thread from pool??
               Some(body) => match encrypt_body(&body, &state) {
                    Ok(enc_body) => {
                        let packet = client::packet::DataPacket{ sid, enc_body };
                        udp_sender.send(client::packet::Packet::Data(packet)).await.unwrap(); // todo remove await
                    },
                    Err(e) => {
                        stop_sender.send(RuntimeError::Unexpected(
                            format!("failed to encrypt data: {}", e)
                        )).unwrap();
                    }
                },
                None => panic!("data_sender channel is closed")
            }
        }
    }
}