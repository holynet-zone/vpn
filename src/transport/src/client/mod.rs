mod error;
pub(crate) mod packet;
mod worker;
mod response;
mod request;
mod credential;

use std::{
    future::Future,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    thread
};
use std::sync::Arc;
use std::time::Duration;
use dashmap::DashMap;
use self::{
    request::Request,
    error::RuntimeError,
    response::Response,
};

use tokio::runtime::Builder;
use tokio::sync::{broadcast, mpsc};
use tracing::{error, warn};
use crate::client::credential::Credential;
use crate::client::packet::DataBody;
use crate::keys::handshake::{PublicKey, SecretKey};
use crate::server;
use crate::session::{Alg, SessionId};

pub struct Client {
    sock: SocketAddr,
    alg: Alg,
    cred: Credential,
    sender: mpsc::Sender<DataBody>,
    sender_recv: Option<mpsc::Receiver<DataBody>>,
    handshake_timeout: Duration,
    handshake_payload: Vec<u8>,
    on_session_created: Option<Arc<dyn Fn(SessionId, Vec<u8>) -> Pin<Box<dyn Future<Output = Result<(), RuntimeError>> + Send>> + Send + Sync>>,
    on_request: Option<Arc<dyn Fn(Request) -> Pin<Box<dyn Future<Output = Response> + Send>> + Send + Sync>>,
}

impl Client {
    pub fn new(addr: IpAddr, port: u16, alg: Alg, cred: Credential) -> Self {
        let (sender, sender_recv) = mpsc::channel::<DataBody>(1000);
        Self {
            sock: SocketAddr::new(addr, port),
            alg,
            cred,
            on_session_created: None,
            on_request: None,
            sender,
            sender_recv: Some(sender_recv),
            handshake_timeout: Duration::from_millis(1000),
            handshake_payload: vec![],
        }
    }

    pub fn on_request<F, Fut>(&mut self, handler: F) -> &mut Self
    where
        F: Fn(Request) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Response> + Send + 'static,
    {
        self.on_request = Some(Arc::new(move |data| Box::pin(handler(data))));
        self
    }
    
    pub fn on_session_created<F, Fut>(&mut self, handler: F) -> &mut Self
    where
        F: Fn(SessionId, Vec<u8>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), RuntimeError>> + Send + 'static,
    {
        self.on_session_created = Some(Arc::new(move |id, data| Box::pin(handler(id, data))));
        self
    }
    
    pub fn sender(&self) -> mpsc::Sender<DataBody> {
        self.sender.clone()
    }

    pub async fn connect(&mut self) -> Result<(), RuntimeError> {
        tracing::info!("Connecting to udp://{}", self.sock);

        let (stop_tx, mut stop_rx) = broadcast::channel::<RuntimeError>(1);
        let sender_recv = self.sender_recv
            .take()
            .expect("sender_recv is already taken");
        
        let worker = worker::create(
            self.sock,
            stop_tx,
            self.cred.clone(),
            self.alg.clone(),
            self.handshake_timeout,
            self.handshake_payload.clone(),
            self.on_request.clone(),
            self.on_session_created.clone(),
            sender_recv,
            self.sender.clone()
        );
        
        tokio::select! {
            resp = worker => match resp {
                Ok(_) => {
                    warn!("worker stopped without error, waiting for stop signal");
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    Ok(())
                },
                Err(err) => {
                    let msg = format!("worker result with unexpected error: {err}");
                    error!(msg);
                    Err(RuntimeError::Unexpected(err.to_string()))
                }
            },
            err = stop_rx.recv() => return match err {
                Ok(err) => Err(err),
                Err(err) => {
                    let msg = format!("stop channel is closed: {err}");
                    error!(msg);
                    Err(RuntimeError::Unexpected(msg))
                }
            }
        }
    }
}