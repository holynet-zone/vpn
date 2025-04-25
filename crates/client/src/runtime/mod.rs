pub mod error;
mod worker;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::runtime::Builder;
use self::{
    error::RuntimeError,
};

use tokio::sync::{broadcast, mpsc};
use tracing::{debug, error, info, warn};
use tracing::field::debug;
use shared::session::Alg;
use shared::connection_config::{CredentialsConfig, RuntimeConfig};
use shared::network::find_available_ifname;
use shared::protocol::{EncryptedData, Packet};
use shared::tun::setup_tun;
use crate::network::DefaultGateway;
use crate::runtime::worker::data::keepalive_sender;
use crate::runtime::worker::handshake::handshake_step;
use crate::runtime::worker::tun::{tun_listener, tun_sender};
use crate::runtime::worker::udp::{udp_listener, udp_sender};

pub struct Runtime {
    sock: SocketAddr,
    alg: Alg,
    cred: CredentialsConfig,
    config: RuntimeConfig,
    pub stop_tx: broadcast::Sender<RuntimeError>
}

impl Runtime {
    pub fn new(
        addr: IpAddr,
        port: u16,
        alg: Alg,
        cred: CredentialsConfig,
        config: RuntimeConfig
    ) -> Self {
        let (stop_tx, _) = broadcast::channel::<RuntimeError>(10);
        Self {
            sock: SocketAddr::new(addr, port),
            alg,
            cred,
            config,
            stop_tx
        }
    }

    pub async fn run(&self) -> Result<(), RuntimeError> {
        tracing::info!("Connecting to udp://{}", self.sock);
        
        let workers = thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);

        let socket = Socket::new(
            Domain::for_address(self.sock),
            Type::DGRAM,
            Some(Protocol::UDP)
        )?;
        socket.set_nonblocking(true)?;
        // socket.set_reuse_port(true)?;
        socket.set_recv_buffer_size(self.config.so_rcvbuf)?;
        socket.set_send_buffer_size(self.config.so_sndbuf)?;
        socket.bind(&SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0,0,0,0)), 0).into())?;
        socket.connect(&self.sock.into())?;

        let socket = Arc::new(UdpSocket::from_std(socket.into())?);

        let (handshake_payload, state) = tokio::spawn(handshake_step(
            socket.clone(),
            self.cred.clone(),
            self.alg.clone(),
            Duration::from_millis(self.config.handshake_timeout)
        )).await.unwrap().map(|(r, s)| (r, Arc::new(s)))?;

        let tun = Arc::new(setup_tun(
            find_available_ifname("holynet"),
            1500, // todo
            handshake_payload.ipaddr,
            32
        ).await?);

        let mut gw = DefaultGateway::create(
            &handshake_payload.ipaddr,
            self.sock.ip().to_string().as_str(),
            true
        );

        let (udp_sender_tx, udp_sender_rx) = mpsc::channel::<Packet>(self.config.out_udp_buf);
        let (tun_sender_tx, tun_sender_rx) = mpsc::channel::<Vec<u8>>(self.config.out_tun_buf);

        let mut data_udp_senders = Vec::new();
        let mut data_tun_senders = Vec::new();
        
        for worker_id in 1..workers + 1 {
            let stop_tx = self.stop_tx.clone();
            
            let udp_sender = udp_sender_tx.clone();
            let tun_sender = tun_sender_tx.clone();

            let (data_udp_sender, data_udp_rx) = mpsc::channel::<EncryptedData>(self.config.data_udp_buf);
            let (data_tun_sender, data_tun_rx) = mpsc::channel::<Vec<u8>>(self.config.data_tun_buf);
            data_udp_senders.push(data_udp_sender);
            data_tun_senders.push(data_tun_sender);

            tokio::spawn(crate::runtime::worker::data::data_tun_executor(
                stop_tx.clone(),
                stop_tx.subscribe(),
                data_tun_rx,
                udp_sender,
                state.clone(),
                handshake_payload.sid,
            ));

            tokio::spawn(crate::runtime::worker::data::data_udp_executor(
                stop_tx.clone(),
                stop_tx.subscribe(),
                data_udp_rx,
                tun_sender,
                state.clone()
            ));
            debug!("worker {worker_id} started");
        }

        // Handle incoming UDP packets
        tokio::spawn(udp_listener(self.stop_tx.clone(), self.stop_tx.subscribe(), socket.clone(), data_udp_senders));

        // Handle outgoing UDP packets
        tokio::spawn(udp_sender(self.stop_tx.clone(), self.stop_tx.subscribe(), socket.clone(), udp_sender_rx));
    
        // Handle incoming TUN packets
        tokio::spawn(tun_listener(
            self.stop_tx.clone(),
            self.stop_tx.subscribe(),
            tun.clone(),
            data_tun_senders
        ));

        // Handle outgoing TUN packets
        tokio::spawn(tun_sender(
            self.stop_tx.clone(),
            self.stop_tx.subscribe(),
            tun.clone(),
            tun_sender_rx
        ));



        match self.config.keepalive {
            Some(duration) => {
                info!("starting keepalive sender with interval {:?}", duration);
                tokio::spawn(keepalive_sender(
                    self.stop_tx.clone(),
                    self.stop_tx.subscribe(),
                    udp_sender_tx,
                    Duration::from_secs(duration),
                    state.clone(),
                    handshake_payload.sid,
                ));
            },
            None => info!("keepalive is disabled")
        }

        // let mut errors = Vec::new();
        // for handle in handles {
        //     if let Err(err) = handle.join() {
        //         errors.push(RuntimeError::Unexpected(format!("{:?}", err)));
        //     }
        // }
        
        
        let mut stop_rx = self.stop_tx.subscribe();
        
        tokio::select! {
            // resp = worker => match resp {
            //     Ok(_) => {
            //         debug!("worker stopped without error, waiting for stop signal");
            //         tokio::time::sleep(Duration::from_secs(2)).await;
            //         Ok(())
            //     },
            //     Err(err) => {
            //         debug!("worker result with error");
            //         Err(err)
            //     }
            // },
            err = stop_rx.recv() => {
                gw.delete();
                match err {
                    Ok(err) => Err(err),
                    Err(err) => {
                        Err(RuntimeError::IO(format!("stop channel err: {err}")))
                    }
                }
            }
        }
    }
}