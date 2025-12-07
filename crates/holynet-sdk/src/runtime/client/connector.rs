use std::sync::Arc;
use std::time::Duration;
use futures::SinkExt;
use tokio::sync::watch;
use tracing::{debug, error};
use shared::connection_config::CredentialsConfig;
use shared::session::Alg;
use crate::gateway::transport::Transport;
use crate::keys::handshake::{PublicKey, SecretKey};
use crate::protocol::Alg;
use crate::runtime::cred::Cred;
use crate::runtime::handshake::handshake_step;
use crate::runtime::state::RuntimeState;
use crate::runtime::transport::Transport;
use super::super::{
    error::RuntimeError
};


pub(crate) async fn executor(
    state: watch::Sender<RuntimeState>,
    transport: Arc<dyn Transport>,
    cred: Cred,
    alg: Alg,
    reconnect_delay: Duration,
    timeout: Duration
) -> ! {
    let mut state_rx = state.subscribe();
    state_rx.mark_changed();
    let mut ticker = tokio::time::interval(reconnect_delay);
    let mut is_reconnect = false;
    loop {
        match state_rx.changed().await {
            Ok(_) => {
                let mut state =  state_rx.borrow().clone();
                match state {
                    RuntimeState::Connecting => match transport.connect().await {
                        Ok(_) => match handshake_step(
                            transport.clone(),
                            &cred,
                            &alg,
                            timeout
                        ).await {
                            Ok((payload, transport_state)) => {
                                is_reconnect = true;
                                state.send(RuntimeState::Connected((payload, Arc::new(transport_state))))
                                    .expect("broken runtime state pipe");
                                continue
                            },
                            // if conn is ok, but handshake no :(
                            Err(err) => match is_reconnect {
                                false => {
                                    state.send(RuntimeState::Error(err))
                                        .expect("broken runtime state pipe");
                                    return;
                                },
                                true => {
                                    error!("{}, trying again in {:?}", err, RECONNECT_DELAY);
                                    state_rx.mark_changed();
                                    ticker.tick().await;
                                }
                            }
                        },
                        // if connecting err
                        Err(err) => match is_reconnect {
                            false => {
                                state.send(RuntimeState::Error(
                                    RuntimeError::IO(format!("connecting error: {}", err))
                                )).expect(
                                    "broken runtime state pipe"
                                );
                                return;
                            },
                            true => {
                                error!("failed to reconnect: {}, trying again in {:?}", err, RECONNECT_DELAY);
                                state_rx.mark_changed();
                                ticker.tick().await;
                            }
                        }
                    },
                    RuntimeState::Error(_) => {
                        debug!("handshake executor stopped by error state");
                        break;
                    },
                    _ => {}
                }
            },
            Err(err) => {
                debug!("state_rx channel error in handshake executor: {}", err);
                break;
            }
        }
    }
}
