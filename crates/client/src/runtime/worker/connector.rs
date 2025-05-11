use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tracing::{debug, error};
use shared::connection_config::CredentialsConfig;
use shared::session::Alg;
use crate::runtime::handshake::handshake_step;
use crate::runtime::state::RuntimeState;
use crate::runtime::transport::Transport;
use super::super::{
    error::RuntimeError
};


const RECONNECT_DELAY: Duration = Duration::from_secs(3);

pub(crate) async fn executor(
    transport: Arc<dyn Transport>,
    state_tx: watch::Sender<RuntimeState>,
    // for handshake step:
    cred: CredentialsConfig,
    alg: Alg,
    timeout: Duration
) {
    let mut state_rx = state_tx.subscribe();
    state_rx.mark_changed();
    let mut ticker = tokio::time::interval(RECONNECT_DELAY);
    let mut is_reconnect = false;

    loop {
        match state_rx.changed().await {
            Ok(_) => {
                let state =  state_rx.borrow().clone();
                match state {
                    RuntimeState::Connecting => match transport.connect().await {
                        Ok(_) => match handshake_step(
                            transport.clone(),
                            cred.clone(),
                            alg.clone(),
                            timeout
                        ).await {
                            Ok((payload, transport_state)) => {
                                is_reconnect = true;
                                state_tx.send(RuntimeState::Connected((payload, Arc::new(transport_state)))).expect(
                                    "broken runtime state pipe"
                                );
                                continue
                            },
                            Err(err) => match is_reconnect {
                                false => {
                                    state_tx.send(RuntimeState::Error(err)).expect(
                                        "broken runtime state pipe"
                                    );
                                    return;
                                },
                                true => {
                                    error!("{}, trying again in {:?}", err, RECONNECT_DELAY);
                                    state_rx.mark_changed();
                                    ticker.tick().await;
                                }
                            }
                        },
                        Err(err) => match is_reconnect {
                            false => {
                                state_tx.send(RuntimeState::Error(
                                    RuntimeError::IO(format!("connecting error: {}", err))
                                )).expect(
                                    "broken runtime state pipe"
                                );
                                return;
                            },
                            true => {
                                error!("failed to reconnect: {}, trying again in {:?}", err, RECONNECT_DELAY);
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
