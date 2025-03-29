use crate::server;
use crate::server::response::Response;
use crate::session::SessionId;
use anyhow::anyhow;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;

#[derive(Clone)]
pub struct ServerSender {
    counter: Arc<AtomicUsize>,
    pub(crate) senders: Arc<Vec<mpsc::Sender<(SessionId, server::Response)>>>,
}

impl ServerSender {
    pub async fn send(&self, sid: SessionId, resp: Response) -> anyhow::Result<()> {
        if self.senders.len() == 0 {
            return Err(anyhow!("no senders available"))
        }
        let idx = self.counter.fetch_add(1, Ordering::Relaxed) % self.senders.len();
        self.senders[idx].send((sid, resp)).await?;
        Ok(())
    }
    
    /// error if the channel is full
    pub fn try_send(&self, sid: SessionId, resp: Response) -> anyhow::Result<()> {
        if self.senders.len() == 0 {
            return Err(anyhow!("no senders available"))
        }
        let idx = self.counter.fetch_add(1, Ordering::Relaxed) % self.senders.len();
        self.senders[idx].try_send((sid, resp))?;
        Ok(())
    }
}

impl Default for ServerSender {
    fn default() -> Self {
        Self {
            counter: Arc::new(AtomicUsize::new(0)),
            senders: Arc::new(Vec::new())
        }
    }
}