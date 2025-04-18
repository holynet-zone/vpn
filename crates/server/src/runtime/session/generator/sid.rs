use dashmap::DashSet;
use rand::RngCore;
use shared::session::SessionId;

const MAX_TRIES: usize = 32;

pub struct SessionIdGenerator {
    borrowed: DashSet<SessionId>,
}

impl SessionIdGenerator {
    pub fn new() -> Self {
        SessionIdGenerator {
            borrowed: DashSet::new(),
        }
    }

    pub fn next(&self) -> Option<SessionId> {
        if self.borrowed.len() as u32 >= SessionId::MAX {
            return None;
        }

        let mut rng = rand::rng();
        for _ in 0..MAX_TRIES {
            let candidate = rng.next_u32();
            if self.borrowed.insert(candidate) {
                return Some(candidate);
            }
        }

        None
    }
    pub fn release(&self, number: &SessionId) {
        self.borrowed.remove(number);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::Arc;
    use tokio::task;

    #[tokio::test]
    async fn test_random_generation_parallel() {
        const THREADS: usize = 32;
        const IDS_PER_THREAD: usize = 256;

        let generator = Arc::new(SessionIdGenerator::new());

        let mut handles = Vec::new();
        for _ in 0..THREADS {
            let generator_clone = generator.clone();
            let handle = task::spawn(async move {
                let mut local = Vec::new();
                for _ in 0..IDS_PER_THREAD {
                    if let Some(id) = generator_clone.next() {
                        local.push(id);
                    }
                }
                local
            });
            handles.push(handle);
        }

        let mut all_ids = HashSet::new();
        for handle in handles {
            let ids = handle.await.unwrap();
            for id in ids {
                assert!(all_ids.insert(id), "Duplicate session ID: {id}");
            }
        }

        assert_eq!(all_ids.len(), THREADS * IDS_PER_THREAD);
    }
}
