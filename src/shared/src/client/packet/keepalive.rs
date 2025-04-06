use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct KeepAliveBody {
    pub client_time: u128
}

impl KeepAliveBody {
    pub fn new() -> Self {
        Self {
            client_time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH).unwrap()
                .as_millis()
        }
    }
    
    pub fn owd(&self) -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap()
            .as_millis() - self.client_time
    }
}

