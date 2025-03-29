use serde::{Deserialize, Serialize};


#[derive(Serialize, Deserialize)]
pub struct KeepAliveBody {
    server_time: u128,
    client_time: u128
}

impl KeepAliveBody {
    
    pub fn new(client_time: u128) -> Self {
        Self {
            server_time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH).unwrap()
                .as_millis(),
            client_time
        }
    }
    
    pub fn owd(&self) -> u128 {
        self.server_time - self.client_time
    }
    
    pub fn rtt(&self) -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap()
            .as_millis() - self.client_time
    }
    
}