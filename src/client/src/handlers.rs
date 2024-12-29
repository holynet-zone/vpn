use std::io::Write;
use mio::net::UdpSocket;
use tracing::{debug, info};
use tun::Device;
use common::Body;
use common::exceptions::CoreExceptions;

pub fn server_event(
    data: &[u8],
    tun: &mut Device,
) -> Result<(), CoreExceptions> {

    let packet = match Body::from_bytes(data) {
        Ok(packet) => packet,
        Err(error) => {
            return Err(CoreExceptions::BadPacketRequest(
                format!("Failed to deserialize packet: {}", error)
            ));
        }
    };
    
    match packet {
        Body::Data {data} => {
            tun.write(&data).unwrap();
            info!("Successfully wrote {} bytes to the tun interface", data.len());
            Ok(())
        },
        Body::KeepAliveResponse { server_timestamp, client_timestamp} => {
            let owd = server_timestamp - client_timestamp;
            let rtt = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() - client_timestamp;
   
            info!(
                "Received keep-alive from the server; One-Way Delay (OWD) = {}; Round Trip Time (RTT) = {}",
                if owd > rtt { "N/A".to_string() } else { owd.to_string() },
                rtt
            );
            Ok(())
        },
        _ => {
            Err(CoreExceptions::BadPacketRequest(
                "Unsupported packet type".to_string()
            ))
        }
    }
}

pub fn device_event(
    data: &[u8],
    udp: &mut UdpSocket,
) -> Result<(), CoreExceptions> {
    let packet = Body::Data { data: data.to_vec() };
    
    match udp.send(&packet.to_bytes().unwrap()) {
        Err(err) => Err(CoreExceptions::IOError(
            format!("Error sending packet to the server: {}", err)
        )),
        Ok(_) => {
            info!("Sent {} bytes to {} via udp", data.len(), udp.local_addr().unwrap());
            Ok(())
        }
    }
}
