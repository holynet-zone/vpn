use std::net::UdpSocket;

fn main() -> std::io::Result<()> {
    {
        let socket = UdpSocket::bind("127.0.0.1:34254")?;
        
        let mut buffer = [0; 1024];
        let (amt, src) = socket.recv_from(&mut buffer)?;
        print!("Received: ");
        for i in 0..amt {
            print!("{}", buffer[i] as char);
        }

        let buffer = &mut buffer[..amt];
        buffer.reverse();
        socket.send_to(buffer, &src)?;
    }
    Ok(())
}
