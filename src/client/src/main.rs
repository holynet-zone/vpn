use std::net::UdpSocket;

fn main()  -> std::io::Result<()> {
    let socket = UdpSocket::bind("127.0.0.1:3400")?;
    socket.connect("127.0.0.1:34254")?;
    
    socket.send(b"hello world!")?;
    
    let mut buf = [0; 1024];
    let (amt, src) = socket.recv_from(&mut buf)?;
    
    println!("{} bytes received from {:?}", amt, src);
    println!("{:?}", &buf[..amt]);
    
    Ok(())
}
