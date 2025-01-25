use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::process::Child;
use std::time::Instant;
use daemonize::Daemonize;
use log::{error, info};


struct VpnServer {
    id: String,
    started_at: Instant,
    process: Child,
}

struct VpnDaemon {
    servers: HashMap<String, VpnServer>
}


fn start_daemon() {
    let working_directory = "/tmp/holynet";
    let _ = fs::create_dir_all(working_directory).unwrap();
    let stdout = File::create(format!("{}/daemon.out", working_directory)).unwrap();
    let stderr = File::create(format!("{}/daemon.err", working_directory)).unwrap();

    let daemonize = Daemonize::new()
        .pid_file(format!("{}/daemon.pid", working_directory))
        .chown_pid_file(true)
        // .working_directory(working_directory)
        .stdout(stdout)
        .stderr(stderr);

    match daemonize.start() {
        Ok(_) => {
            let socket_path = format!("{}/daemon.sock", working_directory);
            let _ = fs::remove_file(&socket_path);
            let listener = UnixListener::bind(socket_path).unwrap();

            for stream in listener.incoming() {
                match stream {
                    Ok(mut stream) => {
                        let mut buffer = [0; 1024];
                        let n = stream.read(&mut buffer).unwrap();
                        let request = String::from_utf8_lossy(&buffer[..n]);
                        
                        let response = format!("Демон получил: {}", request);
                        stream.write_all(response.as_bytes()).unwrap();
                    }
                    Err(err) => {
                        eprintln!("Ошибка при подключении клиента: {}", err);
                    }
                }
            }
        }
        Err(e) => error!("Error starting daemon: {}", e),
    }
}
