use std::path::PathBuf;
use std::time::Duration;
use std::{process, thread};
use client::runtime::error::RuntimeError;
use client::runtime::Runtime;
use shared::connection_config::ConnectionConfig;
use shared::credential::Credential;

pub fn connect(config_path: Option<PathBuf>, key: Option<String>) -> anyhow::Result<()> {
    if config_path.is_some() && key.is_some() {
        return Err(anyhow::anyhow!("config and key cannot be used together"));
    }
    
    let mut config = if let Some(ref path) = config_path {
        ConnectionConfig::load(&*path)
    } else if let Some(key) = key {
        ConnectionConfig::from_base64(&*key)
    } else {
        return Err(anyhow::anyhow!("config or key is required"));
    }?;
    
    if config.runtime.is_none() {
        config.runtime = Some(shared::connection_config::Runtime::default());
    }
    
    if config.interface.is_none() {
        config.interface = Some(shared::connection_config::Interface {
            name: "holynet0".into(), // todo get from free
            mtu: 1420,
        });
    }
    
    if let Some(ref path) = config_path {
        config.save(&*path)?;
    }

    let runtime = Runtime::new(
        config.general.host.parse()?,
        config.general.port,
        config.general.alg,
        Credential {
            sk: config.credentials.private_key,
            psk: config.credentials.pre_shared_key,
            peer_pk: config.credentials.server_public_key,
        },
        Duration::from_millis(config.runtime.as_ref().unwrap().handshake_timeout),
        config.runtime.as_ref().unwrap().keepalive.map(|x| Duration::from_secs(x))
    );
    
    let stop_tx = runtime.stop_tx.clone();

    ctrlc::set_handler(move || {
        stop_tx.send(RuntimeError::StopSignal).unwrap();
        thread::sleep(Duration::from_secs(3));
        process::exit(0);
    }).expect("error setting Ctrl-C handler");
    
    runtime.run()
}