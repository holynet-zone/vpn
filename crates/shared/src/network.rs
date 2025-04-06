use std::collections::HashSet;
use std::process::{Command, Stdio};
use pnet::datalink;

pub fn find_available_ifname(base_name: &str) -> String {
    let interfaces = datalink::interfaces();

    let existing_names: HashSet<String> = interfaces
        .into_iter()
        .map(|iface| iface.name)
        .collect();

    let mut index = 0;
    loop {
        let candidate = format!("{}{}", base_name, index);
        if !existing_names.contains(&candidate) {
            return candidate;
        }

        index += 1;
    }
}

pub fn set_ipv4_forwarding(value: bool) -> std::io::Result<()> {
    let sysctl_arg = if cfg!(target_os = "linux") {
        format!("net.ipv4.ip_forward={}", if value { 1 } else { 0 })
    } else if cfg!(target_os = "macos") {
        format!("net.inet.ip.forwarding={}", if value { 1 } else { 0 })
    } else {
        unimplemented!()
    };
    
    match Command::new("sysctl").arg("-w").arg(sysctl_arg)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status() {
        Ok(_) => Ok(()),
        Err(error) => Err(error)
    }
}
