use std::collections::HashSet;
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