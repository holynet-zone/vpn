use std::time::Instant;

static APP_START_INSTANT: once_cell::sync::Lazy<Instant> = once_cell::sync::Lazy::new(Instant::now);


pub fn micros_since_start() -> u128 {
    APP_START_INSTANT.elapsed().as_micros()
}

pub fn sec_since_start() -> u64 {
    APP_START_INSTANT.elapsed().as_secs()
}


pub fn format_duration_millis(from_micros: u128, to_micros: u128) -> String {
    let diff_micros = to_micros.saturating_sub(from_micros);

    if diff_micros >= 1000 {
        format!("{} ms", diff_micros / 1000)
    } else {
        format!("{:.3} ms", diff_micros as f64 / 1000.0)
    }
}
