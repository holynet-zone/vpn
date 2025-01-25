use rand::Rng;

fn main() {
    let derivation_key: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(32) 
        .map(char::from)
        .collect();

    println!("cargo:rustc-env=DERIVATION_KEY={}", derivation_key);
}