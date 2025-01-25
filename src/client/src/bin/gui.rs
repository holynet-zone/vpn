// Prevents additional console window on Windows in release
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use tauri::command;

#[command]
fn get_runtimes() -> Vec<String> {
    vec![
        "SyncMIO".to_string(),
    ]
}


fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![get_runtimes])
        .run(tauri::generate_context!())
        .expect("error while running application");
}
