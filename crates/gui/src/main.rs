#![cfg_attr(
    all(target_os = "windows", not(debug_assertions)),
    windows_subsystem = "windows"
)]

fn main() -> Result<(), slint::PlatformError> {
    holynet_gui::run()
}
