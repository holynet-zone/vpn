slint::include_modules!();

mod controller;
mod data;
mod domain;
mod globe;
mod land;

#[cfg(target_os = "android")]
mod android_ext;

use controller::Controller;

pub fn run() -> Result<(), slint::PlatformError> {
    let window = AppWindow::new()?;
    let _controller = Controller::new(&window);
    window.run()
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
fn android_main(app: slint::android::AndroidApp) {
    android_ext::init(&app);
    slint::android::init(app).unwrap();
    run().unwrap();
}
