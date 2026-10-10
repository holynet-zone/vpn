slint::include_modules!();

mod about;
mod controller;
mod data;
mod domain;
mod globe;
mod land;
mod proto;
mod split;

#[cfg(target_os = "android")]
mod android_ext;

use controller::Controller;

pub fn run() -> Result<(), slint::PlatformError> {
    let window = AppWindow::new()?;
    #[cfg(not(target_os = "android"))]
    set_window_icon(&window);
    let _controller = Controller::new(&window);
    window.run()
}

#[cfg(not(target_os = "android"))]
fn set_window_icon(window: &AppWindow) {
    use slint::ComponentHandle;
    use slint::winit_030::{WinitWindowAccessor, winit};
    let Some(buf) = window.get_app_icon().to_rgba8() else { return };
    let (w, h) = (buf.width(), buf.height());
    let Ok(icon) = winit::window::Icon::from_rgba(buf.as_bytes().to_vec(), w, h) else {
        return;
    };
    window.window().with_winit_window(|ww| ww.set_window_icon(Some(icon.clone())));
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
fn android_main(app: slint::android::AndroidApp) {
    android_ext::init(&app);
    slint::android::init(app).unwrap();
    run().unwrap();
}
