use std::sync::OnceLock;

use jni::objects::{JClass, JObject, JValue};
use jni::{Env, JavaVM, jni_sig, jni_str, sys};
use slint::android::AndroidApp;

static VM_PTR: OnceLock<usize> = OnceLock::new();
static ACTIVITY_PTR: OnceLock<usize> = OnceLock::new();

const DEX: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/classes.dex"));

pub fn init(app: &AndroidApp) {
    let _ = VM_PTR.set(app.vm_as_ptr() as usize);
    let _ = ACTIVITY_PTR.set(app.activity_as_ptr() as usize);
}

pub fn set_light_system_bars(light: bool) {
    let r = with_helper(|env, activity, class| {
        env.call_static_method(
            class,
            jni_str!("setLightSystemBars"),
            jni_sig!("(Landroid/app/Activity;Z)V"),
            &[JValue::Object(activity), JValue::Bool(light)],
        )
        .map(|_| ())
    });
    if let Err(e) = r {
        eprintln!("[holynet] set_light_system_bars: {e:?}");
    }
}

pub fn open_url(url: &str) {
    let url = url.to_string();
    let r = with_helper(move |env, activity, class| {
        let jurl = env.new_string(&url)?;
        env.call_static_method(
            class,
            jni_str!("openUrl"),
            jni_sig!("(Landroid/app/Activity;Ljava/lang/String;)V"),
            &[JValue::Object(activity), JValue::Object(&jurl)],
        )
        .map(|_| ())
    });
    if let Err(e) = r {
        eprintln!("[holynet] open_url: {e:?}");
    }
}

pub fn request_high_refresh_rate() {
    let r = with_helper(|env, activity, class| {
        env.call_static_method(
            class,
            jni_str!("requestHighRefreshRate"),
            jni_sig!("(Landroid/app/Activity;)V"),
            &[JValue::Object(activity)],
        )
        .map(|_| ())
    });
    if let Err(e) = r {
        eprintln!("[holynet] request_high_refresh_rate: {e:?}");
    }
}

fn with_helper<F>(f: F) -> Result<(), jni::errors::Error>
where
    F: FnOnce(&mut Env, &JObject, &JClass) -> Result<(), jni::errors::Error>,
{
    let (Some(&vm_ptr), Some(&act_ptr)) = (VM_PTR.get(), ACTIVITY_PTR.get()) else {
        return Ok(());
    };

    let vm = unsafe { JavaVM::from_raw(vm_ptr as *mut sys::JavaVM) };
    vm.attach_current_thread(|env: &mut Env| -> Result<(), jni::errors::Error> {
        let activity = unsafe { JObject::from_raw(env, act_ptr as sys::jobject) };

        let ctx_loader = env
            .call_method(
                &activity,
                jni_str!("getClassLoader"),
                jni_sig!("()Ljava/lang/ClassLoader;"),
                &[],
            )?
            .l()?;

        let dex_buf = unsafe { env.new_direct_byte_buffer(DEX.as_ptr() as *mut u8, DEX.len()) }?;
        let dex_loader = env.new_object(
            jni_str!("dalvik/system/InMemoryDexClassLoader"),
            jni_sig!("(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V"),
            &[JValue::Object(&dex_buf), JValue::Object(&ctx_loader)],
        )?;

        let name = env.new_string("dev.holynet.gui.HolyNetAndroid")?;
        let class_obj = env
            .call_method(
                &dex_loader,
                jni_str!("loadClass"),
                jni_sig!("(Ljava/lang/String;)Ljava/lang/Class;"),
                &[JValue::Object(&name)],
            )?
            .l()?;
        let class = env.cast_local::<JClass>(class_obj)?;

        f(env, &activity, &class)
    })
}
