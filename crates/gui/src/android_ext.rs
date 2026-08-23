use std::sync::OnceLock;

use jni::objects::{JClass, JObject, JValue};
use jni::JavaVM;
use slint::android::AndroidApp;

static VM_PTR: OnceLock<usize> = OnceLock::new();
static ACTIVITY_PTR: OnceLock<usize> = OnceLock::new();

const DEX: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/classes.dex"));

pub fn init(app: &AndroidApp) {
    let _ = VM_PTR.set(app.vm_as_ptr() as usize);
    let _ = ACTIVITY_PTR.set(app.activity_as_ptr() as usize);
}

pub fn set_light_system_bars(light: bool) {
    if let Err(e) = try_set(light) {
        eprintln!("[holynet] set_light_system_bars: {e:?}");
    }
}

pub fn request_high_refresh_rate() {
    let r = with_helper(|env, activity, class| {
        env.call_static_method(
            class,
            "requestHighRefreshRate",
            "(Landroid/app/Activity;)V",
            &[JValue::Object(activity)],
        )
        .map(|_| ())
    });
    if let Err(e) = r {
        eprintln!("[holynet] request_high_refresh_rate: {e:?}");
    }
}

fn try_set(light: bool) -> Result<(), jni::errors::Error> {
    with_helper(|env, activity, class| {
        env.call_static_method(
            class,
            "setLightSystemBars",
            "(Landroid/app/Activity;Z)V",
            &[JValue::Object(activity), JValue::Bool(light as u8)],
        )
        .map(|_| ())
    })
}

fn with_helper<F>(f: F) -> Result<(), jni::errors::Error>
where
    F: FnOnce(&mut jni::JNIEnv, &JObject, &JClass) -> Result<(), jni::errors::Error>,
{
    let (Some(&vm_ptr), Some(&act_ptr)) = (VM_PTR.get(), ACTIVITY_PTR.get()) else {
        return Ok(());
    };

    let vm = unsafe { JavaVM::from_raw(vm_ptr as *mut jni::sys::JavaVM) }?;
    let mut env = vm.attach_current_thread()?;
    let activity = unsafe { JObject::from_raw(act_ptr as jni::sys::jobject) };

    let ctx_loader = env
        .call_method(&activity, "getClassLoader", "()Ljava/lang/ClassLoader;", &[])?
        .l()?;

    let dex_buf = unsafe { env.new_direct_byte_buffer(DEX.as_ptr() as *mut u8, DEX.len()) }?;
    let dex_loader = env.new_object(
        "dalvik/system/InMemoryDexClassLoader",
        "(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V",
        &[JValue::Object(dex_buf.as_ref()), JValue::Object(&ctx_loader)],
    )?;

    let name = env.new_string("dev.holynet.gui.HolyNetAndroid")?;
    let class_obj = env
        .call_method(
            &dex_loader,
            "loadClass",
            "(Ljava/lang/String;)Ljava/lang/Class;",
            &[JValue::Object(name.as_ref())],
        )?
        .l()?;
    let class = JClass::from(class_obj);

    f(&mut env, &activity, &class)
}
