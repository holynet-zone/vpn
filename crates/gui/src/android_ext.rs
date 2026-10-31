use std::sync::OnceLock;

use jni::objects::{JByteArray, JClass, JObject, JString, JValue};
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

pub fn haptic_detent() {
    let r = with_helper(|env, activity, class| {
        env.call_static_method(
            class,
            jni_str!("hapticDetent"),
            jni_sig!("(Landroid/app/Activity;)V"),
            &[JValue::Object(activity)],
        )
        .map(|_| ())
    });
    if let Err(e) = r {
        eprintln!("[holynet] haptic_detent: {e:?}");
    }
}

/// Query the launchable apps installed on the device.
///
/// Returns `(package, label, category, is_system)` tuples. Empty on any failure
/// or on non-Android targets.
pub fn list_apps() -> Vec<(String, String, String, bool)> {
    with_class(|env, activity, class| {
        let res = env.call_static_method(
            class,
            jni_str!("listApps"),
            jni_sig!("(Landroid/app/Activity;)Ljava/lang/String;"),
            &[JValue::Object(activity)],
        )?;
        let obj = res.l()?;
        let jstr = env.cast_local::<JString>(obj)?;
        let raw = jstr.mutf8_chars(env)?.to_string();
        Ok(parse_app_list(&raw))
    })
    .unwrap_or_default()
}

fn parse_app_list(raw: &str) -> Vec<(String, String, String, bool)> {
    raw.lines()
        .filter_map(|line| {
            let mut it = line.split('\t');
            let pkg = it.next()?;
            let label = it.next().unwrap_or("");
            let cat = it.next().unwrap_or("");
            let sys = it.next().map(|s| s == "1").unwrap_or(false);
            if pkg.is_empty() {
                return None;
            }
            Some((pkg.to_string(), label.to_string(), cat.to_string(), sys))
        })
        .collect()
}

/// Fetch icons for the given packages in one JNI round-trip.
///
/// Each returned entry is the RGBA pixels (`size`×`size`) for the matching
/// package, or `None` if that app has no reachable icon.
pub fn app_icons(packages: &[String], size: i32) -> Vec<Option<Vec<u8>>> {
    if packages.is_empty() {
        return Vec::new();
    }
    let joined = packages.join("\t");
    let n = packages.len();
    with_class(move |env, activity, class| {
        let jpkgs = env.new_string(&joined)?;
        let res = env.call_static_method(
            class,
            jni_str!("appIcons"),
            jni_sig!("(Landroid/app/Activity;Ljava/lang/String;I)[B"),
            &[
                JValue::Object(activity),
                JValue::Object(&jpkgs),
                JValue::Int(size),
            ],
        )?;
        let obj = res.l()?;
        let arr = env.cast_local::<JByteArray>(obj)?;
        let bytes = env.convert_byte_array(&arr)?;
        Ok(split_icon_blob(&bytes, n))
    })
    .unwrap_or_else(|| vec![None; n])
}

fn split_icon_blob(bytes: &[u8], n: usize) -> Vec<Option<Vec<u8>>> {
    let mut out = Vec::with_capacity(n);
    let mut off = 0usize;
    for _ in 0..n {
        if off + 4 > bytes.len() {
            out.push(None);
            continue;
        }
        let len = u32::from_be_bytes([
            bytes[off],
            bytes[off + 1],
            bytes[off + 2],
            bytes[off + 3],
        ]) as usize;
        off += 4;
        if len == 0 || off + len > bytes.len() {
            out.push(None);
        } else {
            out.push(Some(bytes[off..off + len].to_vec()));
            off += len;
        }
    }
    out
}

fn with_helper<F>(f: F) -> Result<(), jni::errors::Error>
where
    F: FnOnce(&mut Env, &JObject, &JClass) -> Result<(), jni::errors::Error>,
{
    with_class(f);
    Ok(())
}

fn with_class<T, F>(f: F) -> Option<T>
where
    F: FnOnce(&mut Env, &JObject, &JClass) -> Result<T, jni::errors::Error>,
{
    let (Some(&vm_ptr), Some(&act_ptr)) = (VM_PTR.get(), ACTIVITY_PTR.get()) else {
        return None;
    };

    let vm = unsafe { JavaVM::from_raw(vm_ptr as *mut sys::JavaVM) };
    let r = vm.attach_current_thread(|env: &mut Env| -> Result<T, jni::errors::Error> {
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
    });

    match r {
        Ok(v) => Some(v),
        Err(e) => {
            eprintln!("[holynet] jni call failed: {e:?}");
            None
        }
    }
}
