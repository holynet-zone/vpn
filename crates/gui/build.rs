use std::env;
use std::path::PathBuf;

fn main() {
    let config = slint_build::CompilerConfiguration::new().with_style("fluent".into());
    slint_build::compile_with_config("ui/app.slint", config).unwrap();

    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("android") {
        build_android_dex();
    }
}

fn build_android_dex() {
    use android_build::{Dexer, JavaBuild};

    let java_src = "java/HolyNetAndroid.java";
    println!("cargo:rerun-if-changed={java_src}");

    let out_dir: PathBuf = env::var_os("OUT_DIR").unwrap().into();
    let class_dir = out_dir.join("java-classes");
    let _ = std::fs::remove_dir_all(&class_dir);
    std::fs::create_dir_all(&class_dir).expect("cannot create java-classes dir");

    let android_jar = android_build::android_jar(None)
        .expect("android.jar not found - install the SDK platform (and set ANDROID_HOME)");

    let o = JavaBuild::new()
        .file(java_src)
        .class_path(&android_jar)
        .classes_out_dir(&class_dir)
        .java_source_version(8)
        .java_target_version(8)
        .command()
        .expect("failed to build javac command")
        .args(["-encoding", "UTF-8"])
        .output()
        .expect("failed to run javac");
    if !o.status.success() {
        panic!("javac failed: {}", String::from_utf8_lossy(&o.stderr));
    }

    let o = Dexer::new()
        .android_jar(&android_jar)
        .class_path(&class_dir)
        .collect_classes(&class_dir)
        .expect("failed to collect .class list")
        .android_min_api(20)
        .out_dir(&out_dir)
        .command()
        .expect("failed to build d8 command")
        .output()
        .expect("failed to run d8");
    if !o.status.success() {
        panic!("d8 failed: {}", String::from_utf8_lossy(&o.stderr));
    }
}
