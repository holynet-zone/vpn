use std::env;
use std::path::PathBuf;

fn main() {
    let config = slint_build::CompilerConfiguration::new().with_style("fluent".into());
    slint_build::compile_with_config("ui/app.slint", config).unwrap();

    generate_licenses();

    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("android") {
        build_android_dex();
    }
}

fn generate_licenses() {
    println!("cargo:rerun-if-changed=../../Cargo.lock");
    println!("cargo:rerun-if-changed=Cargo.toml");

    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("licenses.rs");
    let cargo = env::var("CARGO").unwrap_or_else(|_| "cargo".into());

    let output = std::process::Command::new(&cargo)
        .args(["metadata", "--format-version", "1"])
        .output();

    let list = match output {
        Ok(o) if o.status.success() => licenses_from_metadata(&o.stdout),
        _ => Vec::new(),
    };

    let mut src = String::from("pub static LICENSES: &[(&str, &str, &str)] = &[\n");
    for (name, version, license) in &list {
        src.push_str(&format!(
            "    ({:?}, {:?}, {:?}),\n",
            name, version, license
        ));
    }
    src.push_str("];\n");
    std::fs::write(&out, src).expect("cannot write licenses.rs");
}

fn licenses_from_metadata(bytes: &[u8]) -> Vec<(String, String, String)> {
    let v: serde_json::Value = match serde_json::from_slice(bytes) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let packages = v["packages"].as_array().cloned().unwrap_or_default();
    let members: std::collections::HashSet<String> = v["workspace_members"]
        .as_array()
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default();

    let mut meta = std::collections::HashMap::new();
    let mut gui_id = None;
    for p in &packages {
        let id = p["id"].as_str().unwrap_or_default().to_string();
        let name = p["name"].as_str().unwrap_or_default().to_string();
        let version = p["version"].as_str().unwrap_or_default().to_string();
        let license = p["license"]
            .as_str()
            .map(String::from)
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "см. license-file".into());
        if name == "holynet-gui" {
            gui_id = Some(id.clone());
        }
        meta.insert(id, (name, version, license));
    }

    let mut direct: std::collections::HashSet<String> = std::collections::HashSet::new();
    if let (Some(root), Some(nodes)) = (gui_id, v["resolve"]["nodes"].as_array()) {
        if let Some(node) = nodes.iter().find(|n| n["id"].as_str() == Some(root.as_str())) {
            if let Some(deps) = node["deps"].as_array() {
                for d in deps {
                    let is_normal = d["dep_kinds"]
                        .as_array()
                        .map(|ks| ks.iter().any(|k| k["kind"].is_null()))
                        .unwrap_or(true);
                    if is_normal {
                        if let Some(pkg) = d["pkg"].as_str() {
                            direct.insert(pkg.to_string());
                        }
                    }
                }
            }
        }
    }

    let mut out: Vec<(String, String, String)> = direct
        .iter()
        .filter(|id| !members.contains(*id))
        .filter_map(|id| meta.get(id).cloned())
        .collect();
    out.sort_by(|a, b| a.0.to_lowercase().cmp(&b.0.to_lowercase()).then(a.1.cmp(&b.1)));
    out.dedup_by(|a, b| a.0 == b.0 && a.1 == b.1);
    out
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
