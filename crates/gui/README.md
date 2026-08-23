# holynet-gui

Cross-platform HolyNet client

## Running

```sh
cargo run -p holynet-gui
```

## Android

Environment setup: Android SDK + NDK (`ANDROID_HOME`,
`ANDROID_NDK_ROOT`), `adb` in PATH, `clang`, the rust target and xbuild itself:

```sh
rustup target add aarch64-linux-android
cargo install --git https://github.com/rust-mobile/xbuild.git
```

Everything else goes through the `scripts/android-build.sh` wrapper (from the repository root):

```sh
scripts/android-build.sh doctor            # check tools (x doctor)
scripts/android-build.sh devices           # devices/emulators
scripts/android-build.sh run               # build + install + run
scripts/android-build.sh build --release   # APK → target/x/release/android/
```

Runtime logs: `scripts/android-build.sh logs` (`adb logcat -s slint`).
