#!/usr/bin/env bash
#
# Сборка/запуск holynet-gui под Android через xbuild (инструмент `x`).
#
# Требования (см. подсказки от `doctor`):
#   - Android SDK + NDK, переменные ANDROID_HOME и ANDROID_NDK_ROOT
#   - adb в PATH (platform-tools)
#   - clang (нужен рендереру Skia)
#   - rustup target для выбранной ABI
#   - xbuild:  cargo install --git https://github.com/rust-mobile/xbuild.git
#
# См. `crates/gui/scripts/android-build.sh --help`.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$CRATE_DIR/../.." && pwd)"
PKG="holynet-gui"
# applicationId в APK (задаётся xbuild из имени пакета); нужен для adb install/launch.
APP_ID="com.example.holynet_gui"

die()  { printf '\033[1;31mОшибка:\033[0m %s\n' "$*" >&2; exit 1; }
info() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mВнимание:\033[0m %s\n' "$*" >&2; }

usage() {
    cat <<'EOF'
Сборка/запуск/поставка holynet-gui под Android через xbuild (инструмент `x`).

Использование:
  crates/gui/scripts/android-build.sh doctor            # x doctor: проверка инструментов
  crates/gui/scripts/android-build.sh devices           # список устройств/эмуляторов
  crates/gui/scripts/android-build.sh build  [опции]    # собрать APK (+подписать)
  crates/gui/scripts/android-build.sh deploy [опции]    # собрать → подписать → поставить → запустить (adb, USB/Wi-Fi)
  crates/gui/scripts/android-build.sh run    [опции]    # то же через xbuild (x run)
  crates/gui/scripts/android-build.sh logs              # adb logcat -s slint

Опции:
  --release        release-сборка (по умолчанию debug)
  --arch <a>       arm64 | arm | x64 | x86   (по умолчанию arm64)
  --device <id>    для deploy: adb-serial (напр. 58121FDCR00951) или adb:<id>;
                   для run: id из `devices`. Если не задан — первое устройство.
  --no-sign        не подписывать APK (тогда deploy/adb install может не поставить)

Примеры:
  crates/gui/scripts/android-build.sh deploy --release      # собрать и залить на телефон одной строкой
  crates/gui/scripts/android-build.sh build --release
  crates/gui/scripts/android-build.sh run --arch x64 --device adb:emulator-5554

ANDROID_HOME определяется автоматически (~/Android/Sdk), adb добавляется в PATH.
EOF
}

# ANDROID_HOME по умолчанию + adb из platform-tools в PATH, чтобы не экспортировать вручную.
if [ -z "${ANDROID_HOME:-}" ] && [ -z "${ANDROID_SDK_ROOT:-}" ] && [ -d "$HOME/Android/Sdk" ]; then
    export ANDROID_HOME="$HOME/Android/Sdk"
fi
SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
if [ -n "$SDK" ] && [ -d "$SDK/platform-tools" ]; then
    case ":$PATH:" in *":$SDK/platform-tools:"*) ;; *) PATH="$SDK/platform-tools:$PATH" ;; esac
fi

# --- разбор аргументов ---------------------------------------------------------
CMD="${1:-build}"
[ $# -gt 0 ] && shift || true

PROFILE="debug"
ARCH="arm64"
DEVICE=""
SIGN=1

while [ $# -gt 0 ]; do
    case "$1" in
        --release) PROFILE="release" ;;
        --arch)    ARCH="${2:?--arch требует значение}"; shift ;;
        --device)  DEVICE="${2:?--device требует значение}"; shift ;;
        --no-sign) SIGN=0 ;;
        -h|--help) usage; exit 0 ;;
        *) die "неизвестный аргумент: $1" ;;
    esac
    shift
done

# ABI -> rust target (для проверки установленного таргета)
case "$ARCH" in
    arm64) RUST_TARGET="aarch64-linux-android" ;;
    arm)   RUST_TARGET="armv7-linux-androideabi" ;;
    x64)   RUST_TARGET="x86_64-linux-android" ;;
    x86)   RUST_TARGET="i686-linux-android" ;;
    *) die "неизвестная arch '$ARCH' (arm64|arm|x64|x86)" ;;
esac

# --- проверки окружения --------------------------------------------------------
check_xbuild() {
    command -v x >/dev/null 2>&1 || die \
"xbuild не найден. Установить:
    cargo install --git https://github.com/rust-mobile/xbuild.git"
}

check_build_env() {
    command -v clang >/dev/null 2>&1 || warn "clang не найден в PATH — рендерер Skia не соберётся"

    if [ -z "${ANDROID_NDK_ROOT:-}" ] && [ -z "${ANDROID_NDK_HOME:-}" ]; then
        warn "ANDROID_NDK_ROOT не задан — xbuild может не найти NDK"
    fi
    [ -z "${ANDROID_HOME:-}" ] && [ -z "${ANDROID_SDK_ROOT:-}" ] \
        && warn "ANDROID_HOME не задан — xbuild может не найти SDK"

    if ! rustup target list --installed 2>/dev/null | grep -qx "$RUST_TARGET"; then
        die "rust-таргет '$RUST_TARGET' не установлен. Поставить:
    rustup target add $RUST_TARGET"
    fi
}

# первое устройство из `x devices` (первый столбец первой строки), если --device не задан
autodetect_device() {
    DEVICE="$(cd "$CRATE_DIR" && x devices 2>/dev/null | awk 'NF{print $1; exit}')"
    [ -n "$DEVICE" ] || die "устройств не найдено. Запусти эмулятор или подключи телефон, см. \`$0 devices\`"
    info "устройство не задано, выбрано: $DEVICE"
}

release_flag() { [ "$PROFILE" = "release" ] && printf -- "--release"; }

# adb: из PATH (мы уже добавили platform-tools) либо напрямую из SDK.
adb_bin() {
    if command -v adb >/dev/null 2>&1; then command -v adb
    elif [ -n "$SDK" ] && [ -x "$SDK/platform-tools/adb" ]; then printf '%s\n' "$SDK/platform-tools/adb"
    else return 1; fi
}

# Собрать APK и (если SIGN=1) подписать. Путь к готовому APK -> в RESULT_APK.
RESULT_APK=""
build_and_sign() {
    info "сборка APK: arch=$ARCH profile=$PROFILE package=$PKG"
    ( cd "$CRATE_DIR" && x build --platform android --arch "$ARCH" --format apk $(release_flag) )
    local apk
    apk="$(find "$REPO_ROOT/target/x/$PROFILE/android" -maxdepth 1 -name '*.apk' ! -name '*-signed.apk' 2>/dev/null | head -n1 || true)"
    [ -n "$apk" ] || die "APK не найден в target/x/$PROFILE/android — см. вывод xbuild выше"
    if [ "$SIGN" = "1" ]; then
        local signed; signed="$(sign_apk "$apk" | tail -n1)"
        if [ -n "$signed" ] && [ -f "$signed" ]; then
            RESULT_APK="$signed"
        else
            warn "подпись не выполнена — беру неподписанный (может не установиться)"
            RESULT_APK="$apk"
        fi
    else
        RESULT_APK="$apk"
    fi
}

# Подписать APK debug-ключом (x build APK не подписывает → не ставится).
# Выводит путь к подписанному *-signed.apk через stdout последней строкой.
sign_apk() {
    local in="$1"
    local sdk="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
    [ -n "$sdk" ] || { warn "ANDROID_HOME не задан — пропускаю подпись"; return 1; }
    local bt; bt="$(ls -d "$sdk"/build-tools/*/ 2>/dev/null | sort -V | tail -n1)"
    [ -n "$bt" ] || { warn "build-tools не найдены в SDK — пропускаю подпись"; return 1; }
    local ks="$HOME/.android/debug.keystore"
    if [ ! -f "$ks" ]; then
        mkdir -p "$HOME/.android"
        keytool -genkeypair -keystore "$ks" -storepass android -keypass android \
            -alias androiddebugkey -keyalg RSA -keysize 2048 -validity 10000 \
            -dname "CN=Android Debug,O=Android,C=US" >/dev/null 2>&1 \
            || { warn "не удалось создать debug.keystore"; return 1; }
        info "создан $ks"
    fi
    local out="${in%.apk}-signed.apk"
    "${bt}zipalign" -f -p 4 "$in" "$out.tmp" >/dev/null 2>&1 || { warn "zipalign не удался"; return 1; }
    "${bt}apksigner" sign --ks "$ks" --ks-pass pass:android \
        --ks-key-alias androiddebugkey --out "$out" "$out.tmp" >/dev/null 2>&1 \
        || { warn "apksigner не удался"; rm -f "$out.tmp"; return 1; }
    rm -f "$out.tmp" "$out.idsig" 2>/dev/null || true
    printf '%s\n' "$out"
}

# --- команды -------------------------------------------------------------------
case "$CMD" in
    -h|--help|help)
        usage
        exit 0
        ;;

    doctor)
        check_xbuild
        exec sh -c "cd '$CRATE_DIR' && x doctor"
        ;;

    devices)
        check_xbuild
        exec sh -c "cd '$CRATE_DIR' && x devices"
        ;;

    build)
        check_xbuild
        check_build_env
        build_and_sign
        info "готово: $RESULT_APK"
        if [ "$SIGN" = "1" ]; then
            [ "$PROFILE" = "release" ] && info "поставить на телефон: $0 deploy --release" \
                                       || info "поставить на телефон: $0 deploy"
        fi
        ;;

    deploy)
        check_xbuild
        check_build_env
        ADB="$(adb_bin)" || die "adb не найден (нет platform-tools в SDK и в PATH)"
        SFLAG=""
        [ -n "$DEVICE" ] && SFLAG="-s ${DEVICE#adb:}"
        # Проверим, что устройство на связи (USB или уже подключённый Wi-Fi adb).
        if ! "$ADB" $SFLAG get-state >/dev/null 2>&1; then
            warn "adb не видит устройство. Подключи по USB (с разрешённой отладкой) либо"
            warn "по Wi-Fi: '$ADB pair <ip:порт> <код>' затем '$ADB connect <ip:порт>'."
            die "устройство недоступно"
        fi
        build_and_sign
        info "установка: $RESULT_APK"
        OUT="$("$ADB" $SFLAG install -r "$RESULT_APK" 2>&1)" || true
        printf '%s\n' "$OUT"
        if ! printf '%s' "$OUT" | grep -q "Success"; then
            if printf '%s' "$OUT" | grep -q "INSTALL_FAILED_UPDATE_INCOMPATIBLE\|signatures do not match"; then
                warn "подпись отличается от установленной — удаляю старую версию и ставлю заново"
                "$ADB" $SFLAG uninstall "$APP_ID" >/dev/null 2>&1 || true
                "$ADB" $SFLAG install -r "$RESULT_APK"
            else
                die "установка не удалась (см. вывод adb выше)"
            fi
        fi
        info "запуск $APP_ID"
        "$ADB" $SFLAG shell monkey -p "$APP_ID" -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1 || true
        info "готово. Логи: $0 logs"
        ;;

    run)
        check_xbuild
        check_build_env
        [ -n "$DEVICE" ] || autodetect_device
        info "запуск на $DEVICE: arch=$ARCH profile=$PROFILE"
        exec sh -c "cd '$CRATE_DIR' && x run --device '$DEVICE' --arch '$ARCH' $(release_flag)"
        ;;

    logs)
        command -v adb >/dev/null 2>&1 || die "adb не найден в PATH (добавь \$ANDROID_HOME/platform-tools)"
        exec adb logcat -s slint
        ;;

    *)
        die "неизвестная команда '$CMD' (doctor|devices|build|deploy|run|logs). См. --help"
        ;;
esac
