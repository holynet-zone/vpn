#!/usr/bin/env bash
set -euo pipefail

# Лайв-предпросмотр .slint через slint-viewer, собранный из вендоренного форка
# (crates/gui/vendor/slint).
#
# Использование:
#   scripts/preview.sh                     # превью по умолчанию (preview_desktop)
#   scripts/preview.sh mobile              # ui/preview/preview_mobile.slint
#   scripts/preview.sh preview_shield      # можно с префиксом preview_
#   scripts/preview.sh ui/app.slint        # или явный путь к файлу
#   REBUILD=1 scripts/preview.sh           # пересобрать slint-viewer перед запуском

GUI_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENDOR_DIR="$GUI_DIR/vendor/slint"
VIEWER="$VENDOR_DIR/target/release/slint-viewer"

DEFAULT_PREVIEW="preview_desktop"
STYLE="${STYLE:-fluent}"
BACKEND="${BACKEND:-winit-skia}"

arg="${1:-$DEFAULT_PREVIEW}"

if [[ -f "$arg" ]]; then
    target="$arg"
elif [[ -f "$GUI_DIR/$arg" ]]; then
    target="$GUI_DIR/$arg"
else
    name="$arg"
    [[ "$name" == preview_* || "$name" == sample ]] || name="preview_$name"
    [[ "$name" == *.slint ]] || name="$name.slint"
    target="$GUI_DIR/ui/preview/$name"
fi

if [[ ! -f "$target" ]]; then
    echo "Файл превью не найден: $target" >&2
    echo "Доступные превью:" >&2
    for f in "$GUI_DIR"/ui/preview/*.slint; do echo "  - $(basename "$f" .slint)" >&2; done
    exit 1
fi

if [[ "${REBUILD:-0}" == "1" || ! -x "$VIEWER" ]]; then
    echo "Сборка slint-viewer из форка ($VENDOR_DIR)..." >&2
    cargo build --release --manifest-path "$VENDOR_DIR/Cargo.toml" -p slint-viewer
fi

echo "Предпросмотр: $target (style=$STYLE, backend=$BACKEND)" >&2
exec "$VIEWER" --auto-reload --style "$STYLE" --backend "$BACKEND" "$target"
