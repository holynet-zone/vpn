use slint::{Brush, Color, SharedString};

use crate::{
    Accent, ChainStep, CipherInfo, DeviceInfo, KeyValue, Lang, PaletteCard, SplitApp, ToggleInfo,
    TransportInfo,
};

fn s(v: &str) -> SharedString {
    v.into()
}

fn hex(rgb: u32) -> Brush {
    let r = ((rgb >> 16) & 0xff) as u8;
    let g = ((rgb >> 8) & 0xff) as u8;
    let b = (rgb & 0xff) as u8;
    Brush::SolidColor(Color::from_rgb_u8(r, g, b))
}

fn tr<'a>(lang: Lang, en: &'a str, ru: &'a str, zh: &'a str, ja: &'a str) -> &'a str {
    match lang {
        Lang::Ru => ru,
        Lang::Zh => zh,
        Lang::Ja => ja,
        _ => en,
    }
}

type L4 = (&'static str, &'static str, &'static str, &'static str);
const TRANSPORTS: &[(&str, &str, L4, L4)] = &[
    (
        "udp",
        "UDP",
        (
            "UDP — direct channel",
            "UDP — прямой канал",
            "UDP — 直连通道",
            "UDP — 直接チャネル",
        ),
        (
            "Lowest latency. First choice while the network lets it through.",
            "Минимальная задержка. Первый выбор, пока сеть его пропускает.",
            "延迟最低。只要网络允许就优先选用。",
            "最小の遅延。ネットワークが通す限り第一候補です。",
        ),
    ),
    (
        "ws",
        "WS",
        (
            "WebSocket over TLS",
            "WebSocket поверх TLS",
            "基于 TLS 的 WebSocket",
            "TLS 上の WebSocket",
        ),
        (
            "Indistinguishable from ordinary web traffic; passes CDNs and corporate proxies.",
            "Неотличим от обычного веб-трафика, проходит через CDN и корпоративные прокси.",
            "与普通网页流量无异，可穿过 CDN 和企业代理。",
            "通常のウェブ通信と区別できず、CDN や企業プロキシを通過します。",
        ),
    ),
    (
        "vk",
        "VK",
        (
            "Tunnel over VK calls",
            "Тоннель через VK-звонки",
            "通过 VK 通话隧道",
            "VK 通話経由のトンネル",
        ),
        (
            "Traffic hides inside a call media stream — works where only allow-lists are open.",
            "Трафик прячется в медиапоток звонка — работает там, где открыты только белые списки.",
            "流量藏在通话媒体流中 — 在仅开放白名单的网络也能用。",
            "通信を通話メディアに隠します — 許可リストのみ開放の環境でも動作します。",
        ),
    ),
    (
        "quic",
        "QUIC",
        (
            "QUIC over HTTP/3",
            "QUIC поверх HTTP/3",
            "基于 HTTP/3 的 QUIC",
            "HTTP/3 上の QUIC",
        ),
        (
            "Looks like ordinary browser traffic and survives network changes.",
            "Выглядит как обычный трафик браузера, держит канал при смене сети.",
            "看起来像普通浏览器流量，网络切换也不中断。",
            "通常のブラウザ通信のように見え、ネットワーク変更にも耐えます。",
        ),
    ),
    (
        "dns",
        "DNS",
        (
            "Tunnel inside DNS queries",
            "Туннель в DNS-запросах",
            "DNS 查询内隧道",
            "DNS クエリ内のトンネル",
        ),
        (
            "Slow, but gets through where only DNS is open: hotels, airports, campuses.",
            "Медленно, но проходит там, где открыт только DNS: отели, аэропорты, кампусы.",
            "较慢，但在仅开放 DNS 的环境可用：酒店、机场、校园。",
            "低速ですが DNS のみ開放の環境（ホテル・空港・キャンパス）を通過します。",
        ),
    ),
];

const CIPHERS: &[(&str, L4)] = &[
    (
        "ChaCha20-Poly1305",
        (
            "faster on phones without AES-NI",
            "быстрее на телефонах без AES-NI",
            "在无 AES-NI 的手机上更快",
            "AES-NI 非搭載の端末で高速",
        ),
    ),
    (
        "AES-256-GCM",
        (
            "hardware accelerated on desktop",
            "аппаратное ускорение на ПК",
            "在桌面端有硬件加速",
            "デスクトップでハードウェア高速化",
        ),
    ),
];

const TOGGLES: &[(&str, L4, L4)] = &[
    (
        "kill",
        ("Kill switch", "Kill switch", "断网保护", "キルスイッチ"),
        (
            "Cut traffic if the channel drops",
            "Обрубить трафик, если канал упал",
            "通道断开时切断流量",
            "チャネル切断時に通信を遮断",
        ),
    ),
    (
        "auto",
        ("Auto-connect", "Автоподключение", "自动连接", "自動接続"),
        (
            "On unknown Wi-Fi networks",
            "В незнакомых Wi-Fi сетях",
            "在陌生 Wi-Fi 网络下",
            "未知の Wi-Fi ネットワークで",
        ),
    ),
    (
        "blocker",
        (
            "Tracker blocking",
            "Блокировка трекеров",
            "拦截追踪器",
            "トラッカーブロック",
        ),
        (
            "DNS-level filter",
            "Фильтр на уровне DNS",
            "DNS 层过滤",
            "DNS レベルのフィルタ",
        ),
    ),
    (
        "lan",
        (
            "Local network",
            "Локальная сеть",
            "本地网络",
            "ローカルネットワーク",
        ),
        (
            "Printers and NAS bypass the channel",
            "Принтеры и NAS в обход канала",
            "打印机和 NAS 绕过通道",
            "プリンタや NAS はチャネルを迂回",
        ),
    ),
];

const APPS: &[L4] = &[
    ("Browser", "Браузер", "浏览器", "ブラウザ"),
    ("Messenger", "Мессенджер", "即时通讯", "メッセンジャー"),
    ("Banking", "Банк", "银行", "銀行"),
    ("Games", "Игры", "游戏", "ゲーム"),
    ("Streaming", "Стриминг", "流媒体", "ストリーミング"),
    (
        "Work VPN client",
        "Рабочий VPN-клиент",
        "工作 VPN 客户端",
        "業務用 VPN クライアント",
    ),
];

const DEVICES: &[(&str, L4, L4, i32)] = &[
    (
        "PHONE",
        ("Pixel 8", "Pixel 8", "Pixel 8", "Pixel 8"),
        (
            "Android · Moscow",
            "Android · Москва",
            "Android · 莫斯科",
            "Android · モスクワ",
        ),
        0,
    ),
    (
        "LAPTOP",
        ("MacBook Air", "MacBook Air", "MacBook Air", "MacBook Air"),
        (
            "macOS · Moscow",
            "macOS · Москва",
            "macOS · 莫斯科",
            "macOS · モスクワ",
        ),
        1,
    ),
    (
        "DESK",
        ("Home PC", "Домашний ПК", "家用电脑", "自宅 PC"),
        (
            "Windows · Kazan",
            "Windows · Казань",
            "Windows · 喀山",
            "Windows · カザン",
        ),
        1,
    ),
    (
        "TAB",
        ("iPad", "iPad", "iPad", "iPad"),
        (
            "iPadOS · offline 3d",
            "iPadOS · офлайн 3 дня",
            "iPadOS · 离线 3 天",
            "iPadOS · オフライン 3日",
        ),
        2,
    ),
];

type Swatch = (u32, u32, u32);
type PaletteDef = (Accent, &'static str, L4, Swatch, Swatch);
const PALETTES: &[PaletteDef] = &[
    (
        Accent::Halo,
        "Halo",
        (
            "warm paper, gold and signal",
            "тёплая бумага, золото и сигнал",
            "暖纸、金色与信号",
            "暖かい紙・金・シグナル",
        ),
        (0xbd6f15, 0x007d9b, 0xfbf7ef),
        (0xf1bf55, 0x4dd3dd, 0x140f08),
    ),
    (
        Accent::Tide,
        "Tide",
        (
            "sea mint and indigo",
            "морская мята и индиго",
            "海薄荷与靛蓝",
            "海のミントとインディゴ",
        ),
        (0x008b76, 0x236cb5, 0xecf9f9),
        (0x57dcb4, 0x7dc0ff, 0x061116),
    ),
    (
        Accent::Ember,
        "Ember",
        (
            "clay, coral and plum",
            "розовая глина, коралл и слива",
            "陶土、珊瑚与李紫",
            "クレイ・コーラル・プラム",
        ),
        (0xc7513c, 0x7c54ae, 0xfff4f0),
        (0xff9977, 0xc4a4fe, 0x180c0c),
    ),
    (
        Accent::Iris,
        "Iris",
        (
            "lavender and azure",
            "лаванда и лазурь",
            "薰衣草与天蓝",
            "ラベンダーとアズュール",
        ),
        (0x825abc, 0x1476b6, 0xf7f4fe),
        (0xd1a8ff, 0x7dc0ff, 0x110d18),
    ),
    (
        Accent::Moss,
        "Moss",
        (
            "olive and turquoise, quiet",
            "олива и бирюза, тихий тон",
            "橄榄与青绿，安静",
            "オリーブとターコイズ、静か",
        ),
        (0x477735, 0x007a86, 0xf4f8ec),
        (0x86d489, 0x61ced4, 0x0b1109),
    ),
    (
        Accent::Ink,
        "Ink",
        (
            "graphite with an amber spark",
            "графит с янтарной искрой",
            "石墨与琥珀火花",
            "グラファイトと琥珀の輝き",
        ),
        (0xa26000, 0x474d58, 0xf3f4f7),
        (0xf2b95a, 0xb3b8bf, 0x0c0d10),
    ),
];

pub struct TransportRow {
    pub name: String,
    pub title: String,
    pub desc: String,
}

pub fn transport_rows(lang: Lang, current: &str) -> (Vec<TransportInfo>, TransportRow) {
    let mut rows = Vec::new();
    let mut sel = TransportRow {
        name: String::new(),
        title: String::new(),
        desc: String::new(),
    };
    for &(id, name, t, d) in TRANSPORTS {
        let title = tr(lang, t.0, t.1, t.2, t.3).to_string();
        let desc = tr(lang, d.0, d.1, d.2, d.3).to_string();
        if id == current {
            sel = TransportRow {
                name: name.to_string(),
                title: title.clone(),
                desc: desc.clone(),
            };
        }
        rows.push(TransportInfo {
            id: s(id),
            name: s(name),
            title: s(&title),
            desc: s(&desc),
            selected: id == current,
        });
    }
    (rows, sel)
}

pub fn cipher_rows(lang: Lang, current: usize) -> (Vec<CipherInfo>, String) {
    let mut rows = Vec::new();
    let mut name = String::new();
    for (i, &(n, h)) in CIPHERS.iter().enumerate() {
        if i == current {
            name = n.to_string();
        }
        rows.push(CipherInfo {
            name: s(n),
            hint: s(tr(lang, h.0, h.1, h.2, h.3)),
            selected: i == current,
        });
    }
    (rows, name)
}

pub fn chain(current: &str) -> Vec<ChainStep> {
    let n = TRANSPORTS.len();
    TRANSPORTS
        .iter()
        .enumerate()
        .map(|(i, &(id, name, ..))| ChainStep {
            code: s(name),
            active: id == current,
            last: i == n - 1,
        })
        .collect()
}

pub fn toggle_rows(lang: Lang, on: &[bool; 4]) -> Vec<ToggleInfo> {
    TOGGLES
        .iter()
        .enumerate()
        .map(|(i, &(id, n, h))| ToggleInfo {
            id: s(id),
            name: s(tr(lang, n.0, n.1, n.2, n.3)),
            hint: s(tr(lang, h.0, h.1, h.2, h.3)),
            on: on[i],
        })
        .collect()
}

pub fn toggle_index(id: &str) -> Option<usize> {
    TOGGLES.iter().position(|&(k, ..)| k == id)
}

pub fn app_rows(lang: Lang, on: &[bool]) -> Vec<SplitApp> {
    APPS.iter()
        .enumerate()
        .map(|(i, &n)| {
            let name = tr(lang, n.0, n.1, n.2, n.3);
            SplitApp {
                name: s(name),
                letter: s(&name.chars().next().unwrap_or('•').to_string()),
                tunneled: on.get(i).copied().unwrap_or(false),
            }
        })
        .collect()
}

pub fn device_rows(lang: Lang) -> Vec<DeviceInfo> {
    DEVICES
        .iter()
        .map(|&(kind, n, m, state)| {
            let tag = match state {
                0 => tr(lang, "active", "сейчас", "当前", "使用中"),
                2 => tr(lang, "offline", "офлайн", "离线", "オフライン"),
                _ => tr(lang, "online", "онлайн", "在线", "オンライン"),
            };
            DeviceInfo {
                kind: s(kind),
                name: s(tr(lang, n.0, n.1, n.2, n.3)),
                meta: s(tr(lang, m.0, m.1, m.2, m.3)),
                tag: s(tag),
                state,
            }
        })
        .collect()
}

pub fn proto_rows(lang: Lang, cipher: &str, transport: &str) -> Vec<KeyValue> {
    let mtu = if transport == "udp" { "1380" } else { "1200" };
    let rows = [
        (
            tr(lang, "Key exchange", "Обмен ключами", "密钥交换", "鍵交換"),
            "X25519".to_string(),
        ),
        (
            tr(lang, "Cipher", "Шифр", "密码", "暗号"),
            cipher.to_string(),
        ),
        (
            tr(
                lang,
                "Padding obfuscation",
                "Padding-обфускация",
                "填充混淆",
                "パディング難読化",
            ),
            tr(lang, "on", "вкл.", "开启", "オン").to_string(),
        ),
        ("MTU", mtu.to_string()),
        (
            "Keepalive",
            tr(lang, "15 s", "15 с", "15 秒", "15 秒").to_string(),
        ),
    ];
    rows.into_iter()
        .map(|(k, v)| KeyValue {
            key: s(k),
            value: s(&v),
        })
        .collect()
}

pub fn palette_rows(lang: Lang, dark: bool, current: Accent) -> Vec<PaletteCard> {
    PALETTES
        .iter()
        .enumerate()
        .map(|(i, &(accent, name, h, light, darkc))| {
            let (a1, a2, base) = if dark { darkc } else { light };
            PaletteCard {
                id: i as i32,
                name: s(name),
                hint: s(tr(lang, h.0, h.1, h.2, h.3)),
                sw1: hex(a1),
                sw2: hex(a2),
                base: hex(base),
                selected: accent == current,
            }
        })
        .collect()
}

pub fn accent_from_index(i: i32) -> Accent {
    PALETTES
        .get(i as usize)
        .map(|p| p.0)
        .unwrap_or(Accent::Halo)
}

pub fn transport_name(id: &str) -> &'static str {
    TRANSPORTS
        .iter()
        .find(|t| t.0 == id)
        .map(|t| t.1)
        .unwrap_or("UDP")
}

pub fn next_transport(id: &str) -> &'static str {
    let i = TRANSPORTS.iter().position(|t| t.0 == id).unwrap_or(0);
    TRANSPORTS[(i + 1) % TRANSPORTS.len()].0
}
