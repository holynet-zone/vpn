use crate::Lang;
use crate::{AddHopChip, EdgeRow, Factor, GlobeNode, NodeRow, RouteHop, SpaceRow, Visibility};
use slint::{ModelRc, SharedString, VecModel};

type L4 = (&'static str, &'static str, &'static str, &'static str);

pub const MAX_HOPS: usize = 4;

struct Node {
    id: &'static str,
    code: &'static str,
    label: L4,
    group: L4,
    subnet: &'static str,
    ep: &'static str,
    lat: f32,
    lon: f32,
    rtt: i32,
    age: u32,
}

struct Edge {
    a: &'static str,
    b: &'static str,
    rtt: i32,
    stale: bool,
}

struct Space {
    id: &'static str,
    name: L4,
    ctl: &'static str,
    fp: &'static str,
    alg: &'static str,
    note: L4,
    nodes: &'static [&'static str],
}

const NODES: &[Node] = &[
    Node {
        id: "nl",
        code: "NL-C",
        label: ("Amsterdam", "Амстердам", "阿姆斯特丹", "アムステルダム"),
        group: ("Europe", "Европа", "欧洲", "ヨーロッパ"),
        subnet: "10.42.3.0/24",
        ep: "198.51.100.7:51820",
        lat: 52.37,
        lon: 4.9,
        rtt: 24,
        age: 12,
    },
    Node {
        id: "de",
        code: "DE-B",
        label: ("Frankfurt", "Франкфурт", "法兰克福", "フランクフルト"),
        group: ("Europe", "Европа", "欧洲", "ヨーロッパ"),
        subnet: "10.42.4.0/24",
        ep: "198.51.100.11:51820",
        lat: 50.11,
        lon: 8.68,
        rtt: 31,
        age: 12,
    },
    Node {
        id: "fi",
        code: "FI-A",
        label: ("Helsinki", "Хельсинки", "赫尔辛基", "ヘルシンキ"),
        group: ("Europe", "Европа", "欧洲", "ヨーロッパ"),
        subnet: "10.42.5.0/24",
        ep: "198.51.100.19:51820",
        lat: 60.17,
        lon: 24.94,
        rtt: 18,
        age: 12,
    },
    Node {
        id: "se",
        code: "SE-D",
        label: ("Stockholm", "Стокгольм", "斯德哥尔摩", "ストックホルム"),
        group: ("Europe", "Европа", "欧洲", "ヨーロッパ"),
        subnet: "10.42.6.0/24",
        ep: "198.51.100.23:51820",
        lat: 59.33,
        lon: 18.07,
        rtt: 27,
        age: 74,
    },
    Node {
        id: "us",
        code: "US-E",
        label: ("New York", "Нью-Йорк", "纽约", "ニューヨーク"),
        group: ("N. America", "Сев. Америка", "北美", "北米"),
        subnet: "10.42.9.0/24",
        ep: "203.0.113.8:51820",
        lat: 40.71,
        lon: -74.01,
        rtt: 88,
        age: 12,
    },
    Node {
        id: "ca",
        code: "CA-A",
        label: ("Toronto", "Торонто", "多伦多", "トロント"),
        group: ("N. America", "Сев. Америка", "北美", "北米"),
        subnet: "10.42.10.0/24",
        ep: "203.0.113.24:51820",
        lat: 43.65,
        lon: -79.38,
        rtt: 101,
        age: 74,
    },
    Node {
        id: "sg",
        code: "SG-A",
        label: ("Singapore", "Сингапур", "新加坡", "シンガポール"),
        group: ("Asia", "Азия", "亚洲", "アジア"),
        subnet: "10.42.20.0/24",
        ep: "192.0.2.40:51820",
        lat: 1.35,
        lon: 103.82,
        rtt: 181,
        age: 12,
    },
    Node {
        id: "jp",
        code: "JP-D",
        label: ("Tokyo", "Токио", "东京", "東京"),
        group: ("Asia", "Азия", "亚洲", "アジア"),
        subnet: "10.42.21.0/24",
        ep: "192.0.2.71:51820",
        lat: 35.68,
        lon: 139.65,
        rtt: -1,
        age: 0,
    },
];

const EDGES: &[Edge] = &[
    Edge { a: "nl", b: "de", rtt: 31, stale: false },
    Edge { a: "nl", b: "fi", rtt: 14, stale: false },
    Edge { a: "fi", b: "se", rtt: 11, stale: false },
    Edge { a: "de", b: "se", rtt: 26, stale: false },
    Edge { a: "nl", b: "us", rtt: 82, stale: false },
    Edge { a: "de", b: "us", rtt: 95, stale: false },
    Edge { a: "us", b: "ca", rtt: 44, stale: true },
    Edge { a: "nl", b: "ca", rtt: 96, stale: false },
    Edge { a: "us", b: "sg", rtt: 168, stale: false },
    Edge { a: "de", b: "sg", rtt: 152, stale: false },
    Edge { a: "sg", b: "jp", rtt: -1, stale: false },
];

const SPACES: &[Space] = &[
    Space {
        id: "core",
        name: ("HolyNet Core", "HolyNet Core", "HolyNet Core", "HolyNet Core"),
        ctl: "ctl.holynet.example:8443",
        fp: "…c8",
        alg: "noise-xk · chacha20",
        note: (
            "Public registry, 8 nodes",
            "Публичный реестр, 8 узлов",
            "公共注册表，8 个节点",
            "公開レジストリ・8 ノード",
        ),
        nodes: &["nl", "de", "fi", "se", "us", "ca", "sg", "jp"],
    },
    Space {
        id: "lab",
        name: ("Lab mesh", "Лаборатория", "实验网格", "ラボメッシュ"),
        ctl: "10.8.0.1:8443",
        fp: "…4a",
        alg: "noise-xk · chacha20",
        note: (
            "Private mesh, 4 nodes",
            "Закрытый mesh, 4 узла",
            "私有网格，4 个节点",
            "非公開メッシュ・4 ノード",
        ),
        nodes: &["nl", "de", "fi", "se"],
    },
    Space {
        id: "edu",
        name: ("Campus", "Кампус", "校园", "キャンパス"),
        ctl: "ctl.campus.example:9443",
        fp: "…71",
        alg: "noise-xk · aes-gcm",
        note: (
            "Campus nodes, 3 nodes",
            "Узлы кампуса, 3 узла",
            "校园节点，3 个节点",
            "キャンパスノード・3 ノード",
        ),
        nodes: &["us", "ca", "jp"],
    },
];

fn s(v: &str) -> SharedString {
    v.into()
}

fn tr(lang: Lang, l: L4) -> &'static str {
    match lang {
        Lang::Ru => l.1,
        Lang::Zh => l.2,
        Lang::Ja => l.3,
        _ => l.0,
    }
}

fn t4(lang: Lang, en: &'static str, ru: &'static str, zh: &'static str, ja: &'static str) -> &'static str {
    tr(lang, (en, ru, zh, ja))
}

fn ms(lang: Lang) -> &'static str {
    match lang {
        Lang::Ru => " мс",
        _ => " ms",
    }
}

fn node(id: &str) -> &'static Node {
    NODES.iter().find(|n| n.id == id).unwrap_or(&NODES[0])
}

fn space(id: &str) -> &'static Space {
    SPACES.iter().find(|sp| sp.id == id).unwrap_or(&SPACES[0])
}

fn in_space(space_id: &str, id: &str) -> bool {
    space(space_id).nodes.contains(&id)
}

pub fn space_ids() -> Vec<&'static str> {
    SPACES.iter().map(|sp| sp.id).collect()
}

pub fn node_count(space_id: &str) -> usize {
    space(space_id).nodes.len()
}

pub fn edge_count(space_id: &str) -> usize {
    EDGES
        .iter()
        .filter(|e| in_space(space_id, e.a) && in_space(space_id, e.b))
        .count()
}

pub fn fastest_exit(space_id: &str) -> &'static str {
    space(space_id)
        .nodes
        .iter()
        .map(|id| node(id))
        .filter(|n| n.rtt >= 0)
        .min_by_key(|n| n.rtt)
        .map(|n| n.id)
        .unwrap_or_else(|| first_alive(space_id))
}

pub fn first_alive(space_id: &str) -> &'static str {
    space(space_id)
        .nodes
        .iter()
        .map(|id| node(id))
        .find(|n| n.rtt >= 0)
        .map(|n| n.id)
        .unwrap_or_else(|| space(space_id).nodes.first().copied().unwrap_or("nl"))
}

fn edge_rtt(space_id: &str, a: &str, b: &str) -> i32 {
    EDGES
        .iter()
        .find(|e| {
            ((e.a == a && e.b == b) || (e.a == b && e.b == a))
                && in_space(space_id, e.a)
                && in_space(space_id, e.b)
        })
        .map(|e| if e.rtt >= 0 { e.rtt } else { -1 })
        .unwrap_or(-1)
}

fn live_ids(space_id: &str) -> Vec<&'static str> {
    space(space_id)
        .nodes
        .iter()
        .copied()
        .filter(|id| node(id).rtt >= 0)
        .collect()
}

fn all_paths(space_id: &str, exit: &str) -> Vec<Vec<&'static str>> {
    let live = live_ids(space_id);
    let mut out: Vec<Vec<&'static str>> = Vec::new();
    fn walk<'a>(
        space_id: &str,
        exit: &str,
        live: &[&'a str],
        path: Vec<&'a str>,
        out: &mut Vec<Vec<&'a str>>,
    ) {
        let last = *path.last().unwrap();
        if last == exit {
            out.push(path);
            return;
        }
        if path.len() >= MAX_HOPS {
            return;
        }
        for &id in live {
            if path.contains(&id) {
                continue;
            }
            if edge_rtt(space_id, last, id) < 0 {
                continue;
            }
            let mut next = path.clone();
            next.push(id);
            walk(space_id, exit, live, next, out);
        }
    }
    for &id in &live {
        walk(space_id, exit, &live, vec![id], &mut out);
    }
    out
}

pub fn path_cost(space_id: &str, path: &[&str]) -> i32 {
    if path.is_empty() {
        return 0;
    }
    let first = node(path[0]).rtt;
    let mut c = if first < 0 { 0 } else { first };
    for i in 1..path.len() {
        let e = edge_rtt(space_id, path[i - 1], path[i]);
        if e > 0 {
            c += e;
        }
    }
    c
}

pub fn path_missing(space_id: &str, path: &[&str]) -> usize {
    let mut m = 0;
    for i in 1..path.len() {
        if edge_rtt(space_id, path[i - 1], path[i]) < 0 {
            m += 1;
        }
    }
    m
}

pub fn plan(space_id: &str, exit: &str, prio: i32) -> Vec<&'static str> {
    let all = all_paths(space_id, exit);
    let pick = |keep: &dyn Fn(&Vec<&'static str>) -> bool| -> Option<Vec<&'static str>> {
        all.iter()
            .filter(|p| keep(p))
            .min_by_key(|p| path_cost(space_id, p))
            .cloned()
    };
    let p = match prio {
        0 => pick(&|p| p.len() == 1),
        1 => pick(&|p| p.len() == 2).or_else(|| pick(&|p| p.len() <= 2)),
        _ => pick(&|p| p.len() >= 3)
            .or_else(|| pick(&|p| p.len() == 2))
            .or_else(|| pick(&|p| p.len() == 1)),
    };
    p.unwrap_or_else(|| vec![node(exit).id])
}

pub fn manual_path(space_id: &str, hops: &[String], exit: &str) -> Vec<&'static str> {
    let mut out: Vec<&'static str> = hops
        .iter()
        .filter(|h| in_space(space_id, h) && h.as_str() != exit)
        .map(|h| node(h).id)
        .collect();
    out.push(node(exit).id);
    out
}

pub fn resolve_exit(space_id: &str, exit: &str) -> &'static str {
    if in_space(space_id, exit) {
        node(exit).id
    } else {
        first_alive(space_id)
    }
}

fn model<T: Clone + 'static>(v: Vec<T>) -> ModelRc<T> {
    ModelRc::new(VecModel::from(v))
}

fn li(lang: Lang) -> usize {
    match lang {
        Lang::Ru => 1,
        Lang::Zh => 2,
        Lang::Ja => 3,
        _ => 0,
    }
}

pub fn node_state(space_id: &str, id: &str, probing: bool) -> i32 {
    let _ = space_id;
    let n = node(id);
    if probing {
        3
    } else if n.rtt < 0 {
        2
    } else if n.age > 60 {
        1
    } else {
        0
    }
}

fn quality(ping: i32) -> i32 {
    if ping < 0 {
        0
    } else if ping < 30 {
        4
    } else if ping < 60 {
        3
    } else if ping < 100 {
        2
    } else {
        1
    }
}

fn rtt_txt(lang: Lang, rtt: i32) -> String {
    if rtt < 0 {
        t4(lang, "no response", "нет ответа", "无响应", "応答なし").to_string()
    } else {
        format!("{}{}", rtt, ms(lang))
    }
}

fn layer_note(lang: Lang, layers_below: usize, is_exit: bool) -> String {
    if is_exit {
        t4(
            lang,
            "end-to-end Noise session · sees destination",
            "сквозная Noise-сессия · видит адресат",
            "端到端 Noise 会话 · 可见目标",
            "エンドツーエンド Noise セッション · 宛先が見える",
        )
        .to_string()
    } else {
        let n = layers_below.max(1);
        match lang {
            Lang::Ru => format!("снимает слой {} · payload не виден", n),
            Lang::Zh => format!("剥离第 {} 层 · 载荷不可见", n),
            Lang::Ja => format!("レイヤー {} を剥がす · ペイロード非表示", n),
            _ => format!("strips layer {} · payload not visible", n),
        }
    }
}

fn hop_row(space_id: &str, lang: Lang, path: &[&str], i: usize) -> RouteHop {
    let id = path[i];
    let n = node(id);
    let last = i == path.len() - 1;
    let in_edge = if i == 0 {
        n.rtt
    } else {
        edge_rtt(space_id, path[i - 1], id)
    };
    let rtt = if in_edge < 0 {
        t4(lang, "no edge", "нет ребра", "无边", "エッジなし").to_string()
    } else {
        format!("{}{}", in_edge, ms(lang))
    };
    RouteHop {
        num: (i + 1) as i32,
        code: s(n.code),
        label: s(tr(lang, n.label)),
        note: s(&layer_note(lang, path.len() - 1 - i, last)),
        rtt: s(&rtt),
        rtt_warn: in_edge < 0,
        is_exit: last,
        can_up: false,
        can_down: false,
        can_drop: false,
        can_swap: false,
    }
}

pub fn path_hops(space_id: &str, lang: Lang, path: &[&str]) -> ModelRc<RouteHop> {
    model((0..path.len()).map(|i| hop_row(space_id, lang, path, i)).collect())
}

pub fn draft_hops(space_id: &str, lang: Lang, path: &[&str]) -> ModelRc<RouteHop> {
    let n = path.len();
    let rows = (0..n)
        .map(|i| {
            let last = i == n - 1;
            let mut r = hop_row(space_id, lang, path, i);
            r.can_up = i > 0 && !last;
            r.can_down = i + 1 < n - 1;
            r.can_drop = !last;
            r.can_swap = last;
            r
        })
        .collect();
    model(rows)
}

pub fn add_hop_list(
    space_id: &str,
    lang: Lang,
    exit: &str,
    hops: &[String],
) -> ModelRc<AddHopChip> {
    let rows = space(space_id)
        .nodes
        .iter()
        .map(|id| node(id))
        .filter(|n| n.rtt >= 0 && n.id != exit && !hops.iter().any(|h| h == n.id))
        .map(|n| AddHopChip {
            id: s(n.id),
            code: s(n.code),
            label: s(tr(lang, n.label)),
            rtt: s(&format!("{}{}", n.rtt, ms(lang))),
        })
        .collect();
    model(rows)
}

pub fn node_rows(
    space_id: &str,
    lang: Lang,
    query: &str,
    exit: &str,
    hops: &[String],
    probing: bool,
) -> ModelRc<NodeRow> {
    let q = query.trim().to_lowercase();
    let rows = space(space_id)
        .nodes
        .iter()
        .map(|id| node(id))
        .filter(|n| {
            q.is_empty()
                || format!("{}{}{}", tr(lang, n.label), n.code, n.subnet)
                    .to_lowercase()
                    .contains(&q)
        })
        .map(|n| {
            let st = node_state(space_id, n.id, probing);
            let tag = if st == 1 {
                match lang {
                    Lang::Ru => format!("устарело {} с", n.age),
                    Lang::Zh => format!("过期 {} 秒", n.age),
                    Lang::Ja => format!("{} 秒前", n.age),
                    _ => format!("stale {} s", n.age),
                }
            } else if st == 2 {
                rtt_txt(lang, -1)
            } else if n.id == exit {
                t4(lang, "current exit", "текущий exit", "当前出口", "現在の出口").to_string()
            } else if hops.iter().any(|h| h == n.id) {
                t4(lang, "in chain", "в цепочке", "在链中", "チェーン内").to_string()
            } else {
                String::new()
            };
            let ping = if st == 3 {
                "···".to_string()
            } else {
                rtt_txt(lang, n.rtt)
            };
            NodeRow {
                id: s(n.id),
                code: s(n.code),
                city: s(tr(lang, n.label)),
                group: s(tr(lang, n.group)),
                meta: s(n.subnet),
                ping: s(&ping),
                node_state: st,
                quality: quality(n.rtt),
                tag: s(&tag),
                selected: n.id == exit,
                alive: n.rtt >= 0,
            }
        })
        .collect();
    model(rows)
}

pub fn edge_rows(space_id: &str, lang: Lang) -> ModelRc<EdgeRow> {
    let rows = EDGES
        .iter()
        .filter(|e| in_space(space_id, e.a) && in_space(space_id, e.b))
        .map(|e| {
            let val = if e.rtt < 0 {
                rtt_txt(lang, -1)
            } else if e.stale {
                format!(
                    "{}{} · {}",
                    e.rtt,
                    ms(lang),
                    t4(lang, "stale", "устарело", "过期", "古い")
                )
            } else {
                format!("{}{}", e.rtt, ms(lang))
            };
            EdgeRow {
                pair: s(&format!("{} → {}", node(e.a).code, node(e.b).code)),
                val: s(&val),
                edge_state: if e.rtt < 0 {
                    2
                } else if e.stale {
                    1
                } else {
                    0
                },
            }
        })
        .collect();
    model(rows)
}

pub fn visibility(
    space_id: &str,
    lang: Lang,
    path: &[&str],
    transport: &str,
) -> ModelRc<Visibility> {
    let exit = *path.last().unwrap();
    let first = node(path[0]);
    let isp_what = match lang {
        Lang::Ru => format!("{}-трафик к {}. Адресат не виден.", transport.to_uppercase(), first.code),
        Lang::Zh => format!("{} 流量到 {}。目标不可见。", transport.to_uppercase(), first.code),
        Lang::Ja => format!("{} トラフィックが {} へ。宛先は非表示。", transport.to_uppercase(), first.code),
        _ => format!("{} traffic to {}. Destination hidden.", transport.to_uppercase(), first.code),
    };
    let mut rows = vec![Visibility {
        who: s(t4(lang, "ISP", "Провайдер", "运营商", "プロバイダ")),
        what: s(&isp_what),
        level: 0,
    }];
    for (i, id) in path.iter().take(path.len() - 1).enumerate() {
        rows.push(Visibility {
            who: s(&format!("{} ({})", node(id).code, i + 1)),
            what: s(t4(
                lang,
                "previous and next hop. Payload not visible.",
                "предыдущий и следующий хоп. Payload не виден.",
                "上一跳与下一跳。载荷不可见。",
                "前後のホップ。ペイロード非表示。",
            )),
            level: 1,
        });
    }
    rows.push(Visibility {
        who: s(&format!("{} · EXIT", node(exit).code)),
        what: s(t4(
            lang,
            "the destination. Your IP is not visible.",
            "адресат запроса. Ваш IP не виден.",
            "请求的目标。你的 IP 不可见。",
            "リクエストの宛先。あなたの IP は非表示。",
        )),
        level: 0,
    });
    rows.push(Visibility {
        who: s(t4(lang, "Site", "Сайт", "站点", "サイト")),
        what: s(node(exit).subnet),
        level: 2,
    });
    model(rows)
}

pub fn factors(lang: Lang, path: &[&str], blocker: bool, kill: bool) -> ModelRc<Factor> {
    let hops = path.len();
    let layers = hops.saturating_sub(1);
    let distinct = hops > 1;
    let rows = vec![
        Factor {
            mark: s("✓"),
            name: s(&match lang {
                Lang::Ru => format!("хопов {} из {}", hops, MAX_HOPS),
                Lang::Zh => format!("{} / {} 跳", hops, MAX_HOPS),
                Lang::Ja => format!("{} / {} ホップ", hops, MAX_HOPS),
                _ => format!("{} of {} hops", hops, MAX_HOPS),
            }),
            level: 1,
        },
        Factor {
            mark: s("✓"),
            name: s(&match lang {
                Lang::Ru => format!("onion-слоёв: {}", layers),
                Lang::Zh => format!("洋葱层: {}", layers),
                Lang::Ja => format!("onion レイヤー: {}", layers),
                _ => format!("{} onion layers", layers),
            }),
            level: 1,
        },
        Factor {
            mark: s(if distinct { "✓" } else { "✕" }),
            name: s(t4(
                lang,
                "hop subnets are distinct",
                "подсети хопов различны",
                "各跳子网互不相同",
                "ホップのサブネットは別々",
            )),
            level: if distinct { 1 } else { 0 },
        },
        Factor {
            mark: s("?"),
            name: s(t4(
                lang,
                "operators — registry does not disclose",
                "операторы — реестр не раскрывает",
                "运营者 — 注册表不披露",
                "運用者 — レジストリは非開示",
            )),
            level: 2,
        },
        Factor {
            mark: s(if blocker { "✓" } else { "✕" }),
            name: s(t4(
                lang,
                "DNS inside the tunnel",
                "DNS через туннель",
                "DNS 走隧道",
                "DNS はトンネル内",
            )),
            level: if blocker { 1 } else { 0 },
        },
        Factor {
            mark: s(if kill { "✓" } else { "✕" }),
            name: s(t4(lang, "kill switch on", "kill switch включён", "已启用断网保护", "キルスイッチ有効")),
            level: if kill { 1 } else { 0 },
        },
    ];
    model(rows)
}

pub fn plan_reason(lang: Lang, prio: i32, len: usize, node_total: usize) -> String {
    match prio {
        0 => match lang {
            Lang::Ru => format!("Минимальный RTT из {} узлов реестра, прямой путь до exit.", node_total),
            Lang::Zh => format!("在 {} 个注册节点中 RTT 最低，直达出口。", node_total),
            Lang::Ja => format!("レジストリ {} ノード中で最小 RTT、出口まで直行。", node_total),
            _ => format!("Lowest RTT across {} registry nodes, direct path to the exit.", node_total),
        },
        1 => match lang {
            Lang::Ru => format!("{} хопа: задержка в пределах двойной прямой, ребро с устаревшей метрикой исключено.", len),
            Lang::Zh => format!("{} 跳：延迟在直连两倍以内，已排除指标过期的边。", len),
            Lang::Ja => format!("{} ホップ：遅延は直行の 2 倍以内、古い指標のエッジを除外。", len),
            _ => format!("{} hops: latency within 2x of direct; an edge with a stale metric was excluded.", len),
        },
        _ => match lang {
            Lang::Ru => format!("{} хопа в разных подсетях; путь выбран по максимальной глубине при допустимой задержке.", len),
            Lang::Zh => format!("{} 跳位于不同子网；在可接受延迟内选择最大深度路径。", len),
            Lang::Ja => format!("{} ホップが別サブネット；許容遅延内で最大の深さを選択。", len),
            _ => format!("{} hops in distinct subnets; deepest path within the latency budget.", len),
        },
    }
}

pub fn privacy_note(lang: Lang, path_len: usize) -> String {
    if path_len > 1 {
        t4(
            lang,
            "Kill switch is on — no traffic leaks to the open network if the channel drops.",
            "Kill switch включён — при обрыве канала трафик не утечёт в открытую сеть.",
            "已启用断网保护 — 通道断开时流量不会泄漏到开放网络。",
            "キルスイッチ有効 — チャネル切断時も開放ネットワークへ通信が漏れません。",
        )
        .to_string()
    } else {
        t4(
            lang,
            "No relay layers: the exit sees your IP.",
            "Relay-слоёв нет: exit видит ваш IP.",
            "无中继层：出口可见你的 IP。",
            "リレー層なし：出口があなたの IP を見ます。",
        )
        .to_string()
    }
}

pub fn space_rows(lang: Lang, joined: &[String], current: &str) -> ModelRc<SpaceRow> {
    let rows = joined
        .iter()
        .map(|id| {
            let sp = space(id);
            SpaceRow {
                id: s(sp.id),
                name: s(tr(lang, sp.name)),
                note: s(tr(lang, sp.note)),
                ctl: s(sp.ctl),
                fp: s(sp.fp),
                current: sp.id == current,
            }
        })
        .collect();
    model(rows)
}

pub fn space_name(lang: Lang, id: &str) -> String {
    tr(lang, space(id).name).to_string()
}

pub fn space_ctl(id: &str) -> String {
    space(id).ctl.to_string()
}

pub struct SpacePreview {
    pub id: String,
    pub name: String,
    pub ctl: String,
    pub note: String,
    pub alg: String,
    pub fp: String,
}

pub fn first_unjoined(lang: Lang, joined: &[String]) -> Option<SpacePreview> {
    SPACES
        .iter()
        .find(|sp| !joined.iter().any(|j| j == sp.id))
        .map(|sp| SpacePreview {
            id: sp.id.to_string(),
            name: tr(lang, sp.name).to_string(),
            ctl: sp.ctl.to_string(),
            note: tr(lang, sp.note).to_string(),
            alg: sp.alg.to_string(),
            fp: sp.fp.to_string(),
        })
}

pub struct ExitView {
    pub code: String,
    pub city: String,
    pub meta: String,
    pub ping: String,
    pub rtt: i32,
    pub endpoint: String,
}

pub fn exit_view(lang: Lang, id: &str) -> ExitView {
    let n = node(id);
    ExitView {
        code: n.code.to_string(),
        city: tr(lang, n.label).to_string(),
        meta: n.subnet.to_string(),
        ping: rtt_txt(lang, n.rtt),
        rtt: n.rtt,
        endpoint: n.ep.to_string(),
    }
}

pub fn topo_counts(lang: Lang, space_id: &str, age: u32) -> String {
    let n = node_count(space_id);
    let e = edge_count(space_id);
    match lang {
        Lang::Ru => format!("{} узлов · {} рёбер · метрики {} с назад", n, e, age),
        Lang::Zh => format!("{} 个节点 · {} 条边 · 指标 {} 秒前", n, e, age),
        Lang::Ja => format!("{} ノード · {} エッジ · 指標 {} 秒前", n, e, age),
        _ => format!("{} nodes · {} edges · metrics {} s old", n, e, age),
    }
}

pub fn mode_label(lang: Lang, manual: bool) -> String {
    if manual {
        t4(lang, "MANUAL", "ВРУЧНУЮ", "手动", "手動").to_string()
    } else {
        t4(lang, "AUTO", "АВТО", "自动", "自動").to_string()
    }
}

pub fn chain_log(lang: Lang, first_code: &str, exit_code: &str) -> ModelRc<SharedString> {
    let lines = match lang {
        Lang::Ru => vec![
            format!("· хоп 1 {}: RTT стабилен", first_code),
            "· хоп 2 заменён, сессия сохранена".to_string(),
            format!("· путь применён до {}", exit_code),
        ],
        Lang::Zh => vec![
            format!("· 第 1 跳 {}: RTT 稳定", first_code),
            "· 第 2 跳已替换，会话保持".to_string(),
            format!("· 路径已应用至 {}", exit_code),
        ],
        Lang::Ja => vec![
            format!("· ホップ 1 {}: RTT 安定", first_code),
            "· ホップ 2 を置換、セッション維持".to_string(),
            format!("· 経路を {} まで適用", exit_code),
        ],
        _ => vec![
            format!("· hop 1 {}: RTT stable", first_code),
            "· hop 2 replaced, session preserved".to_string(),
            format!("· path applied to {}", exit_code),
        ],
    };
    model(lines.iter().map(|l| s(l)).collect())
}

pub fn probe_label(lang: Lang, probing: bool) -> String {
    if probing {
        t4(lang, "Probing…", "Проба идёт…", "测量中…", "測定中…").to_string()
    } else {
        t4(lang, "Re-probe RTT", "Пробить RTT заново", "重新测量 RTT", "RTT を再測定").to_string()
    }
}

pub fn hops_count(lang: Lang, n: usize) -> String {
    match lang {
        Lang::Ru => format!("хопов {} из {}", n, MAX_HOPS),
        Lang::Zh => format!("{} / {} 跳", n, MAX_HOPS),
        Lang::Ja => format!("{} / {} ホップ", n, MAX_HOPS),
        _ => format!("{} of {} hops", n, MAX_HOPS),
    }
}

pub fn prio_names(lang: Lang) -> [&'static str; 3] {
    match lang {
        Lang::Ru => ["Быстрее", "Баланс", "Приватнее"],
        Lang::Zh => ["更快", "平衡", "更私密"],
        Lang::Ja => ["高速", "バランス", "高秘匿"],
        _ => ["Faster", "Balanced", "More private"],
    }
}

pub fn prio_effect(lang: Lang, layers: usize, extra_ms: i32) -> String {
    let extra = extra_ms.max(0);
    match lang {
        Lang::Ru => format!("слоёв: {} · ≈ +{} мс", layers, extra),
        Lang::Zh => format!("层数: {} · ≈ +{} ms", layers, extra),
        Lang::Ja => format!("レイヤー: {} · ≈ +{} ms", layers, extra),
        _ => format!("layers: {} · ≈ +{} ms", layers, extra),
    }
}

pub fn path_sum(lang: Lang, cost: i32, missing: usize) -> String {
    let prefix = if missing > 0 { "≥ " } else { "" };
    format!("{}{}{}", prefix, cost, ms(lang))
}

pub fn path_warn(lang: Lang) -> String {
    t4(
        lang,
        "Path unconfirmed: no measured edge between hops",
        "Путь не подтверждён: нет измеренного ребра между хопами",
        "路径未确认：跳之间没有已测量的边",
        "経路未確認：ホップ間に測定済みエッジがありません",
    )
    .to_string()
}

pub fn empty_title(lang: Lang) -> String {
    t4(
        lang,
        "No relays — direct connection",
        "Релеев нет — прямое подключение",
        "无中继 — 直接连接",
        "リレーなし — 直接接続",
    )
    .to_string()
}

pub fn empty_body(lang: Lang) -> String {
    t4(
        lang,
        "Traffic goes straight from you to the exit node: no onion layers, and the exit sees your IP. Add a hop below or take the planner's path.",
        "Трафик идёт от вас прямо к exit-узлу: onion-слоёв нет, exit видит ваш IP. Добавьте хоп ниже или возьмите готовый путь планировщика.",
        "流量从你直达出口节点：没有洋葱层，出口可见你的 IP。请在下方添加一跳或采用规划器路径。",
        "通信はあなたから出口ノードへ直行：onion 層がなく出口があなたの IP を見ます。下でホップを追加するかプランナーの経路を採用してください。",
    )
    .to_string()
}

pub fn globe_nodes(space_id: &str, lang: Lang) -> ModelRc<GlobeNode> {
    let mut rows: Vec<GlobeNode> = space(space_id)
        .nodes
        .iter()
        .map(|id| node(id))
        .map(|n| GlobeNode {
            id: s(n.id),
            code: s(n.code),
            lat: n.lat,
            lon: n.lon,
            rtt: n.rtt,
            stale: n.age > 60,
            is_me: false,
        })
        .collect();
    rows.push(GlobeNode {
        id: s("__me"),
        code: s(t4(lang, "you", "вы", "你", "あなた")),
        lat: 55.75,
        lon: 37.62,
        rtt: 0,
        stale: false,
        is_me: true,
    });
    model(rows)
}
