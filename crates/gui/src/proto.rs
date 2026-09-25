use slint::{ModelRc, VecModel};

use crate::Lang;
use crate::{AppState, CipherInfo, MtuPreset, ProtoOpt, ProtoRow, TransportInfo};

fn t2(lang: Lang, en: &'static str, ru: &'static str) -> &'static str {
    match lang {
        Lang::Ru => ru,
        _ => en,
    }
}

#[derive(Clone)]
pub struct ProtoState {
    pub cipher_auto: bool,
    pub kex: i32, // 0 hybrid, 1 x25519
    pub pad: i32, // 0 off, 1 std, 2 max
    pub ka: i32,  // -1 auto, else 0/10/25/60
    pub mtu_auto: bool,
    pub mtu: i32,
    pub mtu_probe: i32, // 0 idle, 1 run, 2 done
    pub pp: i32,        // -1 list, 0 transport,1 cipher,2 kex,3 pad,4 ka,5 mtu
}

impl ProtoState {
    pub fn new() -> Self {
        Self {
            cipher_auto: true,
            kex: 0,
            pad: 1,
            ka: -1,
            mtu_auto: true,
            mtu: 1380,
            mtu_probe: 0,
            pp: -1,
        }
    }

    pub fn open(&mut self, key: i32) {
        self.pp = key;
        self.mtu_probe = 0;
    }

    // returns true if a detail was closed; false if already at list level.
    pub fn back(&mut self) -> bool {
        if self.pp >= 0 {
            self.pp = -1;
            true
        } else {
            false
        }
    }

    pub fn reset(&mut self) {
        self.cipher_auto = true;
        self.kex = 0;
        self.pad = 1;
        self.ka = -1;
        self.mtu_auto = true;
        self.mtu = 1380;
    }

    pub fn set_mtu(&mut self, v: i32) {
        self.mtu = v.clamp(1280, 1500);
        self.mtu_auto = false;
    }
}

fn pad_name(lang: Lang, i: i32) -> &'static str {
    match i {
        0 => t2(lang, "Off", "Выключена"),
        2 => t2(lang, "Maximum", "Максимальная"),
        _ => t2(lang, "Standard", "Стандартная"),
    }
}

fn auto_v(lang: Lang, v: &str) -> String {
    format!("{} · {}", t2(lang, "Auto", "Авто"), v)
}

fn opt(name: &str, hint: &str, badge: &str, mono: bool, checked: bool, top: bool) -> ProtoOpt {
    ProtoOpt {
        name: name.into(),
        hint: hint.into(),
        badge: badge.into(),
        has_badge: !badge.is_empty(),
        mono,
        checked,
        top_border: top,
    }
}

#[allow(clippy::too_many_arguments)]
pub fn render(
    st: &AppState,
    lang: Lang,
    ps: &ProtoState,
    transports: &[TransportInfo],
    transport_id: &str,
    auto_transport: bool,
    ciphers: &[CipherInfo],
    cipher: usize,
    mobile: bool,
) {
    let eff_cipher = if ps.cipher_auto {
        if mobile { 0 } else { 1 }
    } else {
        cipher
    };
    let c_short = ciphers
        .get(eff_cipher)
        .map(|c| c.name.split('-').next().unwrap_or("").to_string())
        .unwrap_or_default();
    let t_def = transports
        .iter()
        .find(|t| t.id == transport_id)
        .or_else(|| transports.first());
    let t_name = t_def.map(|t| t.name.to_string()).unwrap_or_default();
    let auto_mtu = if transport_id == "udp" { 1380 } else { 1280 };
    let ka_eff = if ps.ka == -1 { 20 } else { ps.ka };

    let m_transport = !auto_transport;
    let m_cipher = !ps.cipher_auto;
    let m_kex = ps.kex != 0;
    let m_pad = ps.pad != 1;
    let m_mtu = !ps.mtu_auto;
    let m_ka = ps.ka != -1;
    let n_mod = [m_transport, m_cipher, m_kex, m_pad, m_mtu, m_ka]
        .iter()
        .filter(|b| **b)
        .count();

    let sec = t2(lang, "s", "с");
    let off = t2(lang, "Off", "Выкл");

    let row = |key: i32, name: &str, val: String, modified: bool, top: bool| ProtoRow {
        key,
        name: name.into(),
        val: val.into(),
        modified,
        disabled: false,
        top_border: top,
    };

    // Transport group
    let transport_val = if auto_transport {
        auto_v(lang, &t_name)
    } else {
        t_name.clone()
    };
    let grp_transport = vec![row(
        0,
        t2(lang, "Transport", "Транспорт"),
        transport_val,
        m_transport,
        false,
    )];

    // Crypto group
    let cipher_val = if ps.cipher_auto {
        auto_v(lang, &c_short)
    } else {
        c_short.clone()
    };
    let kex_val = if ps.kex == 0 {
        t2(lang, "Hybrid PQ", "Гибрид PQ").to_string()
    } else {
        "X25519".to_string()
    };
    let grp_crypto = vec![
        row(1, t2(lang, "Cipher", "Шифр"), cipher_val, m_cipher, false),
        row(
            2,
            t2(lang, "Key exchange", "Обмен ключами"),
            kex_val,
            m_kex,
            true,
        ),
        row(
            3,
            t2(lang, "Packet obfuscation", "Обфускация пакетов"),
            pad_name(lang, ps.pad).to_string(),
            m_pad,
            true,
        ),
    ];

    // Connection group
    let mtu_val = if ps.mtu_auto {
        auto_v(lang, &auto_mtu.to_string())
    } else {
        ps.mtu.to_string()
    };
    let ka_val = if ps.ka == -1 {
        auto_v(lang, &format!("{} {}", ka_eff, sec))
    } else if ps.ka == 0 {
        off.to_string()
    } else {
        format!("{} {}", ps.ka, sec)
    };
    let grp_conn = vec![
        row(5, "MTU", mtu_val, m_mtu, false),
        row(4, "Keepalive", ka_val, m_ka, true),
    ];

    let mm = |v: Vec<ProtoRow>| ModelRc::new(VecModel::from(v));
    st.set_proto_grp_transport(mm(grp_transport));
    st.set_proto_grp_crypto(mm(grp_crypto));
    st.set_proto_grp_conn(mm(grp_conn));

    // summary + state
    let mtu_eff = if ps.mtu_auto { auto_mtu } else { ps.mtu };
    let ka_sum = if ka_eff != 0 {
        format!("KA {}{}", ka_eff, sec)
    } else {
        format!("KA {}", off)
    };
    let kex_sum = if ps.kex == 0 {
        "X25519+ML-KEM"
    } else {
        "X25519"
    };
    let summary = format!(
        "{} · {} · {} · MTU {} · {}",
        t_name, c_short, kex_sum, mtu_eff, ka_sum
    );
    st.set_proto_detail_summary(summary.into());
    st.set_proto_state_text(
        if n_mod > 0 {
            match lang {
                Lang::Ru => format!("Изменено вручную: {}", n_mod),
                _ => format!("Changed manually: {}", n_mod),
            }
        } else {
            t2(
                lang,
                "Every parameter is tuned automatically",
                "Все параметры подбираются автоматически",
            )
            .to_string()
        }
        .into(),
    );
    st.set_proto_state_modified(n_mod > 0);
    st.set_proto_changed(n_mod > 0);

    // view flags
    let cur = ps.pp;
    st.set_proto_list(cur < 0);
    st.set_proto_detail(cur >= 0);
    st.set_proto_is_opts(cur >= 0 && cur != 5);
    st.set_proto_is_mtu(cur == 5);
    st.set_proto_back_label(
        if cur >= 0 {
            t2(lang, "Protocol settings", "Настройки протокола")
        } else {
            t2(lang, "Settings", "Настройки")
        }
        .into(),
    );

    // detail: title/lead/foot + options
    let recommended = t2(lang, "recommended", "рекомендуется");
    let auto = t2(lang, "Auto", "Авто");
    let (title, lead, foot, opts): (String, String, String, Vec<ProtoOpt>) = match cur {
        0 => {
            let mut o = vec![opt(
                t2(lang, "Automatic, via chain", "Автоматически по цепочке"),
                &transports
                    .iter()
                    .map(|t| t.name.to_string())
                    .collect::<Vec<_>>()
                    .join(" → "),
                recommended,
                false,
                auto_transport,
                false,
            )];
            for (i, t) in transports.iter().enumerate() {
                o.push(opt(
                    &t.title,
                    &t.desc,
                    "",
                    false,
                    !auto_transport && t.id == transport_id,
                    i + 1 > 0,
                ));
            }
            (
                t2(lang, "Transport", "Транспорт").into(),
                t2(
                    lang,
                    "How traffic is disguised on the first leg — from the device to the first node.",
                    "Как трафик маскируется на первом участке — от устройства до первого узла.",
                )
                .into(),
                t2(
                    lang,
                    "If the network kills the current transport, the client silently moves to the next one — session and IP are kept.",
                    "Если сеть глушит текущий транспорт, клиент молча переходит к следующему — сессия и IP сохраняются.",
                )
                .into(),
                o,
            )
        }
        1 => {
            let auto_hint = match lang {
                Lang::Ru => format!(
                    "Сейчас {} — выбирается по наличию аппаратного AES",
                    if mobile { "ChaCha20" } else { "AES" }
                ),
                _ => format!(
                    "Now {} — chosen by hardware AES support",
                    if mobile { "ChaCha20" } else { "AES" }
                ),
            };
            let o = vec![
                opt(auto, &auto_hint, recommended, false, ps.cipher_auto, false),
                opt(
                    "ChaCha20-Poly1305",
                    ciphers.first().map(|c| c.hint.as_str()).unwrap_or(""),
                    "",
                    true,
                    !ps.cipher_auto && cipher == 0,
                    true,
                ),
                opt(
                    "AES-256-GCM",
                    ciphers.get(1).map(|c| c.hint.as_str()).unwrap_or(""),
                    "",
                    true,
                    !ps.cipher_auto && cipher == 1,
                    true,
                ),
            ];
            (
                t2(lang, "Cipher", "Шифр").into(),
                t2(
                    lang,
                    "The algorithm that encrypts each packet. Both are equally strong — the only difference is speed on your hardware.",
                    "Алгоритм, которым шифруется каждый пакет. Оба варианта одинаково надёжны — разница только в скорости на вашем железе.",
                )
                .into(),
                t2(
                    lang,
                    "A cipher change applies on the next handshake without dropping the session.",
                    "Смена шифра применится при следующем рукопожатии, без разрыва сессии.",
                )
                .into(),
                o,
            )
        }
        2 => {
            let o = vec![
                opt(
                    "X25519 + ML-KEM-768",
                    t2(
                        lang,
                        "Protects against traffic recorded today being decrypted by a quantum computer tomorrow.",
                        "Защищает от записи трафика сегодня с расчётом расшифровать его квантовым компьютером завтра.",
                    ),
                    t2(lang, "post-quantum", "постквантовый"),
                    true,
                    ps.kex == 0,
                    false,
                ),
                opt(
                    "X25519",
                    t2(
                        lang,
                        "Slightly faster handshake. For older nodes without ML-KEM.",
                        "Чуть быстрее рукопожатие. Для старых узлов без ML-KEM.",
                    ),
                    "",
                    true,
                    ps.kex == 1,
                    true,
                ),
            ];
            (
                t2(lang, "Key exchange", "Обмен ключами").into(),
                t2(
                    lang,
                    "How the device and node agree on session keys.",
                    "Как устройство и узел договариваются о ключах сессии.",
                )
                .into(),
                t2(
                    lang,
                    "The hybrid adds about 1 KB to the handshake. If a node lacks ML-KEM, the client falls back to X25519 on its own.",
                    "Гибрид добавляет около 1 КБ к рукопожатию. Если узел не поддерживает ML-KEM, клиент сам откатится на X25519.",
                )
                .into(),
                o,
            )
        }
        3 => {
            let o = vec![
                opt(
                    pad_name(lang, 0),
                    t2(
                        lang,
                        "Lowest overhead. Easier to fingerprint by packet sizes.",
                        "Минимум накладных расходов. Проще распознать по размерам пакетов.",
                    ),
                    "",
                    false,
                    ps.pad == 0,
                    false,
                ),
                opt(
                    pad_name(lang, 1),
                    t2(
                        lang,
                        "Evens out packet sizes, +2–3% traffic.",
                        "Выравнивает размеры пакетов, +2–3 % трафика.",
                    ),
                    recommended,
                    false,
                    ps.pad == 1,
                    true,
                ),
                opt(
                    pad_name(lang, 2),
                    t2(
                        lang,
                        "Adds noise during pauses too. +8–12% traffic and battery.",
                        "Добавляет шум и в паузах. +8–12 % трафика и расход батареи.",
                    ),
                    "",
                    false,
                    ps.pad == 2,
                    true,
                ),
            ];
            (
                t2(lang, "Packet obfuscation", "Обфускация пакетов").into(),
                t2(
                    lang,
                    "Evens out packet size and timing so they can’t reveal what kind of traffic it is.",
                    "Выравнивает размер и ритм пакетов, чтобы по ним нельзя было узнать тип трафика.",
                )
                .into(),
                String::new(),
                o,
            )
        }
        4 => {
            let o = vec![
                opt(
                    auto,
                    t2(
                        lang,
                        "Adapts to the network: 15–25 s behind NAT, less on Wi-Fi.",
                        "Подстраивается под сеть: 15–25 с за NAT, реже в Wi-Fi.",
                    ),
                    recommended,
                    false,
                    ps.ka == -1,
                    false,
                ),
                opt(
                    &format!("10 {}", sec),
                    t2(lang, "For aggressive carrier NAT.", "Для агрессивных NAT мобильных операторов."),
                    "",
                    false,
                    ps.ka == 10,
                    true,
                ),
                opt(
                    &format!("25 {}", sec),
                    t2(lang, "WireGuard default.", "Стандарт WireGuard."),
                    "",
                    false,
                    ps.ka == 25,
                    true,
                ),
                opt(
                    &format!("60 {}", sec),
                    t2(
                        lang,
                        "Saves battery, may drop behind NAT.",
                        "Экономит батарею, может рваться за NAT.",
                    ),
                    "",
                    false,
                    ps.ka == 60,
                    true,
                ),
                opt(
                    off,
                    t2(
                        lang,
                        "Only if the connection is never idle.",
                        "Только если соединение и так не простаивает.",
                    ),
                    "",
                    false,
                    ps.ka == 0,
                    true,
                ),
            ];
            (
                "Keepalive".into(),
                t2(
                    lang,
                    "How often the client pings the node so the router or carrier doesn’t close the connection.",
                    "Как часто клиент напоминает узлу о себе, чтобы роутер или оператор не закрыли соединение.",
                )
                .into(),
                t2(
                    lang,
                    "More often is steadier on mobile networks; less often saves battery.",
                    "Чаще — стабильнее в мобильных сетях, реже — меньше расход батареи.",
                )
                .into(),
                o,
            )
        }
        5 => (
            "MTU".into(),
            t2(
                lang,
                "The largest packet size in the tunnel. Too big and packets fragment or drop; too small and speed suffers.",
                "Максимальный размер пакета в туннеле. Слишком большой — пакеты дробятся или теряются, слишком маленький — ниже скорость.",
            )
            .into(),
            t2(
                lang,
                "Change it only if pages load partially or large downloads stall.",
                "Меняйте вручную, только если сайты грузятся не до конца или соединение подвисает на больших файлах.",
            )
            .into(),
            vec![],
        ),
        _ => (String::new(), String::new(), String::new(), vec![]),
    };

    st.set_proto_detail_title(title.into());
    st.set_proto_detail_lead(lead.into());
    st.set_proto_detail_foot(foot.clone().into());
    st.set_proto_detail_has_foot(!foot.is_empty());
    st.set_proto_opts(ModelRc::new(VecModel::from(opts)));

    // MTU editor
    st.set_mtu_auto(ps.mtu_auto);
    st.set_mtu_val(ps.mtu.to_string().into());
    st.set_mtu_dec_op(if ps.mtu <= 1280 { 0.3 } else { 1.0 });
    st.set_mtu_inc_op(if ps.mtu >= 1500 { 0.3 } else { 1.0 });
    st.set_mtu_auto_hint(
        if ps.mtu_auto {
            match lang {
                Lang::Ru => format!("Сейчас {} — подбирается по пути до узла", auto_mtu),
                _ => format!("Now {} — tuned to the path to the node", auto_mtu),
            }
        } else {
            t2(lang, "Set a value manually", "Задайте значение вручную").to_string()
        }
        .into(),
    );
    let presets = [
        (1280, t2(lang, "minimum", "минимум")),
        (1380, t2(lang, "mobile", "моб. сети")),
        (1420, "WireGuard"),
        (1500, "Ethernet"),
    ];
    let preset_rows: Vec<MtuPreset> = presets
        .iter()
        .map(|(v, hint)| MtuPreset {
            val: v.to_string().into(),
            hint: (*hint).into(),
            selected: !ps.mtu_auto && ps.mtu == *v,
        })
        .collect();
    st.set_mtu_presets(ModelRc::new(VecModel::from(preset_rows)));
    let found = if transport_id == "udp" { 1392 } else { 1280 };
    st.set_mtu_probing(ps.mtu_probe == 1);
    st.set_mtu_has_result(ps.mtu_probe == 2);
    st.set_mtu_probe_label(
        if ps.mtu_probe == 1 {
            t2(lang, "Testing…", "Проверяем…")
        } else {
            t2(lang, "Test path to node", "Проверить путь до узла")
        }
        .into(),
    );
    st.set_mtu_result(
        match lang {
            Lang::Ru => format!("Путь пропускает пакеты до {} байт без фрагментации.", found),
            _ => format!(
                "The path carries packets up to {} bytes without fragmentation.",
                found
            ),
        }
        .into(),
    );
    st.set_mtu_can_apply(ps.mtu_auto || ps.mtu != found);

    // group captions + labels
    st.set_proto_cap_transport(t2(lang, "Transport", "Транспорт").into());
    st.set_proto_cap_crypto(t2(lang, "Encryption", "Шифрование").into());
    st.set_proto_cap_conn(t2(lang, "Connection", "Соединение").into());
    st.set_proto_cap_diag(t2(lang, "Diagnostics", "Диагностика").into());
    st.set_proto_reset_label(t2(lang, "Restore recommended", "Вернуть рекомендуемые").into());
    st.set_proto_sim_hint(
        t2(
            lang,
            "Checks how the client walks the transport chain when the network blocks the current one.",
            "Проверяет, как клиент переходит по цепочке транспортов, если сеть блокирует текущий.",
        )
        .into(),
    );
    st.set_mtu_bytes(t2(lang, "bytes", "байт").into());
    st.set_mtu_use(t2(lang, "Apply", "Применить").into());
    st.set_mtu_auto_label(t2(lang, "Automatic", "Автоматически").into());
}

// Apply a picked option index for the currently open detail. Touches shared
// transport/cipher state, so it runs against the full set of fields.
#[allow(clippy::too_many_arguments)]
pub fn apply_pick(
    ps: &mut ProtoState,
    pp: i32,
    index: usize,
    auto_transport: &mut bool,
    transport_id: &mut String,
    cipher: &mut usize,
    transport_ids: &[String],
) {
    match pp {
        0 => {
            if index == 0 {
                *auto_transport = true;
            } else if let Some(id) = transport_ids.get(index - 1) {
                *auto_transport = false;
                *transport_id = id.clone();
            }
        }
        1 => {
            if index == 0 {
                ps.cipher_auto = true;
            } else {
                ps.cipher_auto = false;
                *cipher = index - 1;
            }
        }
        2 => ps.kex = index as i32,
        3 => ps.pad = index as i32,
        4 => {
            ps.ka = match index {
                1 => 10,
                2 => 25,
                3 => 60,
                4 => 0,
                _ => -1,
            }
        }
        _ => {}
    }
}
