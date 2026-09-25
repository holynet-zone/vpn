use slint::{Color, ModelRc, SharedString, VecModel};

use crate::Lang;
use crate::{AppState, SplitAppRow, SplitChip, SplitDomainRow, SplitModeRow};

struct App {
    id: &'static str,
    name: &'static str,
    cat_ru: &'static str,
    cat_en: &'static str,
    h: f32,
    vpn: bool,
    sys: bool,
}

const fn app(
    id: &'static str,
    name: &'static str,
    cat_ru: &'static str,
    cat_en: &'static str,
    h: f32,
    vpn: bool,
    sys: bool,
) -> App {
    App {
        id,
        name,
        cat_ru,
        cat_en,
        h,
        vpn,
        sys,
    }
}

static APPS: &[App] = &[
    app("sber", "СберБанк", "Финансы", "Finance", 150.0, true, false),
    app("tbank", "Т-Банк", "Финансы", "Finance", 95.0, true, false),
    app(
        "gos",
        "Госуслуги",
        "Госсервисы",
        "Government",
        250.0,
        true,
        false,
    ),
    app("ozon", "Ozon", "Покупки", "Shopping", 255.0, true, false),
    app(
        "wb",
        "Wildberries",
        "Покупки",
        "Shopping",
        330.0,
        false,
        false,
    ),
    app(
        "ymaps",
        "Яндекс Карты",
        "Навигация",
        "Navigation",
        25.0,
        false,
        false,
    ),
    app("tg", "Telegram", "Общение", "Social", 225.0, false, false),
    app("wa", "WhatsApp", "Общение", "Social", 150.0, false, false),
    app("chrome", "Chrome", "Браузер", "Browser", 60.0, false, false),
    app("yt", "YouTube", "Видео", "Video", 25.0, false, false),
    app("spot", "Spotify", "Музыка", "Music", 150.0, false, false),
    app("steam", "Steam", "Игры", "Games", 250.0, false, false),
    app(
        "teams",
        "Microsoft Teams",
        "Работа",
        "Work",
        275.0,
        false,
        false,
    ),
    app(
        "anyc",
        "Cisco AnyConnect",
        "Работа · VPN",
        "Work · VPN",
        220.0,
        true,
        false,
    ),
    app(
        "cast",
        "Google Home",
        "Устройства",
        "Devices",
        200.0,
        false,
        false,
    ),
    app(
        "play",
        "Google Play",
        "Системное",
        "System",
        165.0,
        false,
        true,
    ),
    app(
        "upd",
        "Обновление системы",
        "Системное",
        "System",
        240.0,
        false,
        true,
    ),
    app(
        "dl",
        "Диспетчер загрузок",
        "Системное",
        "System",
        200.0,
        false,
        true,
    ),
];

fn t2(lang: Lang, en: &'static str, ru: &'static str) -> &'static str {
    match lang {
        Lang::Ru => ru,
        _ => en,
    }
}

fn gamma(x: f32) -> f32 {
    let x = x.clamp(0.0, 1.0);
    if x <= 0.003_130_8 {
        12.92 * x
    } else {
        1.055 * x.powf(1.0 / 2.4) - 0.055
    }
}

// oklch(l c h) -> sRGB Color. Used for app icon tints: oklch(0.62 0.14 h).
fn oklch(l: f32, c: f32, h_deg: f32) -> Color {
    let hr = h_deg.to_radians();
    let a = c * hr.cos();
    let b = c * hr.sin();
    let l_ = l + 0.396_337_78 * a + 0.215_803_76 * b;
    let m_ = l - 0.105_561_346 * a - 0.063_854_17 * b;
    let s_ = l - 0.089_484_18 * a - 1.291_485_5 * b;
    let (lc, mc, sc) = (l_ * l_ * l_, m_ * m_ * m_, s_ * s_ * s_);
    let r = 4.076_741_7 * lc - 3.307_711_6 * mc + 0.230_969_94 * sc;
    let g = -1.268_438 * lc + 2.609_757_4 * mc - 0.341_319_38 * sc;
    let bb = -0.004_196_086_3 * lc - 0.703_418_6 * mc + 1.707_614_7 * sc;
    Color::from_rgb_u8(
        (gamma(r) * 255.0).round() as u8,
        (gamma(g) * 255.0).round() as u8,
        (gamma(bb) * 255.0).round() as u8,
    )
}

fn icon(a: &App) -> Color {
    oklch(0.62, 0.14, a.h)
}

#[derive(Clone)]
pub struct SplitState {
    pub on: bool,
    pub mode_exclude: bool,
    pub ex: Vec<String>,
    pub incl: Vec<String>,
    pub query: String,
    pub sys: bool,
    pub sug_hide: bool,
    pub doms: Vec<String>,
    pub dom_in: String,
}

impl SplitState {
    pub fn new() -> Self {
        Self {
            on: true,
            mode_exclude: true,
            ex: vec!["sber".into(), "cast".into()],
            incl: vec!["chrome".into(), "tg".into()],
            query: String::new(),
            sys: false,
            sug_hide: false,
            doms: vec!["*.sberbank.ru".into(), "192.168.0.0/16".into()],
            dom_in: String::new(),
        }
    }

    fn sel(&self) -> &Vec<String> {
        if self.mode_exclude {
            &self.ex
        } else {
            &self.incl
        }
    }

    fn sel_mut(&mut self) -> &mut Vec<String> {
        if self.mode_exclude {
            &mut self.ex
        } else {
            &mut self.incl
        }
    }

    pub fn flip_app(&mut self, id: &str) {
        let sel = self.sel_mut();
        if let Some(pos) = sel.iter().position(|x| x == id) {
            sel.remove(pos);
        } else {
            sel.push(id.to_string());
        }
    }

    pub fn set_mode(&mut self, exclude: bool) {
        self.mode_exclude = exclude;
    }

    pub fn sug_apply(&mut self) {
        for a in APPS.iter().filter(|a| a.vpn) {
            if !self.ex.iter().any(|x| x == a.id) {
                self.ex.push(a.id.to_string());
            }
        }
    }

    pub fn add_domain(&mut self, lang: Lang) {
        let din = self.dom_in.trim().to_lowercase();
        if valid_domain(&din, &self.doms, lang) {
            self.doms.push(din);
            self.dom_in.clear();
        }
    }

    pub fn drop_domain(&mut self, v: &str) {
        self.doms.retain(|x| x != v);
    }
}

fn kind_of(v: &str, lang: Lang) -> Option<&'static str> {
    let subnet = |s: &str| {
        let parts: Vec<&str> = s.split('/').collect();
        parts.len() == 2
            && ipv4(parts[0])
            && parts[1].parse::<u8>().map(|n| n <= 32).unwrap_or(false)
    };
    if subnet(v) {
        Some(t2(lang, "Subnet", "Подсеть"))
    } else if ipv4(v) {
        Some(t2(lang, "IP address", "IP-адрес"))
    } else if v.starts_with("*.") {
        Some(t2(lang, "Domain and subdomains", "Домен и поддомены"))
    } else if is_domain(v) {
        Some(t2(lang, "Domain", "Домен"))
    } else {
        None
    }
}

fn ipv4(s: &str) -> bool {
    let octets: Vec<&str> = s.split('.').collect();
    octets.len() == 4
        && octets.iter().all(|o| {
            !o.is_empty() && o.len() <= 3 && o.parse::<u16>().map(|n| n <= 255).unwrap_or(false)
        })
}

fn is_domain(s: &str) -> bool {
    let labels: Vec<&str> = s.split('.').collect();
    labels.len() >= 2
        && labels.iter().all(|l| {
            !l.is_empty()
                && l.chars()
                    .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
        })
}

fn valid_domain(din: &str, doms: &[String], lang: Lang) -> bool {
    if din.is_empty() {
        return false;
    }
    let Some(kind) = kind_of(din, lang) else {
        return false;
    };
    if doms.iter().any(|x| x == din) {
        return false;
    }
    let wild = t2(lang, "Domain and subdomains", "Домен и поддомены");
    if kind == wild {
        // require *.domain.tld
        let rest = &din[2..];
        return is_domain(rest);
    }
    true
}

pub fn render(st: &AppState, lang: Lang, s: &SplitState) {
    let ex = s.mode_exclude;
    let sel = s.sel();
    let q = s.query.trim().to_lowercase();

    let matches = |a: &App| {
        (s.sys || !a.sys || sel.iter().any(|x| x == a.id))
            && (q.is_empty()
                || a.name.to_lowercase().contains(&q)
                || t2(lang, a.cat_en, a.cat_ru).to_lowercase().contains(&q))
    };
    let vis: Vec<&App> = APPS.iter().filter(|a| matches(a)).collect();

    let row = |a: &App, i: usize, on: bool| -> SplitAppRow {
        let blocks = a.vpn && ex && !on;
        SplitAppRow {
            id: a.id.into(),
            name: a.name.into(),
            letter: a.name.chars().next().unwrap_or(' ').to_string().into(),
            color: icon(a).into(),
            sub: if blocks {
                t2(lang, "Often blocks VPNs", "Часто блокирует VPN").into()
            } else {
                t2(lang, a.cat_en, a.cat_ru).into()
            },
            sub_warn: blocks,
            selected: on,
            top_border: i > 0,
        }
    };

    let sel_a: Vec<SplitAppRow> = vis
        .iter()
        .filter(|a| sel.iter().any(|x| x == a.id))
        .enumerate()
        .map(|(i, a)| row(a, i, true))
        .collect();
    let rest_a: Vec<SplitAppRow> = vis
        .iter()
        .filter(|a| !sel.iter().any(|x| x == a.id))
        .enumerate()
        .map(|(i, a)| row(a, i, false))
        .collect();

    let sug: Vec<&App> = APPS
        .iter()
        .filter(|a| a.vpn && !s.ex.iter().any(|x| x == a.id))
        .collect();

    let modes = vec![
        SplitModeRow {
            key: 0,
            name: t2(
                lang,
                "Everything via VPN except selected",
                "Всё через VPN, кроме выбранных",
            )
            .into(),
            hint: t2(
                lang,
                "Safer: new apps are protected by default.",
                "Надёжнее: новые приложения по умолчанию защищены.",
            )
            .into(),
            selected: ex,
            top_border: false,
        },
        SplitModeRow {
            key: 1,
            name: t2(lang, "Only selected via VPN", "Только выбранные через VPN").into(),
            hint: t2(
                lang,
                "Other apps go direct — even ones you forgot about.",
                "Остальные приложения ходят напрямую — даже если вы про них забыли.",
            )
            .into(),
            selected: !ex,
            top_border: true,
        },
    ];

    let sug_chips: Vec<SplitChip> = sug
        .iter()
        .map(|a| SplitChip {
            name: a.name.into(),
            letter: a.name.chars().next().unwrap_or(' ').to_string().into(),
            color: icon(a).into(),
        })
        .collect();

    let n_sel = sel.len();
    let din = s.dom_in.trim().to_lowercase();
    let dup = s.doms.contains(&din);
    let dk = if din.is_empty() {
        None
    } else {
        kind_of(&din, lang)
    };
    let valid = valid_domain(&din, &s.doms, lang);

    let doms: Vec<SplitDomainRow> = s
        .doms
        .iter()
        .map(|v| SplitDomainRow {
            value: v.clone().into(),
            kind: kind_of(v, lang).unwrap_or("").into(),
        })
        .collect();

    let dom_hint: SharedString = if din.is_empty() {
        t2(
            lang,
            "A domain, *.domain wildcard, IP address or subnet. Applies to every app.",
            "Домен, маска *.домен, IP-адрес или подсеть. Правило работает для всех приложений.",
        )
        .into()
    } else if dup {
        t2(lang, "This rule already exists.", "Такое правило уже есть.").into()
    } else if valid {
        let kl = dk.unwrap_or("").to_lowercase();
        match lang {
            Lang::Ru => format!("Будет добавлено как {}.", kl),
            _ => format!("Will be added as {}.", kl),
        }
        .into()
    } else {
        t2(
            lang,
            "Doesn’t look like a domain, IP or subnet.",
            "Не похоже на домен, IP или подсеть.",
        )
        .into()
    };

    let no_match = rest_a.is_empty() && (!q.is_empty() || sel_a.is_empty());
    let no_match_text: SharedString = if !q.is_empty() {
        match lang {
            Lang::Ru => format!("Ничего не найдено по «{}»", s.query.trim()),
            _ => format!("Nothing matches “{}”", s.query.trim()),
        }
        .into()
    } else {
        t2(lang, "All apps are selected", "Все приложения выбраны").into()
    };

    let m = |v: Vec<SplitAppRow>| ModelRc::new(VecModel::from(v));

    st.set_split_on(s.on);
    st.set_split_mode(if ex { 0 } else { 1 });
    st.set_split_lead(
        t2(
            lang,
            "Choose which apps and sites go through the HolyNet route and which go direct over your network.",
            "Выберите, какие приложения и сайты идут через маршрут HolyNet, а какие — напрямую через вашу сеть.",
        )
        .into(),
    );
    st.set_split_off_note(
        t2(
            lang,
            "All device traffic currently goes through the route.",
            "Сейчас весь трафик устройства идёт через маршрут.",
        )
        .into(),
    );
    st.set_split_modes(ModelRc::new(VecModel::from(modes)));

    st.set_split_sug_visible(ex && !s.sug_hide && !sug.is_empty());
    st.set_split_sug_text(
        t2(
            lang,
            "These apps often block foreign IP addresses. Excluding them sends them direct.",
            "Эти приложения часто блокируют зарубежные IP-адреса. Если исключить их, они пойдут напрямую.",
        )
        .into(),
    );
    st.set_split_sug_btn(
        match lang {
            Lang::Ru => format!("Исключить {}", sug.len()),
            _ => format!("Exclude {}", sug.len()),
        }
        .into(),
    );
    st.set_split_sug(ModelRc::new(VecModel::from(sug_chips)));

    st.set_split_sys_on(s.sys);
    st.set_split_has_sel(!sel_a.is_empty());
    st.set_split_sel_n(sel_a.len().to_string().into());
    st.set_split_sel_cap(
        if ex {
            t2(lang, "Direct", "Напрямую")
        } else {
            t2(lang, "Via VPN", "Через VPN")
        }
        .into(),
    );
    st.set_split_sel(m(sel_a));
    st.set_split_rest_n(rest_a.len().to_string().into());
    st.set_split_rest_cap(
        if ex {
            t2(lang, "Via VPN", "Через VPN")
        } else {
            t2(lang, "Direct", "Напрямую")
        }
        .into(),
    );
    st.set_split_rest(m(rest_a));
    st.set_split_no_match(no_match);
    st.set_split_no_match_text(no_match_text);

    st.set_split_dom_cap(
        if ex {
            t2(
                lang,
                "Sites and addresses direct",
                "Сайты и адреса напрямую",
            )
        } else {
            t2(
                lang,
                "Sites and addresses via VPN",
                "Сайты и адреса через VPN",
            )
        }
        .into(),
    );
    st.set_split_dom_n(s.doms.len().to_string().into());
    st.set_split_doms(ModelRc::new(VecModel::from(doms)));
    st.set_split_dom_hint(dom_hint);
    st.set_split_dom_hint_warn(!din.is_empty() && !valid);
    st.set_split_add_enabled(valid);
    st.set_split_show_risk(ex && (n_sel > 0 || !s.doms.is_empty()));

    // summary for the shield entry row.
    let count = n_sel + s.doms.len();
    let summary: SharedString = if !s.on {
        t2(lang, "Off", "Выкл").into()
    } else if ex {
        match lang {
            Lang::Ru => format!("{} напрямую", count),
            _ => format!("{} direct", count),
        }
        .into()
    } else {
        match lang {
            Lang::Ru => format!("только {}", count),
            _ => format!("only {}", count),
        }
        .into()
    };
    st.set_split_summary(summary);
}
