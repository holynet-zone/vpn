use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;
use std::time::Duration;

use slint::{ComponentHandle, ModelRc, SharedString, Timer, TimerMode, VecModel};

use crate::data;
use crate::domain;
use crate::{
    Accent, AppState, AppWindow, ConnStatus, Lang, PrioTab, RouteTab, Screen, Str, Theme, ThemeMode,
};

const SPARK_LEN: usize = 34;

struct Core {
    status: ConnStatus,
    server_id: String,
    transport_id: String,
    auto_transport: bool,
    cipher: usize,
    toggles: [bool; 4],
    apps: Vec<bool>,
    query: String,
    sec: u64,
    down: f64,
    up: f64,
    spark: VecDeque<f32>,
    banner: Option<(String, String)>,
    lang: Lang,
    mode: ThemeMode,
    accent: Accent,
    space_id: String,
    exit_id: String,
    hops: Vec<String>,
    prio: i32,
    route_tab: RouteTab,
    manual_mode: bool,
    probing: bool,
}


fn detect_lang() -> Lang {
    let loc = sys_locale::get_locale().unwrap_or_default().to_lowercase();
    if loc.starts_with("ru") {
        Lang::Ru
    } else if loc.starts_with("zh") {
        Lang::Zh
    } else if loc.starts_with("ja") {
        Lang::Ja
    } else {
        Lang::En
    }
}

impl Core {
    fn new() -> Self {
        Self {
            status: ConnStatus::Off,
            server_id: "nl".into(),
            transport_id: "udp".into(),
            auto_transport: true,
            cipher: 0,
            toggles: [true, true, true, false],
            apps: vec![true, true, false, false, true, false],
            query: String::new(),
            sec: 0,
            down: 0.0,
            up: 0.0,
            spark: VecDeque::from(vec![1.0; SPARK_LEN]),
            banner: None,
            lang: detect_lang(),
            mode: ThemeMode::System,
            accent: Accent::Halo,
            space_id: "core".into(),
            exit_id: "us".into(),
            hops: vec!["nl".into(), "de".into()],
            prio: 1,
            route_tab: RouteTab::Auto,
            manual_mode: false,
            probing: false,
        }
    }
}

pub struct Controller {
    _tick: Timer,
    _spark: Timer,
}

impl Controller {
    pub fn new(window: &AppWindow) -> Self {
        let core = Rc::new(RefCell::new(Core::new()));

        {
            let c = core.borrow();
            window.global::<Theme>().set_accent(c.accent);
            window.global::<Theme>().set_mode(c.mode);
            window.global::<Str>().set_lang(c.lang);
        }


        window
            .global::<Screen>()
            .set_mobile_target(cfg!(target_os = "android"));

        wire(window, &core);
        render_all(window, &core.borrow());

        #[cfg(target_os = "android")]
        crate::android_ext::request_high_refresh_rate();

        Self {
            _tick: start_traffic_timer(window, &core),
            _spark: start_spark_timer(window, &core),
        }
    }
}

fn model<T: Clone + 'static>(v: Vec<T>) -> ModelRc<T> {
    ModelRc::new(VecModel::from(v))
}

fn privacy(c: &Core) -> i32 {
    let mut s = 40;
    if c.toggles[0] {
        s += 25;
    }
    if c.toggles[2] {
        s += 20;
    }
    if c.toggles[1] {
        s += 15;
    }
    if c.toggles[3] {
        s -= 10;
    }
    if data::is_vk(&c.transport_id) {
        s += 5;
    }
    s.min(100)
}

fn fmt_time(sec: u64) -> String {
    let (h, m, s) = (sec / 3600, (sec / 60) % 60, sec % 60);
    if h > 0 {
        format!("{}:{:02}:{:02}", h, m, s)
    } else {
        format!("{:02}:{:02}", m, s)
    }
}

fn t4<'a>(lang: Lang, en: &'a str, ru: &'a str, zh: &'a str, ja: &'a str) -> &'a str {
    match lang {
        Lang::Ru => ru,
        Lang::Zh => zh,
        Lang::Ja => ja,
        _ => en,
    }
}

fn fmt_bytes(v: f64, lang: Lang) -> String {
    let ru = matches!(lang, Lang::Ru);
    let big = v >= 1024.0;
    let (val, unit) = if big {
        (v / 1024.0, if ru { " ГБ" } else { " GB" })
    } else {
        (v, if ru { " МБ" } else { " MB" })
    };
    let mut num = if big {
        format!("{:.2}", val)
    } else {
        format!("{:.1}", val)
    };
    if ru {
        num = num.replace('.', ",");
    }
    format!("{}{}", num, unit)
}

fn render_all(app: &AppWindow, c: &Core) {
    let st = app.global::<AppState>();
    let lang = c.lang;
    let dark = app.global::<Theme>().get_dark();

    #[cfg(target_os = "android")]
    crate::android_ext::set_light_system_bars(!dark);

    let (servers, sel) = data::server_rows(lang, &c.server_id, &c.query);
    let (transports, tr) = data::transport_rows(lang, &c.transport_id);
    let (ciphers, cipher_name) = data::cipher_rows(lang, c.cipher);

    st.set_servers(model(servers));
    st.set_transports(model(transports));
    st.set_ciphers(model(ciphers));
    st.set_chain(model(data::chain(&c.transport_id)));
    st.set_toggles(model(data::toggle_rows(lang, &c.toggles)));
    st.set_apps(model(data::app_rows(lang, &c.apps)));
    st.set_devices(model(data::device_rows(lang)));
    st.set_proto_rows(model(data::proto_rows(lang, &cipher_name, &c.transport_id)));
    st.set_palettes(model(data::palette_rows(lang, dark, c.accent)));

    st.set_server_code(sel.code.into());
    st.set_server_meta(sel.meta.into());
    st.set_server_ping(sel.ping.into());

    st.set_transport_code(tr.name.clone().into());
    st.set_transport_title(tr.title.into());
    st.set_transport_desc(tr.desc.into());
    st.set_auto_transport(c.auto_transport);

    let sub = match lang {
        Lang::Ru => format!("Трафик идёт через {}, транспорт {}", sel.city, tr.name),
        Lang::Zh => format!("流量经 {}，传输 {}", sel.city, tr.name),
        Lang::Ja => format!("{} 経由で通信中・トランスポート {}", sel.city, tr.name),
        _ => format!("Traffic flows through {} over {}", sel.city, tr.name),
    };
    st.set_server_city(sel.city.into());
    st.set_status_sub(sub.into());

    st.set_kill_on(c.toggles[0]);
    st.set_privacy_score(privacy(c));

    let cipher_short = cipher_name.split('-').next().unwrap_or(&cipher_name);
    st.set_cipher_name(cipher_short.into());
    st.set_proto_summary(format!("{} · {}", tr.name, cipher_short).into());
    st.set_dev_summary(format!("3 {} 6", t4(lang, "of", "из", "/", "/")).into());

    let tunneled = c.apps.iter().filter(|b| **b).count();
    let split = match lang {
        Lang::Ru => format!("{} в канале", tunneled),
        Lang::Zh => format!("{} 经通道", tunneled),
        Lang::Ja => format!("{} 件トンネル経由", tunneled),
        _ => format!("{} tunneled", tunneled),
    };
    st.set_split_summary(split.into());

    st.set_banner_visible(c.banner.is_some());
    if let Some((a, b)) = &c.banner {
        let text = match lang {
            Lang::Ru => format!(
                "{} перестал проходить — переключаюсь на {}. Сессия не рвётся.",
                a, b
            ),
            Lang::Zh => format!("{} 无法通过 — 正在切换到 {}。会话不会中断。", a, b),
            Lang::Ja => format!(
                "{} が通らなくなりました — {} に切り替えます。セッションは維持されます。",
                a, b
            ),
            _ => format!(
                "{} stopped passing — switching to {}. The session stays alive.",
                a, b
            ),
        };
        st.set_banner_text(text.into());
    }

    render_route(app, c);
    render_live(app, c);
}

fn render_route(app: &AppWindow, c: &Core) {
    let st = app.global::<AppState>();
    let lang = c.lang;
    let space = c.space_id.as_str();
    let exit = domain::resolve_exit(space, &c.exit_id);

    let auto_path = domain::plan(space, exit, c.prio);
    let manual_path = domain::manual_path(space, &c.hops, exit);
    let path: Vec<&str> = if c.manual_mode {
        manual_path.iter().copied().collect()
    } else {
        auto_path.iter().copied().collect()
    };

    let ev = domain::exit_view(lang, exit);
    st.set_exit_code(ev.code.clone().into());
    st.set_exit_city(ev.city.clone().into());
    st.set_exit_meta(ev.meta.clone().into());
    st.set_exit_ping(ev.ping.clone().into());

    let cost = domain::path_cost(space, &path);
    let miss = domain::path_missing(space, &path);
    st.set_path_hops(domain::path_hops(space, lang, &path));
    st.set_path_sum(domain::path_sum(lang, cost, miss).into());
    st.set_path_estimated(miss > 0);
    st.set_path_warn(domain::path_warn(lang).into());
    st.set_hops_count(domain::hops_count(lang, path.len()).into());
    st.set_route_mode_label(domain::mode_label(lang, c.manual_mode).into());

    let first_code = domain::exit_view(lang, path[0]).code;
    if c.status == ConnStatus::On {
        st.set_chain_log(domain::chain_log(lang, &first_code, &ev.code));
    } else {
        st.set_chain_log(model::<slint::SharedString>(vec![]));
    }

    let sub = match lang {
        Lang::Ru => format!("Трафик идёт через {}, транспорт {}", ev.city, c.transport_id.to_uppercase()),
        Lang::Zh => format!("流量经 {}，传输 {}", ev.city, c.transport_id.to_uppercase()),
        Lang::Ja => format!("{} 経由で通信中・トランスポート {}", ev.city, c.transport_id.to_uppercase()),
        _ => format!("Traffic flows through {} over {}", ev.city, c.transport_id.to_uppercase()),
    };
    st.set_status_sub(sub.into());

    st.set_route_tab(c.route_tab);
    st.set_route_auto(!c.manual_mode);
    st.set_route_manual(c.manual_mode);
    st.set_prio(c.prio);
    let names = domain::prio_names(lang);
    let prios: Vec<PrioTab> = (0..3)
        .map(|i| PrioTab {
            name: names[i].into(),
            selected: i as i32 == c.prio,
        })
        .collect();
    st.set_prios(model(prios));
    let auto_cost = domain::path_cost(space, &auto_path);
    let extra = auto_cost - ev.rtt.max(0);
    st.set_prio_effect(domain::prio_effect(lang, auto_path.len().saturating_sub(1), extra).into());
    st.set_plan_reason(
        domain::plan_reason(lang, c.prio, auto_path.len(), domain::node_count(space)).into(),
    );

    let manual_view: Vec<&str> = manual_path.iter().copied().collect();
    st.set_draft_hops(domain::draft_hops(space, lang, &manual_view));
    st.set_add_hop_list(domain::add_hop_list(space, lang, exit, &c.hops));
    let relays = manual_path.len().saturating_sub(1);
    st.set_no_relays(relays == 0);
    st.set_has_relays(relays > 0);
    st.set_can_add_hop(manual_path.len() < domain::MAX_HOPS);
    st.set_empty_title(domain::empty_title(lang).into());
    st.set_empty_body(domain::empty_body(lang).into());

    st.set_node_list(domain::node_rows(space, lang, &c.query, exit, &c.hops, c.probing));
    st.set_edge_list(domain::edge_rows(space, lang));
    st.set_topo_counts(domain::topo_counts(lang, space, if c.probing { 0 } else { 12 }).into());
    st.set_probe_label(domain::probe_label(lang, c.probing).into());
    st.set_probing(c.probing);
    st.set_globe_nodes(domain::globe_nodes(space, lang));

    st.set_visibility(domain::visibility(space, lang, &path, &c.transport_id));
    st.set_factors(domain::factors(lang, &path, c.toggles[2], c.toggles[0]));
    st.set_privacy_note(domain::privacy_note(lang, path.len()).into());
}

fn render_live(app: &AppWindow, c: &Core) {
    let st = app.global::<AppState>();
    let lang = c.lang;
    st.set_status(c.status);

    if c.status == ConnStatus::On {
        st.set_session_time(fmt_time(c.sec).into());
        st.set_down_text(fmt_bytes(c.down, lang).into());
        st.set_up_text(fmt_bytes(c.up, lang).into());
        let last = *c.spark.back().unwrap_or(&0.0);
        let mbps = 12 + (last * 2.4) as i32;
        let unit = if matches!(lang, Lang::Ru) { " Мбит/с" } else { " Mbps" };
        st.set_speed_now(format!("{}{}", mbps, unit).into());
    } else {
        st.set_session_time("—".into());
        st.set_down_text("—".into());
        st.set_up_text("—".into());
        st.set_speed_now(t4(lang, "no data", "нет данных", "无数据", "データなし").into());
    }

    let norm: Vec<f32> = c
        .spark
        .iter()
        .map(|v| (v / 48.0).clamp(0.02, 1.0))
        .collect();
    st.set_spark(model(norm));
}

fn wire(window: &AppWindow, core: &Rc<RefCell<Core>>) {
    let st = window.global::<AppState>();

    {
        let w = window.as_weak();
        let cc = core.clone();
        st.on_toggle_connect(move || {
            let Some(app) = w.upgrade() else { return };
            let restart = {
                let mut c = cc.borrow_mut();
                match c.status {
                    ConnStatus::Off => {
                        c.status = ConnStatus::Connecting;
                        true
                    }
                    _ => {
                        c.status = ConnStatus::Off;
                        c.banner = None;
                        false
                    }
                }
            };
            render_all(&app, &cc.borrow());
            if restart {
                let w = app.as_weak();
                let cc2 = cc.clone();
                Timer::single_shot(Duration::from_millis(1500), move || {
                    if let Some(app) = w.upgrade() {
                        {
                            let mut c = cc2.borrow_mut();
                            if c.status == ConnStatus::Connecting {
                                c.status = ConnStatus::On;
                                c.sec = 0;
                                c.down = 0.0;
                                c.up = 0.0;
                            }
                        }
                        render_all(&app, &cc2.borrow());
                    }
                });
            }
        });
    }

    {
        let w = window.as_weak();
        let cc = core.clone();
        st.on_smart_pick(move || {
            if let Some(app) = w.upgrade() {
                {
                    let mut c = cc.borrow_mut();
                    let fastest = domain::fastest_exit(&c.space_id);
                    c.exit_id = fastest.to_string();
                    c.manual_mode = false;
                    c.route_tab = RouteTab::Auto;
                }
                app.global::<Screen>().invoke_go(crate::Page::Route);
                render_all(&app, &cc.borrow());
            }
        });
    }

    {
        let w = window.as_weak();
        let cc = core.clone();
        st.on_simulate(move || {
            let Some(app) = w.upgrade() else { return };
            let next = {
                let mut c = cc.borrow_mut();
                let cur = c.transport_id.clone();
                let next = data::next_transport(&cur).to_string();
                let a = data::transport_name(&cur).to_string();
                let b = data::transport_name(&next).to_string();
                c.status = ConnStatus::Connecting;
                c.banner = Some((a, b));
                next
            };
            render_all(&app, &cc.borrow());

            let w1 = app.as_weak();
            let cc1 = cc.clone();
            Timer::single_shot(Duration::from_millis(1400), move || {
                if let Some(app) = w1.upgrade() {
                    {
                        let mut c = cc1.borrow_mut();
                        c.status = ConnStatus::On;
                        c.transport_id = next.clone();
                    }
                    render_all(&app, &cc1.borrow());
                }
            });
            let w2 = app.as_weak();
            let cc2 = cc.clone();
            Timer::single_shot(Duration::from_millis(7000), move || {
                if let Some(app) = w2.upgrade() {
                    cc2.borrow_mut().banner = None;
                    render_all(&app, &cc2.borrow());
                }
            });
        });
    }

    {
        let w = window.as_weak();
        let cc = core.clone();
        st.on_select_server(move |id: SharedString| {
            if let Some(app) = w.upgrade() {
                cc.borrow_mut().server_id = id.to_string();
                render_all(&app, &cc.borrow());
            }
        });
    }
    {
        let w = window.as_weak();
        let cc = core.clone();
        st.on_select_transport(move |id: SharedString| {
            if let Some(app) = w.upgrade() {
                {
                    let mut c = cc.borrow_mut();
                    c.transport_id = id.to_string();
                    c.auto_transport = false;
                }
                render_all(&app, &cc.borrow());
            }
        });
    }
    {
        let w = window.as_weak();
        let cc = core.clone();
        st.on_select_cipher(move |i: i32| {
            if let Some(app) = w.upgrade() {
                cc.borrow_mut().cipher = i.max(0) as usize;
                render_all(&app, &cc.borrow());
            }
        });
    }
    {
        let w = window.as_weak();
        let cc = core.clone();
        st.on_flip_toggle(move |id: SharedString| {
            if let Some(app) = w.upgrade() {
                if let Some(idx) = data::toggle_index(&id) {
                    let mut c = cc.borrow_mut();
                    c.toggles[idx] = !c.toggles[idx];
                }
                render_all(&app, &cc.borrow());
            }
        });
    }
    {
        let w = window.as_weak();
        let cc = core.clone();
        st.on_flip_app(move |i: i32| {
            if let Some(app) = w.upgrade() {
                let idx = i.max(0) as usize;
                {
                    let mut c = cc.borrow_mut();
                    if idx < c.apps.len() {
                        c.apps[idx] = !c.apps[idx];
                    }
                }
                render_all(&app, &cc.borrow());
            }
        });
    }
    {
        let w = window.as_weak();
        let cc = core.clone();
        st.on_set_auto_transport(move |b: bool| {
            if let Some(app) = w.upgrade() {
                cc.borrow_mut().auto_transport = b;
                render_all(&app, &cc.borrow());
            }
        });
    }
    {
        let w = window.as_weak();
        let cc = core.clone();
        st.on_query_changed(move |q: SharedString| {
            if let Some(app) = w.upgrade() {
                cc.borrow_mut().query = q.to_string();
                render_all(&app, &cc.borrow());
            }
        });
    }
    {
        let w = window.as_weak();
        let cc = core.clone();
        st.on_select_palette(move |i: i32| {
            if let Some(app) = w.upgrade() {
                let accent = data::accent_from_index(i);
                cc.borrow_mut().accent = accent;
                app.global::<Theme>().set_accent(accent);
                render_all(&app, &cc.borrow());
            }
        });
    }
    {
        let w = window.as_weak();
        let cc = core.clone();
        st.on_set_mode(move |m: ThemeMode| {
            if let Some(app) = w.upgrade() {
                cc.borrow_mut().mode = m;
                app.global::<Theme>().set_mode(m);
                render_all(&app, &cc.borrow());
            }
        });
    }
    {
        let w = window.as_weak();
        let cc = core.clone();
        st.on_set_lang(move |l: Lang| {
            if let Some(app) = w.upgrade() {
                cc.borrow_mut().lang = l;
                app.global::<Str>().set_lang(l);
                render_all(&app, &cc.borrow());
            }
        });
    }

    {
        let w = window.as_weak();
        let cc = core.clone();
        st.on_select_route_tab(move |tab: RouteTab| {
            if let Some(app) = w.upgrade() {
                {
                    let mut c = cc.borrow_mut();
                    c.route_tab = tab;
                    match tab {
                        RouteTab::Auto => c.manual_mode = false,
                        RouteTab::Manual => c.manual_mode = true,
                        RouteTab::Graph => {}
                    }
                }
                render_all(&app, &cc.borrow());
            }
        });
    }
    {
        let w = window.as_weak();
        let cc = core.clone();
        st.on_set_prio(move |i: i32| {
            if let Some(app) = w.upgrade() {
                {
                    let mut c = cc.borrow_mut();
                    c.prio = i.clamp(0, 2);
                    c.manual_mode = false;
                    c.route_tab = RouteTab::Auto;
                }
                render_all(&app, &cc.borrow());
            }
        });
    }
    {
        let w = window.as_weak();
        let cc = core.clone();
        st.on_hop_up(move |i: i32| {
            if let Some(app) = w.upgrade() {
                {
                    let mut c = cc.borrow_mut();
                    let i = i as usize;
                    if i > 0 && i < c.hops.len() {
                        c.hops.swap(i - 1, i);
                        c.manual_mode = true;
                    }
                }
                render_all(&app, &cc.borrow());
            }
        });
    }
    {
        let w = window.as_weak();
        let cc = core.clone();
        st.on_hop_down(move |i: i32| {
            if let Some(app) = w.upgrade() {
                {
                    let mut c = cc.borrow_mut();
                    let i = i as usize;
                    if i + 1 < c.hops.len() {
                        c.hops.swap(i, i + 1);
                        c.manual_mode = true;
                    }
                }
                render_all(&app, &cc.borrow());
            }
        });
    }
    {
        let w = window.as_weak();
        let cc = core.clone();
        st.on_hop_drop(move |i: i32| {
            if let Some(app) = w.upgrade() {
                {
                    let mut c = cc.borrow_mut();
                    let i = i as usize;
                    if i < c.hops.len() {
                        c.hops.remove(i);
                        c.manual_mode = true;
                    }
                }
                render_all(&app, &cc.borrow());
            }
        });
    }
    {
        let w = window.as_weak();
        st.on_hop_swap(move || {
            if let Some(app) = w.upgrade() {
                app.global::<Screen>().invoke_go(crate::Page::Nodes);
            }
        });
    }
    {
        let w = window.as_weak();
        let cc = core.clone();
        st.on_add_hop(move |id: SharedString| {
            if let Some(app) = w.upgrade() {
                {
                    let mut c = cc.borrow_mut();
                    c.hops.push(id.to_string());
                    let cap = domain::MAX_HOPS - 1;
                    if c.hops.len() > cap {
                        c.hops.truncate(cap);
                    }
                    c.manual_mode = true;
                    c.route_tab = RouteTab::Manual;
                }
                render_all(&app, &cc.borrow());
            }
        });
    }
    {
        let w = window.as_weak();
        let cc = core.clone();
        st.on_reset_draft(move || {
            if let Some(app) = w.upgrade() {
                {
                    let mut c = cc.borrow_mut();
                    c.hops.clear();
                    c.manual_mode = true;
                }
                render_all(&app, &cc.borrow());
            }
        });
    }
    {
        let w = window.as_weak();
        let cc = core.clone();
        st.on_draft_from_plan(move || {
            if let Some(app) = w.upgrade() {
                {
                    let mut c = cc.borrow_mut();
                    let exit = domain::resolve_exit(&c.space_id, &c.exit_id);
                    let mut plan = domain::plan(&c.space_id, exit, c.prio);
                    plan.pop();
                    c.hops = plan.iter().map(|s| s.to_string()).collect();
                    c.manual_mode = true;
                    c.route_tab = RouteTab::Manual;
                }
                render_all(&app, &cc.borrow());
            }
        });
    }
    {
        let w = window.as_weak();
        let cc = core.clone();
        st.on_fill_fast(move || {
            if let Some(app) = w.upgrade() {
                {
                    let mut c = cc.borrow_mut();
                    let exit = domain::resolve_exit(&c.space_id, &c.exit_id);
                    let mut plan = domain::plan(&c.space_id, exit, c.prio);
                    plan.pop();
                    c.hops = plan.iter().map(|s| s.to_string()).collect();
                    c.manual_mode = true;
                }
                render_all(&app, &cc.borrow());
            }
        });
    }
    {
        let w = window.as_weak();
        let cc = core.clone();
        st.on_select_exit(move |id: SharedString| {
            if let Some(app) = w.upgrade() {
                cc.borrow_mut().exit_id = id.to_string();
                app.global::<Screen>().invoke_go(crate::Page::Route);
                render_all(&app, &cc.borrow());
            }
        });
    }
    {
        let w = window.as_weak();
        let cc = core.clone();
        st.on_pick_node(move |id: SharedString| {
            if let Some(app) = w.upgrade() {
                cc.borrow_mut().exit_id = id.to_string();
                render_all(&app, &cc.borrow());
            }
        });
    }
    {
        let w = window.as_weak();
        let cc = core.clone();
        st.on_apply_route(move || {
            let Some(app) = w.upgrade() else { return };
            let restart = {
                let mut c = cc.borrow_mut();
                match c.status {
                    ConnStatus::Off => {
                        c.status = ConnStatus::Connecting;
                        true
                    }
                    _ => {
                        c.status = ConnStatus::Off;
                        c.banner = None;
                        false
                    }
                }
            };
            render_all(&app, &cc.borrow());
            if restart {
                let w = app.as_weak();
                let cc2 = cc.clone();
                Timer::single_shot(Duration::from_millis(1500), move || {
                    if let Some(app) = w.upgrade() {
                        {
                            let mut c = cc2.borrow_mut();
                            if c.status == ConnStatus::Connecting {
                                c.status = ConnStatus::On;
                                c.sec = 0;
                                c.down = 0.0;
                                c.up = 0.0;
                            }
                        }
                        render_all(&app, &cc2.borrow());
                    }
                });
            }
        });
    }
    {
        let w = window.as_weak();
        let cc = core.clone();
        st.on_reprobe(move || {
            let Some(app) = w.upgrade() else { return };
            {
                let mut c = cc.borrow_mut();
                if c.probing {
                    return;
                }
                c.probing = true;
            }
            render_all(&app, &cc.borrow());
            let w = app.as_weak();
            let cc2 = cc.clone();
            Timer::single_shot(Duration::from_millis(1600), move || {
                if let Some(app) = w.upgrade() {
                    cc2.borrow_mut().probing = false;
                    render_all(&app, &cc2.borrow());
                }
            });
        });
    }
}

fn start_traffic_timer(window: &AppWindow, core: &Rc<RefCell<Core>>) -> Timer {
    let w = window.as_weak();
    let cc = core.clone();
    let timer = Timer::default();
    timer.start(TimerMode::Repeated, Duration::from_secs(1), move || {
        if let Some(app) = w.upgrade() {
            {
                let mut c = cc.borrow_mut();
                if c.status == ConnStatus::On {
                    c.sec += 1;
                    c.down += 0.6 + rand::random::<f64>() * 2.4;
                    c.up += 0.1 + rand::random::<f64>() * 0.5;
                }
            }
            render_live(&app, &cc.borrow());
        }
    });
    timer
}

fn start_spark_timer(window: &AppWindow, core: &Rc<RefCell<Core>>) -> Timer {
    let w = window.as_weak();
    let cc = core.clone();
    let timer = Timer::default();
    timer.start(TimerMode::Repeated, Duration::from_millis(260), move || {
        if let Some(app) = w.upgrade() {
            {
                let mut c = cc.borrow_mut();
                let peak = match c.transport_id.as_str() {
                    "udp" => 44.0,
                    "ws" => 32.0,
                    _ => 22.0,
                };
                let v = if c.status == ConnStatus::On {
                    4.0 + rand::random::<f32>() * peak
                } else {
                    1.0 + rand::random::<f32>() * 2.0
                };
                c.spark.pop_front();
                c.spark.push_back(v);
            }
            render_live(&app, &cc.borrow());
        }
    });
    timer
}
