use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;
use std::time::Duration;

use slint::{ComponentHandle, ModelRc, SharedString, Timer, TimerMode, VecModel};

use crate::data;
use crate::{Accent, AppState, AppWindow, ConnStatus, Lang, Screen, Str, Theme, ThemeMode};

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

    render_live(app, c);
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
                cc.borrow_mut().server_id = "fi".into();
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
