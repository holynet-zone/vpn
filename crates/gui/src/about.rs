use slint::{ModelRc, SharedString, VecModel};

use crate::Lang;
use crate::{AppState, DocSection, LegalDocRow};

include!(concat!(env!("OUT_DIR"), "/licenses.rs"));

type L2 = (&'static str, &'static str);
type Sec = (L2, L2); // (heading, paragraph)

struct Doc {
    key: &'static str,
    title: L2,
    updated: L2,
    tldr: L2,
    sections: &'static [Sec],
}

fn p2(lang: Lang, s: L2) -> &'static str {
    match lang {
        Lang::Ru => s.1,
        _ => s.0,
    }
}

static DOCS: &[Doc] = &[
    Doc {
        key: "privacy",
        title: ("Privacy Policy", "Политика конфиденциальности"),
        updated: ("Updated 1 September 2026", "Обновлено 1 сентября 2026"),
        tldr: (
            "We can’t see where you go, and we keep nothing that links traffic to you.",
            "Мы не видим, куда вы ходите, и не храним ничего, что связывает трафик с вами.",
        ),
        sections: &[
            (
                ("What we don’t collect", "Что мы не собираем"),
                (
                    "Traffic contents, visited addresses, DNS queries, your IP address or session times. Nodes run without logs, and onion layers stop any single node from seeing both you and the destination.",
                    "Содержимое трафика, посещённые адреса, DNS-запросы, ваш IP-адрес и время сессий. Узлы работают без журналов, а onion-слои не дают одному узлу видеть одновременно вас и назначение.",
                ),
            ),
            (
                ("What stays on your device", "Что хранится на устройстве"),
                (
                    "Space keys, the node registry and your settings. They live on the phone and are never synced to our servers.",
                    "Ключи пространств, реестр узлов и настройки. Они остаются на телефоне и не синхронизируются с нашими серверами.",
                ),
            ),
            (
                ("Crash reports", "Отчёты о сбоях"),
                (
                    "Off by default. When enabled, we receive the stack trace and app version — no addresses, nodes or device identifiers.",
                    "Выключены по умолчанию. Если их включить, отправляются стек ошибки и версия приложения — без адресов, узлов и идентификаторов устройства.",
                ),
            ),
            (
                ("Payments", "Платежи"),
                (
                    "Payments are handled by a payment provider. We only receive subscription status and expiry date.",
                    "Оплату обрабатывает платёжный провайдер. Мы получаем только статус подписки и дату окончания.",
                ),
            ),
            (
                ("Government requests", "Запросы государственных органов"),
                (
                    "There is nothing to hand over: traffic data doesn’t exist. Every request we receive is published in our transparency report.",
                    "Передавать нечего: данных о трафике не существует. Каждый полученный запрос мы публикуем в отчёте о прозрачности.",
                ),
            ),
        ],
    },
    Doc {
        key: "terms",
        title: ("Terms of Service", "Условия использования"),
        updated: ("Updated 1 September 2026", "Обновлено 1 сентября 2026"),
        tldr: (
            "The service is provided as is. You are responsible for how you use it.",
            "Сервис предоставляется «как есть». Вы отвечаете за то, как им пользуетесь.",
        ),
        sections: &[
            (
                ("Accounts and spaces", "Аккаунт и пространства"),
                (
                    "Access comes from a space key. Treat it like a password: whoever holds it can connect on behalf of the space.",
                    "Доступ к сети даёт ключ пространства. Храните его как пароль: владелец ключа может подключаться от имени пространства.",
                ),
            ),
            (
                ("Subscription and refunds", "Подписка и возврат"),
                (
                    "Subscriptions renew automatically and can be cancelled any time. Within 14 days of payment we refund, no questions asked.",
                    "Подписка продлевается автоматически, отменить её можно в любой момент. В течение 14 дней после оплаты вернём деньги без объяснения причин.",
                ),
            ),
            (
                ("Availability", "Доступность"),
                (
                    "We work to keep nodes online but can’t guarantee access in a specific country or network — blocks change faster than we do.",
                    "Мы стараемся держать узлы в сети, но не гарантируем работу в конкретной стране или сети — блокировки меняются быстрее нас.",
                ),
            ),
            (
                ("Changes to these terms", "Изменения условий"),
                (
                    "We announce material changes in the app 30 days ahead. The full revision history lives in the repository.",
                    "О существенных изменениях предупреждаем в приложении за 30 дней. История правок доступна в репозитории.",
                ),
            ),
        ],
    },
    Doc {
        key: "aup",
        title: ("Acceptable Use Policy", "Допустимое использование"),
        updated: ("Updated 1 September 2026", "Обновлено 1 сентября 2026"),
        tldr: (
            "The HolyNet network may not be used to harm other people or systems.",
            "Сеть HolyNet нельзя использовать, чтобы вредить другим людям и системам.",
        ),
        sections: &[
            (
                ("Prohibited", "Запрещено"),
                (
                    "Spam, DDoS and scanning other networks, distributing malware, fraud, and child sexual abuse material.",
                    "Спам-рассылки, DDoS и сканирование чужих сетей, распространение вредоносного ПО, мошенничество и материалы сексуальной эксплуатации детей.",
                ),
            ),
            (
                ("Node load", "Нагрузка на узлы"),
                (
                    "Don’t run automated workloads on one key that degrade the space for other members.",
                    "Не запускайте на одном ключе автоматизированные нагрузки, которые мешают другим участникам пространства.",
                ),
            ),
            (
                ("Enforcement", "Что происходит при нарушении"),
                (
                    "We keep no logs, so we act on reports from node operators and revoke the space key the abuse comes from.",
                    "Журналов у нас нет, поэтому мы опираемся на жалобы операторов узлов и блокируем ключ пространства, с которого идёт злоупотребление.",
                ),
            ),
        ],
    },
    Doc {
        key: "licenses",
        title: ("Open-source licenses", "Лицензии открытого ПО"),
        updated: ("", ""),
        tldr: (
            "HolyNet is released under GPL-3.0 and builds on these projects.",
            "HolyNet распространяется по GPL-3.0 и опирается на эти проекты.",
        ),
        sections: &[],
    },
];

pub const GH: &str = "https://github.com/holynet/holynet";

pub fn doc_url(idx: usize) -> String {
    format!("{}/blob/main/legal/{}.md", GH, DOCS[idx].key)
}

// order of the legal-group rows: privacy, terms, aup, licenses.
const LEGAL_ORDER: &[usize] = &[0, 1, 2, 3];

pub fn render(st: &AppState, lang: Lang, about_doc: Option<usize>, upd: i32) {
    st.set_about_doc_open(about_doc.is_some());
    st.set_about_version_line(
        p2(
            lang,
            (
                "Version 4.0.0 · build 2026.09",
                "Версия 4.0.0 · сборка 2026.09",
            ),
        )
        .into(),
    );
    st.set_about_pitch(
        p2(
            lang,
            (
                "An open-source private network. Traffic crosses several independent nodes — none of them sees both who you are and where you are going.",
                "Приватная сеть с открытым кодом. Маршрут через несколько независимых узлов — ни один из них не видит одновременно вас и то, куда вы идёте.",
            ),
        )
        .into(),
    );
    st.set_gh_short("holynet/holynet".into());

    let (label, state): (SharedString, i32) = match upd {
        1 => (p2(lang, ("Checking…", "Проверяем…")).into(), 1),
        2 => (
            p2(lang, ("You are up to date", "Установлена последняя версия")).into(),
            2,
        ),
        _ => (
            p2(lang, ("Check for updates", "Проверить обновления")).into(),
            0,
        ),
    };
    st.set_about_update_label(label);
    st.set_about_update_state(state);

    let back_label: SharedString = if about_doc.is_some() {
        p2(lang, ("About", "О приложении")).into()
    } else {
        p2(lang, ("Settings", "Настройки")).into()
    };
    st.set_about_back_label(back_label);

    let legal: Vec<LegalDocRow> = LEGAL_ORDER
        .iter()
        .enumerate()
        .map(|(i, &idx)| LegalDocRow {
            key: idx as i32,
            title: p2(lang, DOCS[idx].title).into(),
            top_border: i > 0,
        })
        .collect();
    st.set_about_legal(ModelRc::new(VecModel::from(legal)));

    if let Some(idx) = about_doc {
        let d = &DOCS[idx];
        st.set_doc_title(p2(lang, d.title).into());
        st.set_doc_updated(p2(lang, d.updated).into());
        st.set_doc_tldr(p2(lang, d.tldr).into());
        st.set_doc_url(doc_url(idx).into());
        let secs: Vec<DocSection> = if d.key == "licenses" {
            LICENSES
                .iter()
                .enumerate()
                .map(|(i, (name, version, license))| DocSection {
                    n: format!("{:02}", i + 1).into(),
                    h: (*name).into(),
                    p: format!("v{} · {}", version, license).into(),
                })
                .collect()
        } else {
            d.sections
                .iter()
                .enumerate()
                .map(|(i, (h, p))| DocSection {
                    n: format!("{:02}", i + 1).into(),
                    h: p2(lang, *h).into(),
                    p: p2(lang, *p).into(),
                })
                .collect()
        };
        st.set_doc_sections(ModelRc::new(VecModel::from(secs)));
    } else {
        st.set_doc_sections(ModelRc::new(VecModel::from(Vec::<DocSection>::new())));
    }
}
