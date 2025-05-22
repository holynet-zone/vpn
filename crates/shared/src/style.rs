
pub fn styles() -> clap::builder::Styles {
    clap::builder::Styles::styled()
        .usage(
            anstyle::Style::new()
                .bold()
                .fg_color(Some(anstyle::Color::Ansi(anstyle::AnsiColor::Green)))
        )
        .header(
            anstyle::Style::new()
                .bold()
                .fg_color(Some(anstyle::Color::Ansi(anstyle::AnsiColor::Green)))
        )
        .literal(
            anstyle::Style::new()
                .bold()
                .fg_color(Some(anstyle::Color::Ansi(anstyle::AnsiColor::Cyan)))
        )
        .invalid(
            anstyle::Style::new()
                .bold()
                .fg_color(Some(anstyle::Color::Ansi(anstyle::AnsiColor::Red)))
        )
        .error(
            anstyle::Style::new()
                .bold()
                .fg_color(Some(anstyle::Color::Ansi(anstyle::AnsiColor::Red)))
        )
        .valid(
            anstyle::Style::new()
                .bold()
                .fg_color(Some(anstyle::Color::Ansi(anstyle::AnsiColor::Green)))
        )
        .placeholder(
            anstyle::Style::new()
                .fg_color(Some(anstyle::Color::Ansi(anstyle::AnsiColor::Cyan)))
        )
}

#[macro_export]
macro_rules! success_ok {
    ($message:expr) => {
        success_ok!("OK", $message)
    };
    ($level:expr, $message:expr) => {
        println!(
            "{}{:>12}{} {}",
            anstyle::Style::new()
                .bold()
                .fg_color(Some(anstyle::Color::Ansi(anstyle::AnsiColor::Green))),
            $level,
            anstyle::Reset.render(),
            $message
        )
    };
    ($level:expr, $message:expr, $($arg:tt)*) => {
        success_ok!($level, format!($message, $($arg)*))
    };
}

#[macro_export]
macro_rules! success_err {
    ($message:expr) => {
        eprintln!(
            "{}error:{} {}",
            anstyle::Style::new()
                .bold()
                .fg_color(Some(anstyle::Color::Ansi(anstyle::AnsiColor::Red))),
            anstyle::Reset.render(),
            $message
        )
    };
    ($message:expr, $($arg:tt)*) => {
        success_err!(format!($message, $($arg)*))
    };
}

#[macro_export]
macro_rules! success_warn {
    ($message:expr) => {
        eprintln!(
            "{}warning:{} {}",
            anstyle::Style::new()
                .bold()
                .fg_color(Some(anstyle::Color::Ansi(anstyle::AnsiColor::Yellow))),
            anstyle::Reset.render(),
            $message
        )
    };
    ($message:expr, $($arg:tt)*) => {
        success_warn!(format!($message, $($arg)*))
    };
}
