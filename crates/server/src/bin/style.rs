use std::io::Read;
use inquire::ui::{Attributes, Color, RenderConfig, StyleSheet, Styled};

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

pub fn render_config() -> RenderConfig<'static> {
    let mut render_config = RenderConfig::default();
    render_config.answered_prompt_prefix = Styled::new("✔").with_fg(Color::LightGreen);
    render_config.prompt_prefix = Styled::new(">").with_fg(Color::LightRed);
    render_config.highlighted_option_prefix = Styled::new("➠").with_fg(Color::LightYellow);
    render_config.selected_checkbox = Styled::new("☑").with_fg(Color::LightGreen);
    render_config.scroll_up_prefix = Styled::new("⇞");
    render_config.scroll_down_prefix = Styled::new("⇟");
    render_config.unselected_checkbox = Styled::new("☐");
    
    render_config.error_message.message = StyleSheet::new().with_fg(Color::DarkRed);
    render_config.error_message = render_config
        .error_message
        .with_prefix(Styled::new("❌ ").with_fg(Color::DarkRed));

    render_config.answer = StyleSheet::new()
        .with_attr(Attributes::ITALIC)
        .with_fg(Color::DarkGreen);

    render_config.help_message = StyleSheet::new().with_fg(Color::DarkCyan);

    render_config
}

// a helper function to create pretty placeholders for encrypted information
pub fn format_opaque_bytes(bytes: &[u8]) -> String {
    if bytes.len() < 8 {
        String::new()
    } else {
        let max_bytes = 32;
        let rem = if bytes.len() > max_bytes {
            &bytes[0..max_bytes]
        } else {
            bytes
        };

        let hex_str: String = rem.iter().map(|b| format!("{:02x}", b)).collect();

        let block_chars = [
            "\u{2595}", "\u{2581}", "\u{2582}", "\u{2583}", "\u{2584}", "\u{2585}",
            "\u{2586}", "\u{2587}", "\u{2588}", "\u{2589}", "\u{259A}", "\u{259B}",
            "\u{259C}", "\u{259D}", "\u{259E}", "\u{259F}"
        ];

        hex_str.chars()
            .filter_map(|c| {
                match c {
                    '0'..='9' => Some(block_chars[c.to_digit(16).unwrap() as usize].to_string()),
                    'a'..='f' => Some(block_chars[c.to_digit(16).unwrap() as usize].to_string()),
                    _ => None,
                }
            })
            .collect()
    }
}
