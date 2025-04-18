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
        /*
        // TODO: Hm, this can allow the same color for both, should rejig things to avoid this
        // Select foreground and background colors based on the first 8 bytes.
        let fg_color_index = bytes[0] % 8;
        let bg_color_index = bytes[4] % 8;

        // ANSI escape codes for foreground and background colors.
        let fg_color_code = 37; // 30 through 37 are foreground colors
        let bg_color_code = 40; // 40 through 47 are background colors
        */

        // to be more general, perhaps this should be configurable
        // an opaque address needs less space than an opaque memo, etc
        let max_bytes = 32;
        let rem = if bytes.len() > max_bytes {
            bytes[0..max_bytes].to_vec()
        } else {
            bytes.to_vec()
        };

        // Convert the rest of the bytes to hexadecimal.
        let hex_str = hex::encode_upper(rem);
        let opaque_chars: String = hex_str
            .chars()
            .map(|c| {
                match c {
                    '0' => "\u{2595}",
                    '1' => "\u{2581}",
                    '2' => "\u{2582}",
                    '3' => "\u{2583}",
                    '4' => "\u{2584}",
                    '5' => "\u{2585}",
                    '6' => "\u{2586}",
                    '7' => "\u{2587}",
                    '8' => "\u{2588}",
                    '9' => "\u{2589}",
                    'A' => "\u{259A}",
                    'B' => "\u{259B}",
                    'C' => "\u{259C}",
                    'D' => "\u{259D}",
                    'E' => "\u{259E}",
                    'F' => "\u{259F}",
                    _ => "",
                }
                    .to_string()
            })
            .collect();

        //format!("\u{001b}[{};{}m{}", fg_color_code, bg_color_code, block_chars)
        opaque_chars
    }
}
