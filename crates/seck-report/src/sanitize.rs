//! Terminal-injection-safe sanitizer for LLM output strings.
//!
//! Strips:
//!   * ANSI/CSI sequences (`ESC[`)
//!   * OSC sequences (`ESC]`) — including OSC 8 hyperlinks
//!   * BiDi overrides (U+202A..U+202E, U+2066..U+2069) — Trojan Source
//!   * Zero-width characters (U+200B/C/D, U+FEFF)
//!   * All other control characters except `\n` and `\t`
//!
//! Preserves: printable Unicode, newlines, tabs.

pub fn sanitize(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\x1b' => {
                // ESC: ANSI / OSC. Skip until terminator.
                match chars.peek() {
                    Some('[') => {
                        // CSI: skip until alpha char (or `m`/`H`/etc).
                        chars.next();
                        while let Some(&p) = chars.peek() {
                            chars.next();
                            if p.is_ascii_alphabetic() || p == '~' {
                                break;
                            }
                        }
                    }
                    Some(']') => {
                        // OSC: skip until BEL (\x07) or ST (ESC \\).
                        chars.next();
                        while let Some(&p) = chars.peek() {
                            chars.next();
                            if p == '\x07' {
                                break;
                            }
                            if p == '\x1b' {
                                // ESC + \\ string-terminator: consume one more.
                                let _ = chars.next();
                                break;
                            }
                        }
                    }
                    _ => {
                        // Bare ESC: drop it.
                    }
                }
            }
            // BiDi overrides — Trojan Source defense
            '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' => {}
            // Zero-width chars
            '\u{200b}' | '\u{200c}' | '\u{200d}' | '\u{feff}' => {}
            // Other control chars except \n and \t
            c if c.is_control() && c != '\n' && c != '\t' => {}
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::sanitize;

    #[test]
    fn strips_ansi_csi() {
        let input = "hello\x1b[31mworld\x1b[0m";
        assert_eq!(sanitize(input), "helloworld");
    }

    #[test]
    fn strips_osc_8_hyperlinks() {
        let input = "\x1b]8;;http://evil/\x07click here\x1b]8;;\x07";
        assert_eq!(sanitize(input), "click here");
    }

    #[test]
    fn strips_bidi_overrides() {
        let input = "good\u{202e}drowssap\u{202c}";
        let out = sanitize(input);
        assert!(!out.contains('\u{202e}'));
        assert!(!out.contains('\u{202c}'));
        assert_eq!(out, "gooddrowssap");
    }

    #[test]
    fn strips_zero_width() {
        let input = "ab\u{200b}c\u{200d}d";
        let out = sanitize(input);
        assert!(!out.contains('\u{200b}'));
        assert!(!out.contains('\u{200d}'));
        assert_eq!(out, "abcd");
    }

    #[test]
    fn preserves_newline_and_tab() {
        let input = "line1\nline2\tcol2";
        assert_eq!(sanitize(input), "line1\nline2\tcol2");
    }

    #[test]
    fn strips_other_controls() {
        let input = "a\x07b\x08c";
        assert_eq!(sanitize(input), "abc");
    }

    #[test]
    fn strips_st_terminated_osc() {
        let input = "\x1b]0;title\x1b\\after";
        assert_eq!(sanitize(input), "after");
    }
}
