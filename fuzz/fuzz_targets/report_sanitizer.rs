#![no_main]
use libfuzzer_sys::fuzz_target;
use seck_report::sanitize::sanitize;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let out = sanitize(s);
        // Postcondition: output contains no forbidden control characters,
        // no BiDi overrides, no zero-width characters.
        for c in out.chars() {
            assert!(
                c == '\n' || c == '\t' || !c.is_control(),
                "sanitizer leaked control char U+{:04X}",
                c as u32
            );
            assert!(
                !matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'),
                "sanitizer leaked BiDi U+{:04X}",
                c as u32
            );
            assert!(
                !matches!(c, '\u{200b}' | '\u{200c}' | '\u{200d}' | '\u{feff}'),
                "sanitizer leaked ZWJ/BOM U+{:04X}",
                c as u32
            );
        }
    }
});
