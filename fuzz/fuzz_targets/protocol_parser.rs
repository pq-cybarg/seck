#![no_main]
use libfuzzer_sys::fuzz_target;
use seck_reader::protocol::read_frames;

fuzz_target!(|data: &[u8]| {
    let mut cursor = std::io::Cursor::new(data);
    let _ = read_frames(&mut cursor);
});
