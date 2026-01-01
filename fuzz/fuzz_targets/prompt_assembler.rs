#![no_main]
use libfuzzer_sys::fuzz_target;
use seck_reader::prompt::{assemble, AssembleConfig};
use seck_reader::protocol::Frame;

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let split = (data[0] as usize) % data.len();
    // Split into a name-bytes chunk and a content chunk.
    let name = String::from_utf8_lossy(&data[..split]).into_owned();
    let bytes = data[split..].to_vec();
    let frames = vec![Frame { relative_path: name, bytes }];
    let _ = assemble(&AssembleConfig { nonce: [0u8; 32] }, &frames);
});
