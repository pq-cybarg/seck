use std::fs;
use seck_taint::Tainted;

fn main() {
    let t: Tainted<Vec<u8>> = Tainted::__new_internal(b"/tmp/x".to_vec());
    let _ = fs::remove_file(t);
}
