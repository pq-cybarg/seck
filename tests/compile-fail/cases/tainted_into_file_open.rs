use std::fs::File;
use seck_taint::Tainted;

fn main() {
    let t: Tainted<Vec<u8>> = Tainted::__new_internal(b"/etc/passwd".to_vec());
    let _ = File::open(t);
}
