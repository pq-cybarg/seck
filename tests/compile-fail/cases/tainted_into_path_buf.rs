use std::path::PathBuf;
use seck_taint::Tainted;

fn main() {
    let t: Tainted<Vec<u8>> = Tainted::__new_internal(b"/foo".to_vec());
    let _p: PathBuf = t.into();
}
