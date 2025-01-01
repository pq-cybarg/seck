use std::ffi::OsString;
use seck_taint::Tainted;

fn main() {
    let t: Tainted<Vec<u8>> = Tainted::__new_internal(b"hi".to_vec());
    let _o: OsString = t.into();
}
