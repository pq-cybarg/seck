use std::env;
use seck_taint::Tainted;

fn main() {
    let t: Tainted<Vec<u8>> = Tainted::__new_internal(b"value".to_vec());
    // SAFETY: tests/compile-fail/* is purposely written to NOT compile.
    unsafe { env::set_var("KEY", t); }
}
