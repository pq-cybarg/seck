use std::borrow::Cow;
use seck_taint::Tainted;

fn main() {
    let t: Tainted<Vec<u8>> = Tainted::__new_internal(b"hi".to_vec());
    let _c: Cow<'_, str> = t.into();
}
