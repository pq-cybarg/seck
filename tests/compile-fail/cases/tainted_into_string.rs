use seck_taint::Tainted;

fn main() {
    let t: Tainted<Vec<u8>> = Tainted::__new_internal(b"hi".to_vec());
    let _s: String = t.into();
}
