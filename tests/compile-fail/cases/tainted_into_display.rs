use seck_taint::Tainted;

fn main() {
    let t: Tainted<Vec<u8>> = Tainted::__new_internal(vec![1, 2, 3]);
    let _ = format!("{}", t);
}
