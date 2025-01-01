use seck_taint::Tainted;

fn main() {
    let t: Tainted<Vec<u8>> = Tainted::__new_internal(b"x".to_vec());
    // No Debug impl ⇒ no coercion to Box<dyn Debug>.
    let b: Box<dyn std::fmt::Debug> = Box::new(t);
    let _ = b;
}
