use seck_taint::Tainted;

fn http_get(_url: &str) {}

fn main() {
    let t: Tainted<Vec<u8>> = Tainted::__new_internal(b"example.com".to_vec());
    // No AsRef<str> for Tainted<Vec<u8>>.
    http_get(t.as_ref());
}
