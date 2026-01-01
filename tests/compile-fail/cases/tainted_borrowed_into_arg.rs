use std::process::Command;
use seck_taint::Tainted;

fn main() {
    let t: Tainted<Vec<u8>> = Tainted::__new_internal(b"hi".to_vec());
    Command::new("/bin/true").arg(&t);
}
