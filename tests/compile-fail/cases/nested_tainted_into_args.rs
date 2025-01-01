// Vec<Tainted<...>> still cannot pass through Command::args.
use std::process::Command;
use seck_taint::Tainted;

fn main() {
    let t: Tainted<Vec<u8>> = Tainted::__new_internal(b"x".to_vec());
    let v = vec![t];
    Command::new("/bin/true").args(v);
}
