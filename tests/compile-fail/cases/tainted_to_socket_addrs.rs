use std::net::ToSocketAddrs;
use seck_taint::Tainted;

fn main() {
    let t: Tainted<Vec<u8>> = Tainted::__new_internal(b"example.com:80".to_vec());
    // No ToSocketAddrs impl for Tainted<Vec<u8>>.
    let _ = t.to_socket_addrs();
}
