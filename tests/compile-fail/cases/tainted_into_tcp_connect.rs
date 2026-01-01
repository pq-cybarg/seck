use std::net::TcpStream;
use seck_taint::Tainted;

fn main() {
    let t: Tainted<Vec<u8>> = Tainted::__new_internal(b"127.0.0.1:80".to_vec());
    let _ = TcpStream::connect(t);
}
