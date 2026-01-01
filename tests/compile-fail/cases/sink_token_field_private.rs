// SinkToken's _private field is, well, private. Downstream cannot fabricate one.
use seck_taint::SinkToken;

fn main() {
    let _bad = SinkToken { _private: () };
}
