//! trybuild harness: every file in `cases/*.rs` must FAIL to compile.
//! A passing case here is a regression in the typestate invariant.

#[test]
fn typestate_invariants() {
    let t = trybuild::TestCases::new();
    t.compile_fail("cases/*.rs");
}
