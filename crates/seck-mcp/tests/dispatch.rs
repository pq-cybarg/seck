//! In-process tests for the JSON-RPC dispatcher (no subprocess required).

use seck_mcp::SeckMcpServer;
use serde_json::Value;
use std::path::PathBuf;

fn server() -> SeckMcpServer {
    SeckMcpServer::new(PathBuf::from("/usr/bin/true"))
}

#[test]
fn initialize_returns_server_info() {
    let s = server();
    let req = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
    let resp = s.dispatch(req).expect("response");
    let body = serde_json::to_value(&resp).unwrap();
    assert_eq!(body["result"]["serverInfo"]["name"], "seck");
    assert!(body["result"]["protocolVersion"].is_string());
}

#[test]
fn tools_list_returns_three_tools() {
    let s = server();
    let req = r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#;
    let resp = s.dispatch(req).expect("response");
    let body = serde_json::to_value(&resp).unwrap();
    let tools = body["result"]["tools"].as_array().expect("tools array");
    let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
    assert!(names.contains(&"analyze_file"));
    assert!(names.contains(&"list_models"));
    assert!(names.contains(&"verify_file_sha3"));
}

#[test]
fn list_models_returns_manifest_entries() {
    let s = server();
    let req = r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_models","arguments":{}}}"#;
    let resp = s.dispatch(req).expect("response");
    let body = serde_json::to_value(&resp).unwrap();
    let txt = body["result"]["content"][0]["text"].as_str().expect("text");
    let entries: Value = serde_json::from_str(txt).unwrap();
    assert!(entries.is_array());
    assert!(entries.as_array().unwrap().len() >= 5);
}

#[test]
fn verify_file_sha3_correct_hash_ok() {
    let s = server();
    let f = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(f.path(), b"hello").unwrap();
    let real = hex::encode(seck_crypto::hash::sha3_256(b"hello"));
    // Build the request via serde_json::json! so Windows paths
    // (which contain backslashes) are JSON-escaped correctly. A
    // hand-rolled format! string leaves `\` un-escaped and produces
    // invalid JSON that the server rejects before reaching the tool.
    let req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {
            "name": "verify_file_sha3",
            "arguments": {
                "path": f.path().to_string_lossy(),
                "sha3_256_hex": real,
            }
        }
    })
    .to_string();
    let resp = s.dispatch(&req).expect("response");
    let body = serde_json::to_value(&resp).unwrap();
    let txt = body["result"]["content"][0]["text"].as_str().unwrap();
    assert!(txt.starts_with("OK"));
}

#[test]
fn unknown_tool_returns_error() {
    let s = server();
    let req = r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"no_such_tool","arguments":{}}}"#;
    let resp = s.dispatch(req).expect("response");
    let body = serde_json::to_value(&resp).unwrap();
    assert!(body["error"].is_object());
    assert_eq!(body["error"]["code"], -32602);
}

#[test]
fn parse_error_returns_minus_32700() {
    let s = server();
    let resp = s.dispatch("not json at all").expect("response");
    let body = serde_json::to_value(&resp).unwrap();
    assert_eq!(body["error"]["code"], -32700);
}
