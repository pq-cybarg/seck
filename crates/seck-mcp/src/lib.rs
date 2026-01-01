//! Minimal MCP server over stdio. Hand-rolled JSON-RPC 2.0 to avoid a
//! large SDK dependency (smaller TCB). Implements just enough of the MCP
//! 2025-06-18 wire protocol for `tools/list` and `tools/call` plus the
//! `initialize` handshake.
//!
//! Tools exposed:
//!   * `analyze_file(path: string)` — shells out to the seck CLI binary
//!     (which is itself sandboxed). Returns the JSON report.
//!   * `list_models()` — returns the bundled models manifest entries.
//!   * `verify_file_sha3(path: string, sha3_256_hex: string)` — verifies
//!     a local file's SHA3-256 against an expected hex.
//!
//! All `Content::text` payloads are passed through `seck-report::sanitize`
//! before serialization so a malicious LLM-generated report can't smuggle
//! terminal-control sequences through the MCP transport.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub mod server;
pub mod store;

pub use server::SeckMcpServer;
pub use store::ReportStore;

#[derive(Debug, Serialize, Deserialize)]
pub struct RpcRequest {
    pub jsonrpc: String,
    pub id: Option<Value>,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RpcResponse {
    pub jsonrpc: &'static str,
    pub id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl RpcResponse {
    pub fn ok(id: Option<Value>, result: Value) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn err(id: Option<Value>, code: i32, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: None,
            error: Some(RpcError {
                code,
                message: message.into(),
                data: None,
            }),
        }
    }
}

pub fn server_info() -> Value {
    json!({
        "name": "seck",
        "version": env!("CARGO_PKG_VERSION"),
    })
}

pub fn server_capabilities() -> Value {
    json!({ "tools": {} })
}

pub fn tool_list() -> Value {
    json!({
        "tools": [
            {
                "name": "analyze_file",
                "description": "Run seck analyze on a file or directory in the sandboxed pipeline. Returns the JSON report.",
                "inputSchema": {
                    "type": "object",
                    "properties": { "path": { "type": "string" } },
                    "required": ["path"]
                }
            },
            {
                "name": "list_models",
                "description": "List installed local models from the bundled manifest.",
                "inputSchema": { "type": "object", "properties": {} }
            },
            {
                "name": "verify_file_sha3",
                "description": "Verify a local file's SHA3-256 matches the expected hex.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": { "type": "string" },
                        "sha3_256_hex": { "type": "string" }
                    },
                    "required": ["path", "sha3_256_hex"]
                }
            }
        ]
    })
}
