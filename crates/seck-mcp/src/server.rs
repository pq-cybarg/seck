//! JSON-RPC dispatcher. Reads line-delimited JSON from a reader (stdin
//! over a stdio transport), writes responses line-delimited to a writer.

use crate::{RpcRequest, RpcResponse, ReportStore, server_capabilities, server_info, tool_list};
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::sync::Arc;

const BUNDLED_MANIFEST: &str =
    include_str!("../../../platform/manifests/models.manifest.toml");

#[derive(Clone)]
pub struct SeckMcpServer {
    pub store: Arc<ReportStore>,
    pub seck_bin: PathBuf,
}

impl SeckMcpServer {
    pub fn new(seck_bin: PathBuf) -> Self {
        Self {
            store: Arc::new(ReportStore::new()),
            seck_bin,
        }
    }

    /// Run the server on the provided reader/writer pair. Blocks until
    /// the reader EOFs.
    pub fn serve<R: Read, W: Write>(&self, r: R, mut w: W) -> std::io::Result<()> {
        let r = BufReader::new(r);
        for line in r.lines() {
            let line = match line {
                Ok(l) if !l.trim().is_empty() => l,
                Ok(_) => continue,
                Err(e) => return Err(e),
            };
            let resp = self.dispatch(&line);
            if let Some(resp) = resp {
                let s = serde_json::to_string(&resp).unwrap_or_else(|_| "{}".into());
                writeln!(w, "{s}")?;
                w.flush()?;
            }
        }
        Ok(())
    }

    pub fn dispatch(&self, line: &str) -> Option<RpcResponse> {
        let req: RpcRequest = match serde_json::from_str(line) {
            Ok(r) => r,
            Err(e) => return Some(RpcResponse::err(None, -32700, format!("parse: {e}"))),
        };
        // Notifications (no id) get no response.
        let is_notification = req.id.is_none();
        let resp = self.handle(&req);
        if is_notification && resp.error.is_none() {
            return None;
        }
        Some(resp)
    }

    fn handle(&self, req: &RpcRequest) -> RpcResponse {
        match req.method.as_str() {
            "initialize" => RpcResponse::ok(
                req.id.clone(),
                json!({
                    "protocolVersion": "2025-06-18",
                    "capabilities": server_capabilities(),
                    "serverInfo": server_info(),
                    "instructions": "seck — sandboxed-LLM file/project analyzer",
                }),
            ),
            "notifications/initialized" | "initialized" => {
                // Notification — no response.
                RpcResponse::ok(req.id.clone(), json!(null))
            }
            "tools/list" => RpcResponse::ok(req.id.clone(), tool_list()),
            "tools/call" => self.handle_tool_call(req),
            other => RpcResponse::err(
                req.id.clone(),
                -32601,
                format!("method not found: {other}"),
            ),
        }
    }

    fn handle_tool_call(&self, req: &RpcRequest) -> RpcResponse {
        let name = req.params.get("name").and_then(|v| v.as_str()).unwrap_or("");
        let args = req.params.get("arguments").cloned().unwrap_or(json!({}));
        match name {
            "analyze_file" => match self.tool_analyze_file(&args) {
                Ok(v) => RpcResponse::ok(req.id.clone(), v),
                Err(e) => RpcResponse::err(req.id.clone(), -32000, e.to_string()),
            },
            "list_models" => match self.tool_list_models() {
                Ok(v) => RpcResponse::ok(req.id.clone(), v),
                Err(e) => RpcResponse::err(req.id.clone(), -32000, e.to_string()),
            },
            "verify_file_sha3" => match self.tool_verify_file_sha3(&args) {
                Ok(v) => RpcResponse::ok(req.id.clone(), v),
                Err(e) => RpcResponse::err(req.id.clone(), -32000, e.to_string()),
            },
            other => RpcResponse::err(req.id.clone(), -32602, format!("unknown tool: {other}")),
        }
    }

    fn tool_analyze_file(&self, args: &Value) -> anyhow::Result<Value> {
        let path = args
            .get("path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("missing 'path'"))?;
        // Spawn seck CLI. The CLI in turn forks the sandboxed reader.
        let out = std::process::Command::new(&self.seck_bin)
            .args(["analyze", path, "--output", "json"])
            .output()?;
        if !out.status.success() {
            anyhow::bail!(
                "seck analyze failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        let report: Value = serde_json::from_slice(&out.stdout)?;
        let report_id = self.store.put(report.clone());
        // Sanitize the summary field before returning it through MCP.
        let summary = report["findings"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|f| f["summary"].as_str())
                    .map(seck_report::sanitize::sanitize)
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_default();
        Ok(json!({
            "content": [
                { "type": "text", "text": format!("report_id: {report_id}\n{summary}") }
            ]
        }))
    }

    fn tool_list_models(&self) -> anyhow::Result<Value> {
        let m = seck_models::manifest::parse(BUNDLED_MANIFEST)?;
        let entries: Vec<Value> = m
            .entries
            .iter()
            .map(|e| {
                json!({
                    "name": e.name,
                    "params_billion": e.params_billion,
                    "recommended_min_ram_gb": e.recommended_min_ram_gb,
                    "license": e.license,
                })
            })
            .collect();
        Ok(json!({
            "content": [
                { "type": "text", "text": serde_json::to_string_pretty(&entries)? }
            ]
        }))
    }

    fn tool_verify_file_sha3(&self, args: &Value) -> anyhow::Result<Value> {
        let path = args
            .get("path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("missing 'path'"))?;
        let want = args
            .get("sha3_256_hex")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("missing 'sha3_256_hex'"))?
            .to_lowercase();
        let bytes = std::fs::read(path)?;
        let got = hex::encode(seck_crypto::hash::sha3_256(&bytes));
        let ok = got == want;
        Ok(json!({
            "content": [{
                "type": "text",
                "text": if ok { format!("OK — {path}") }
                        else { format!("MISMATCH: expected {want}, got {got}") }
            }],
            "isError": !ok
        }))
    }
}
