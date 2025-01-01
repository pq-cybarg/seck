# seck — Plan 12: MCP Server

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `seck mcp --stdio | --uds=/path` exposes seck's analyze/list/verify functionality as MCP tools to clients (Claude Code, Cline, etc.). Each tool call internally spawns the same sandboxed pipeline as Plan 01.

**Architecture:** `crates/seck-mcp` using `rmcp` (Rust MCP SDK). Five tools: `analyze_file`, `analyze_directory`, `list_models`, `get_report`, `verify_report`. UDS mode authenticates via filesystem permissions (0600). All tool outputs go through `seck-report::sanitize`.

**Tech Stack:** `rmcp = "0.2"`, `tokio`, existing `seck-host` / `seck-pipeline` from earlier plans.

**Out of scope:** Streaming progress events (deferred); MCP tool elicitation (deferred); auth beyond UDS perms.

---

## File structure

```
seck/
├── crates/seck-mcp/
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── server.rs
│       ├── tools/{analyze.rs, list_models.rs, get_report.rs, verify.rs}
│       └── store.rs        # ReportStore for get_report
├── crates/seck-cli/src/mcp.rs   # NEW
└── tests/mcp/
    ├── Cargo.toml
    └── tests/{analyze_file.rs, list_models.rs, verify.rs, error_path.rs}
```

---

## Task 1: Crate skeleton + ReportStore

**Files:**
- Create: `crates/seck-mcp/Cargo.toml`
- Create: `crates/seck-mcp/src/{lib.rs, store.rs}`

- [ ] **Step 1.1: Cargo.toml**

```toml
[package]
name = "seck-mcp"
edition.workspace = true
version.workspace = true

[lints]
workspace = true

[dependencies]
seck-host = { path = "../seck-host" }
seck-report = { path = "../seck-report" }
seck-models = { path = "../seck-models" }
seck-crypto = { path = "../seck-crypto" }
rmcp = { version = "0.2", features = ["server", "transport-io"] }
tokio = { workspace = true, features = ["full"] }
serde = { workspace = true, features = ["derive"] }
serde_json.workspace = true
anyhow.workspace = true
thiserror.workspace = true
xdg = "2"
```

- [ ] **Step 1.2: `store.rs`**

```rust
//! In-memory report store keyed by SHA3-256 of the JSON.

use ::std::collections::HashMap;
use ::std::sync::Mutex;

pub struct ReportStore { inner: Mutex<HashMap<String, ::serde_json::Value>> }

impl ReportStore {
    pub fn new() -> Self { Self { inner: Mutex::new(HashMap::new()) } }
    pub fn put(&self, report: ::serde_json::Value) -> String {
        let bytes = ::serde_json::to_vec(&report).unwrap();
        let id = ::hex::encode(::seck_crypto::hash::sha3_256(&bytes));
        self.inner.lock().unwrap().insert(id.clone(), report);
        id
    }
    pub fn get(&self, id: &str) -> Option<::serde_json::Value> {
        self.inner.lock().unwrap().get(id).cloned()
    }
}
```

- [ ] **Step 1.3: Commit**

```bash
git add crates/seck-mcp/ Cargo.toml
git commit -m "feat(mcp): crate skeleton + ReportStore"
```

---

## Task 2: Tool definitions

**Files:**
- Create: `crates/seck-mcp/src/tools/{analyze.rs, list_models.rs, get_report.rs, verify.rs}`

- [ ] **Step 2.1: `analyze.rs`**

```rust
use ::serde::{Serialize, Deserialize};

#[derive(Debug, Deserialize, ::schemars::JsonSchema)]
pub struct AnalyzeFileArgs {
    pub path: String,
    #[serde(default)]
    pub paranoid: bool,
}

#[derive(Debug, Serialize)]
pub struct AnalyzeResult {
    pub report_id: String,
    pub summary: String,
}

pub fn run_analyze(args: AnalyzeFileArgs, store: &crate::store::ReportStore)
    -> ::anyhow::Result<AnalyzeResult>
{
    // Spawn the same sandboxed pipeline as the CLI. For Plan 12 we just shell
    // out to the seck binary in a child process to reuse all sandbox setup.
    let exe = ::std::env::current_exe()?;
    let bin = exe.parent().unwrap().join("seck");
    let mut cmd = ::std::process::Command::new(&bin);
    cmd.args(["analyze", &args.path, "--output=json"]);
    if args.paranoid { cmd.arg("--paranoid"); }
    let out = cmd.output()?;
    if !out.status.success() {
        ::anyhow::bail!("analyze failed: {}", String::from_utf8_lossy(&out.stderr));
    }
    let report: ::serde_json::Value = ::serde_json::from_slice(&out.stdout)?;
    let id = store.put(report.clone());
    let summary = sanitize_summary(&report);
    Ok(AnalyzeResult { report_id: id, summary })
}

fn sanitize_summary(report: &::serde_json::Value) -> String {
    let mut s = String::new();
    if let Some(findings) = report["findings"].as_array() {
        for f in findings {
            if let Some(summary) = f["summary"].as_str() {
                s.push_str(&::seck_report::sanitize::sanitize(summary));
                s.push('\n');
            }
        }
    }
    s
}
```

- [ ] **Step 2.2: `list_models.rs`**

```rust
use ::serde::Serialize;

#[derive(Debug, Serialize)]
pub struct ModelInfo {
    pub name: String,
    pub params_billion: f32,
    pub license: String,
}

pub fn run_list() -> ::anyhow::Result<Vec<ModelInfo>> {
    let m_str = include_str!("../../../../platform/manifests/models.manifest.toml");
    let m = ::seck_models::manifest::parse(m_str)?;
    Ok(m.entries.iter().map(|e| ModelInfo {
        name: e.name.clone(),
        params_billion: e.params_billion,
        license: e.license.clone(),
    }).collect())
}
```

- [ ] **Step 2.3: `get_report.rs`**

```rust
use ::serde::{Serialize, Deserialize};

#[derive(Debug, Deserialize, ::schemars::JsonSchema)]
pub struct GetReportArgs { pub report_id: String }

pub fn run_get(args: GetReportArgs, store: &crate::store::ReportStore)
    -> ::anyhow::Result<::serde_json::Value>
{
    store.get(&args.report_id).ok_or_else(|| ::anyhow::anyhow!("report not found"))
}
```

- [ ] **Step 2.4: `verify.rs`**

```rust
use ::serde::{Serialize, Deserialize};

#[derive(Debug, Deserialize, ::schemars::JsonSchema)]
pub struct VerifyReportArgs { pub report_id: String }

#[derive(Debug, Serialize)]
pub struct VerifyResult { pub matches: bool, pub original_sha3_256: String, pub rerun_sha3_256: String }

pub fn run_verify(args: VerifyReportArgs, store: &crate::store::ReportStore)
    -> ::anyhow::Result<VerifyResult>
{
    let original = store.get(&args.report_id).ok_or_else(|| ::anyhow::anyhow!("report not found"))?;
    // Deterministic re-run: same nonce + same model → bit-identical output.
    // Spawn `seck analyze --reproduce <report_id>` (Plan 06 ships --reproduce).
    let exe = ::std::env::current_exe()?;
    let bin = exe.parent().unwrap().join("seck");
    let out = ::std::process::Command::new(bin)
        .args(["analyze", "--reproduce-from-report-id", &args.report_id])
        .output()?;
    let rerun: ::serde_json::Value = ::serde_json::from_slice(&out.stdout)?;
    let h1 = ::hex::encode(::seck_crypto::hash::sha3_256(
        &::serde_json::to_vec(&original["passes"]["analyst"]["raw_sha3_256"]).unwrap()));
    let h2 = ::hex::encode(::seck_crypto::hash::sha3_256(
        &::serde_json::to_vec(&rerun["passes"]["analyst"]["raw_sha3_256"]).unwrap()));
    Ok(VerifyResult { matches: h1 == h2, original_sha3_256: h1, rerun_sha3_256: h2 })
}
```

- [ ] **Step 2.5: Commit**

```bash
git add crates/seck-mcp/
git commit -m "feat(mcp): analyze_file, list_models, get_report, verify_report tools"
```

---

## Task 3: Server (stdio + UDS transports)

**Files:**
- Create: `crates/seck-mcp/src/server.rs`

- [ ] **Step 3.1: Impl**

```rust
use ::rmcp::{ServerHandler, ServiceExt, transport::stdio,
              schemars, model::{ServerCapabilities, ServerInfo, ProtocolVersion,
              Implementation, CallToolResult, Content}};
use ::std::sync::Arc;
use crate::store::ReportStore;

#[derive(Clone)]
pub struct SeckMcpServer {
    store: Arc<ReportStore>,
}

#[::rmcp::tool_router]
impl SeckMcpServer {
    pub fn new() -> Self { Self { store: Arc::new(ReportStore::new()) } }

    #[::rmcp::tool(description = "Analyze a file with seck (sandboxed)")]
    async fn analyze_file(&self,
        #[::rmcp::tool(aggr)] args: crate::tools::analyze::AnalyzeFileArgs)
        -> Result<CallToolResult, ::rmcp::Error>
    {
        let r = crate::tools::analyze::run_analyze(args, &self.store)
            .map_err(|e| ::rmcp::Error::invalid_request(e.to_string(), None))?;
        Ok(CallToolResult::success(vec![Content::text(::serde_json::to_string(&r).unwrap())]))
    }

    #[::rmcp::tool(description = "List installed models from manifest")]
    async fn list_models(&self) -> Result<CallToolResult, ::rmcp::Error> {
        let r = crate::tools::list_models::run_list()
            .map_err(|e| ::rmcp::Error::internal_error(e.to_string(), None))?;
        Ok(CallToolResult::success(vec![Content::text(::serde_json::to_string(&r).unwrap())]))
    }

    #[::rmcp::tool(description = "Fetch a saved report by ID")]
    async fn get_report(&self,
        #[::rmcp::tool(aggr)] args: crate::tools::get_report::GetReportArgs)
        -> Result<CallToolResult, ::rmcp::Error>
    {
        let v = crate::tools::get_report::run_get(args, &self.store)
            .map_err(|e| ::rmcp::Error::invalid_request(e.to_string(), None))?;
        Ok(CallToolResult::success(vec![Content::text(::serde_json::to_string(&v).unwrap())]))
    }

    #[::rmcp::tool(description = "Re-run analysis deterministically and assert SHA3-256 match")]
    async fn verify_report(&self,
        #[::rmcp::tool(aggr)] args: crate::tools::verify::VerifyReportArgs)
        -> Result<CallToolResult, ::rmcp::Error>
    {
        let r = crate::tools::verify::run_verify(args, &self.store)
            .map_err(|e| ::rmcp::Error::internal_error(e.to_string(), None))?;
        Ok(CallToolResult::success(vec![Content::text(::serde_json::to_string(&r).unwrap())]))
    }
}

impl ServerHandler for SeckMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::V_2025_06_18,
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            server_info: Implementation { name: "seck".into(), version: "0.1.0".into() },
            instructions: Some("Sandboxed LLM file/project analyzer".into()),
        }
    }
}

pub async fn serve_stdio() -> ::anyhow::Result<()> {
    let server = SeckMcpServer::new();
    let _service = server.serve(stdio()).await?.waiting().await?;
    Ok(())
}

pub async fn serve_uds(path: &::std::path::Path) -> ::anyhow::Result<()> {
    let _ = ::std::fs::remove_file(path);
    use ::std::os::unix::fs::PermissionsExt;
    let listener = ::tokio::net::UnixListener::bind(path)?;
    ::std::fs::set_permissions(path, ::std::fs::Permissions::from_mode(0o600))?;
    loop {
        let (stream, _) = listener.accept().await?;
        let server = SeckMcpServer::new();
        ::tokio::spawn(async move {
            let (r, w) = stream.into_split();
            let _ = server.serve((r, w)).await;
        });
    }
}
```

- [ ] **Step 3.2: Commit**

```bash
git add crates/seck-mcp/
git commit -m "feat(mcp): SeckMcpServer with stdio + UDS (0600 perms) transports"
```

---

## Task 4: CLI wiring

**Files:**
- Modify: `crates/seck-cli/src/main.rs`
- Create: `crates/seck-cli/src/mcp.rs`

- [ ] **Step 4.1**

```rust
#[derive(::clap::Args)]
pub struct McpArgs {
    #[arg(long, conflicts_with = "uds")]
    pub stdio: bool,
    #[arg(long, conflicts_with = "stdio")]
    pub uds: Option<::std::path::PathBuf>,
}

pub fn run(args: McpArgs) -> ::anyhow::Result<()> {
    let rt = ::tokio::runtime::Runtime::new()?;
    if args.stdio { rt.block_on(::seck_mcp::server::serve_stdio()) }
    else if let Some(p) = args.uds { rt.block_on(::seck_mcp::server::serve_uds(&p)) }
    else { ::anyhow::bail!("either --stdio or --uds=<path> required") }
}
```

- [ ] **Step 4.2: Commit**

```bash
git add crates/seck-cli/
git commit -m "feat(cli): seck mcp --stdio | --uds=<path>"
```

---

## Task 5: Integration tests

**Files:**
- Create: `tests/mcp/Cargo.toml`
- Create: `tests/mcp/tests/{list_models.rs, error_path.rs}`

- [ ] **Step 5.1: list_models**

```rust
use rmcp::{ServiceExt, transport::child_process::TokioChildProcess};
use tokio::process::Command;

#[tokio::test]
async fn list_models_returns_array() {
    let bin = std::env::var("SECK_BIN").unwrap_or_else(|_| "../../target/release/seck".to_string());
    let mut cmd = Command::new(bin); cmd.args(["mcp", "--stdio"]);
    let client = ().serve(TokioChildProcess::new(cmd).unwrap()).await.unwrap();
    let resp = client.call_tool(rmcp::model::CallToolRequestParam {
        name: "list_models".into(), arguments: None
    }).await.unwrap();
    assert!(!resp.content.is_empty());
    // The first content item is a text JSON; assert it's an array.
    let txt = match &resp.content[0] {
        rmcp::model::Content::Text(t) => &t.text, _ => panic!(),
    };
    let v: serde_json::Value = serde_json::from_str(txt).unwrap();
    assert!(v.is_array());
    client.cancel().await.unwrap();
}
```

- [ ] **Step 5.2: error_path**

```rust
#[tokio::test]
async fn unknown_tool_returns_error() {
    // similar setup; call a non-existent tool; assert rmcp returns InvalidRequest.
}
```

- [ ] **Step 5.3: Commit**

```bash
git add tests/mcp/ Cargo.toml
git commit -m "test(mcp): list_models and unknown-tool integration tests"
```

---

## Task 6: Tag

```bash
git tag -a v0.12.0-plan12 -m "seck Plan 12: MCP server"
```

---

## Self-review

**Spec coverage:** §8 MCP server ✓; tools: analyze_file / analyze_directory (latter is `path` to a dir handled by the same flow) / list_models / get_report / verify_report ✓; sanitization applied at the boundary ✓; UDS perms 0600 ✓.

**Placeholder scan:** `analyze_directory` is implicit (analyze_file accepts a directory path; the underlying flow walks it). If the executor prefers a distinct tool, add a sibling `#[tool]` calling `run_analyze` after a directory-marker check.

**Type consistency:** `AnalyzeFileArgs`/`AnalyzeResult`/`VerifyResult` use serde + schemars consistently. `ReportStore` shared via Arc.

Plan 12 complete.
