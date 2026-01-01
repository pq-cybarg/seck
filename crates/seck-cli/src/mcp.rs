//! `seck mcp --stdio` — run the Model Context Protocol server over stdio.

use clap::Args;

#[derive(Args)]
pub struct McpArgs {
    /// Talk JSON-RPC over stdin / stdout (the standard MCP transport).
    #[arg(long)]
    pub stdio: bool,
}

pub fn run(args: McpArgs) -> anyhow::Result<()> {
    if !args.stdio {
        anyhow::bail!("only --stdio transport is supported in Plan 12 (UDS to follow)");
    }
    // Locate seck binary next to this one (we ARE this binary, but the
    // server spawns it as a subprocess for tool calls so it can run the
    // sandboxed pipeline freshly each time).
    let seck_bin = std::env::current_exe()?;
    let server = seck_mcp::SeckMcpServer::new(seck_bin);
    server.serve(std::io::stdin().lock(), std::io::stdout().lock())?;
    Ok(())
}
