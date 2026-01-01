//! `seck pair` — bring up a WireGuard endpoint and display a QR code
//! the mobile client scans. After the user confirms the fingerprint,
//! the endpoint is ready for the mobile to use (the actual MCP-over-WG
//! transport spawns from here in a follow-up).

use anyhow::Context;

#[derive(clap::Args)]
pub struct PairArgs {
    /// LAN-bound listening address. Default is loopback; pass an
    /// RFC1918 / link-local / loopback IP to let a phone on the same
    /// LAN connect. Public IPs are refused on purpose.
    #[arg(long, default_value = "127.0.0.1:51820")]
    pub bind: String,
}

pub fn run(args: PairArgs) -> anyhow::Result<()> {
    let bind: std::net::SocketAddr = args.bind.parse().context("--bind not parseable")?;
    let ep = seck_pair::WgEndpoint::new_random(bind);
    let bundle = seck_pair::pairing::build_bundle(&ep)
        .context("building pairing bundle (set SECK_PAIR_LAN_IP if your LAN IP isn't loopback)")?;
    let json = serde_json::to_string(&bundle)?;
    println!("{}", seck_pair::qr::render(&json));
    println!();
    println!(
        "Fingerprint: {}",
        seck_pair::pairing::format_fingerprint(&bundle.fingerprint_sha3_256)
    );
    println!("Confirm this fingerprint matches on your mobile device.");
    println!("Endpoint: {}", bundle.host_endpoint);
    println!();
    println!("(The MCP-over-WG service will be launched in a follow-up; this CLI ships pairing.)");
    Ok(())
}
