use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::time::Instant;

mod scan;
mod schema;

use scan::{parse_ports, resolve_target, tcp_connect_scan};
use schema::{ScanResult, Target};

#[derive(Parser, Debug)]
#[command(name = "bitprobe-engine", version, about = "BitProbe scanning engine (Rust)")]
struct Cli {
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run a scan against a target
    Scan {
        /// Target hostname/IP (CIDR not supported yet in this minimal engine)
        #[arg(long)]
        input: String,

        /// Ports: "1-1024" or "80,443,8080"
        #[arg(long, default_value = "1-1024")]
        ports: String,

        /// Per-connection timeout in ms
        #[arg(long, default_value_t = 800)]
        timeout_ms: u64,

        /// Emit JSON to stdout
        #[arg(long, default_value_t = true)]
        json: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.cmd {
        Commands::Scan {
            input,
            ports,
            timeout_ms,
            json,
        } => {
            let started = Instant::now();

            let port_list = parse_ports(&ports).context("invalid --ports")?;
            let resolved = resolve_target(&input).await.context("failed to resolve target")?;

            let mut findings = Vec::new();
            for ip in &resolved {
                let mut f = tcp_connect_scan(ip, &port_list, timeout_ms).await?;
                findings.append(&mut f);
            }

            let result = ScanResult::new(
                Target {
                    input,
                    resolved,
                },
                started.elapsed().as_millis() as u64,
                findings,
            );

            if json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            }

            Ok(())
        }
    }
}
