use anyhow::{anyhow, Result};
use futures::{
    stream::{FuturesUnordered, StreamExt},
    FutureExt,
};
use std::net::{IpAddr, SocketAddr};
use tokio::{
    net::TcpStream,
    time::{timeout, Duration},
};

use crate::schema::{Asset, Finding};

type ScanFuture = futures::future::BoxFuture<'static, Option<u16>>;

pub fn parse_ports(spec: &str) -> Result<Vec<u16>> {
    let mut out = Vec::new();

    for part in spec.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        if let Some((a, b)) = part.split_once('-') {
            let start: u16 = a.parse().map_err(|_| anyhow!("bad port: {a}"))?;
            let end: u16 = b.parse().map_err(|_| anyhow!("bad port: {b}"))?;
            if start == 0 || end == 0 || start > end {
                return Err(anyhow!("invalid port range: {part}"));
            }
            for p in start..=end {
                out.push(p);
            }
        } else {
            let p: u16 = part.parse().map_err(|_| anyhow!("bad port: {part}"))?;
            if p == 0 {
                return Err(anyhow!("port 0 is invalid"));
            }
            out.push(p);
        }
    }

    out.sort_unstable();
    out.dedup();
    Ok(out)
}

pub async fn resolve_target(input: &str) -> Result<Vec<String>> {
    if input.parse::<IpAddr>().is_ok() {
        return Ok(vec![input.to_string()]);
    }

    let mut ips = Vec::new();
    let addrs = tokio::net::lookup_host((input, 0)).await?;
    for a in addrs {
        ips.push(a.ip().to_string());
    }

    ips.sort();
    ips.dedup();

    if ips.is_empty() {
        return Err(anyhow!("no resolved addresses"));
    }

    Ok(ips)
}

fn spawn_probe(
    addr: SocketAddr,
    port: u16,
    timeout_dur: Duration,
) -> ScanFuture {
    async move {
        let res = timeout(timeout_dur, TcpStream::connect(addr)).await;
        if matches!(res, Ok(Ok(_))) {
            Some(port)
        } else {
            None
        }
    }
    .boxed()
}

pub async fn tcp_connect_scan(
    ip: &str,
    ports: &[u16],
    timeout_ms: u64,
) -> Result<Vec<Finding>> {
    let ip_addr: IpAddr = ip.parse()?;
    let timeout_dur = Duration::from_millis(timeout_ms);

    let max_inflight = 512usize;
    let mut findings = Vec::new();
    let mut futs: FuturesUnordered<ScanFuture> = FuturesUnordered::new();

    let mut idx = 0usize;

    while idx < ports.len() && futs.len() < max_inflight {
        let port = ports[idx];
        idx += 1;
        futs.push(spawn_probe(
            SocketAddr::new(ip_addr, port),
            port,
            timeout_dur,
        ));
    }

    while let Some(res) = futs.next().await {
        if let Some(open_port) = res {
            findings.push(Finding::open_port(
                format!("open-port-{}-{}", ip, open_port),
                Asset {
                    ip: ip.to_string(),
                    port: Some(open_port),
                    protocol: Some("tcp".to_string()),
                    service: None,
                },
            ));
        }

        if idx < ports.len() {
            let port = ports[idx];
            idx += 1;
            futs.push(spawn_probe(
                SocketAddr::new(ip_addr, port),
                port,
                timeout_dur,
            ));
        }
    }

    Ok(findings)
}
