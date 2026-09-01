![BitProbe](bitprobe.jpg)

# BitProbe

---

**BitProbe** is a modular security recon and vulnerability assessment framework designed for continuous web, network, and TLS analysis.

This repository contains the **public demonstration** of BitProbe. The full scanning engine and remainder of the project remains private.

---

## Features

### Public Current State (This Repository)

- Passive technology fingerprinting (server, framework, CDN, analytics, WAF)
- Network port enumeration and basic service identification
- TLS configuration and certificate inspection
- Security header analysis
- Sensitive file and misconfiguration detection
- CVE correlation using a local vulnerability database
- Safe GET-based checks for reflected XSS, SQL errors, path traversal, open redirects, command injection, template injection, and local file inclusion
- Explicit `safe-active` profile with bounded adaptive request budgets
- Grouped, severity-ordered findings with affected endpoint lists
- Automated attack-chain correlation
- Client-ready JSON, Markdown, HTML, and PDF output
- Transparent risk scoring per grouped finding

---

## Example Usage

```bash
python3 bitprobe.py \
  https://example.com \
  --include fingerprinting,security_headers,network_scanner,tls_analysis
```

---

## Security Notice

Active checks use bounded, read-only GET requests and do not submit POST forms or follow external redirects.
Run scans only against systems you own or have explicit permission to test.

## License

MIT License — Public interface only.

Built as an independent security engineering project and portfolio project.
