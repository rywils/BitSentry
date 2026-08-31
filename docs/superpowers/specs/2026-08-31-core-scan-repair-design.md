# Core Scan Repair Design

## Problem

BitProbe selects a committed macOS arm64 Rust executable on Linux because selection checks only whether the file exists.
The resulting `Exec format error` disables network findings.

Report generation enables PDF by default even when `reportlab` is unavailable.
A PDF failure marks the scan failed after JSON and Markdown reports were written successfully.

Technology fingerprinting detects PHP and WordPress but drops their versions.
CVE correlation requires those versions, so it returns no findings for software with matching advisories.

Long-running checks report only a generic pending count.
The reported 30-second delay came from 28 rate-limited sensitive-path requests, not the failed network task.

## Scope

This change repairs executable selection, report failure isolation, version propagation, and progress output.
It does not add SQL injection, XSS, or other active web probes.

## Network Engine Selection

Rust remains the preferred network engine when its executable can run on the host.
Selection will execute `bitprobe-engine --version` with captured output and a short timeout.
A missing, incompatible, non-executable, or timed-out binary will be rejected.
The existing Go and Python implementations remain the fallback order.

A platform-specific build artifact must not control runtime behavior solely because it exists in the repository.

## Report Generation

Reporter will attempt every requested output format.
A failed format will produce one concise warning and will not discard successful artifacts.
The scan succeeds when at least one requested artifact is written.
The scan fails with an aggregated error when every requested format fails.
A PDF-only request without `reportlab` therefore remains an error.

## Technology Versions

Fingerprint checks will continue through version-bearing signatures after a generic technology match.
PHP, WordPress, Apache, Nginx, and IIS signatures will capture version groups when the response exposes them.
The existing technology result schema remains unchanged.
CVE correlation will receive canonical technology names with extracted versions.

## Progress Output

Each submitted check will retain its plugin name and start time.
When no check finishes during a progress interval, output will identify the pending plugin names and elapsed time.
Rate limiting remains unchanged to avoid increasing traffic against scanned targets.

## Tests

Regression tests will cover:

- rejecting an incompatible Rust executable and selecting a fallback engine
- preserving JSON when optional PDF generation fails
- failing a PDF-only request when PDF generation is unavailable
- extracting PHP and WordPress versions from a response
- passing the extracted PHP version into CVE lookup
- identifying pending checks in progress output

A local HTTP fixture will reproduce a versioned WordPress and PHP target without contacting a public system.
The final verification will run focused tests, the full Python suite, lint checks, a Rust release build in a temporary target directory, and the local end-to-end scan.

## Out of Scope

Active injection testing requires separate request mutation, reflection analysis, response comparison, safety limits, and authorization controls.
That work will receive its own design after the core scan path is reliable.
