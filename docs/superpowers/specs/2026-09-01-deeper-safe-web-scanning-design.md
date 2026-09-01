# Deeper Safe Web Scanning Design

## Goal

Extend BitSentry from four bounded GET checks into a modular safe-active web scanner that confirms more vulnerability classes without mutating application state.

## Scope

The first milestone covers unauthenticated or already-authorized HTTP GET scanning only.

It tests query parameters, same-origin GET forms, discovered static assets, and API-like JSON responses when exposed through GET.

It does not submit POST, PUT, PATCH, or DELETE requests.

It does not run timing probes, brute force, credential attacks, or unrestricted external callbacks.

## Detection modules

`web_vulnerabilities` becomes a coordinator for focused checks under `bitprobe/scanner/active_checks/`.

Each check receives a baseline response, an endpoint, a parameter map, and a bounded request function.

Each check returns confirmed `Finding` objects with redacted evidence.

The first modules are:

- reflected XSS with context-aware markup confirmation
- SQL injection with differential error and response-shape confirmation
- path traversal and local file inclusion signatures
- open redirect with redirects disabled
- command injection using non-timing response markers only
- server-side template injection using arithmetic markers only
- SSRF using safe, scanner-controlled canary URLs only when explicitly configured

A module may report only when a baseline comparison and a vulnerability-specific signal both succeed.

## Discovery

The scanner keeps same-origin enforcement after URL preparation by the HTTP client.

It rejects malformed URLs, cross-origin final responses, unsafe form controls, and non-HTML form sources.

Parameter values preserve repeated query and form values.

The scanner extracts JSON keys only from GET responses with JSON content types and only at the top level.

JavaScript is not executed in this milestone.

## Request budgets

Budgets apply per origin, endpoint, and parameter.

The default safe-active budget is 24 requests per endpoint and 240 requests per origin.

A parameter starts with one baseline and one probe per applicable module.

Additional probes are allowed only when the first probe produces a module-specific signal.

Duplicate endpoint, parameter, and payload combinations are removed before dispatch.

The shared request handler remains the authority for rate limiting.

Progress reports include the active module, endpoint, parameter, completed requests, and budget usage.

## Safety

All active requests use GET.

All active requests use `allow_redirects=False`.

Every request URL is validated against the approved origin after request preparation.

SSRF checks are disabled unless a canary host is explicitly configured.

Evidence never stores original parameter values, credentials, cookies, authorization headers, or full response bodies.

Evidence contains the parameter name, payload class, status code, response content type, bounded matched signature, and a short redacted excerpt.

## Findings and reports

Findings are grouped by plugin, title, severity, description, and remediation before risk scoring, attack-chain construction, statistics, or report rendering.

Each grouped finding has sorted `affected_endpoints` and `endpoint_count`.

Markdown, PDF, and JSON preserve the grouped endpoint list.

## Scan tiers

Passive remains the default reconnaissance tier for quick scans.

Safe active is enabled by explicit profile or command selection and uses the modules in this document.

Intrusive mode is a future separately authorized tier for state-changing methods, authenticated workflows, and timing checks.

Browser-assisted mode is a future optional tier for JavaScript-rendered routes and network capture.

## Testing

Every detector has unit tests for positive and negative controls.

Controlled HTTP fixtures verify request methods, budgets, origin enforcement, redirect behavior, redacted evidence, and grouped output.

The full Python suite, Go network tests, Rust build, and a local end-to-end scan are required before release.
