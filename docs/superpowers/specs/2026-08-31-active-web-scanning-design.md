# Active Web Scanning and Grouped Findings Design

## Problem

BitProbe currently reports passive configuration issues, exposed files, TLS weaknesses, ports, and fingerprint-based CVEs.
It does not mutate page inputs to verify application vulnerabilities.

The report also emits the same vulnerability once per endpoint.
Those duplicates are unsorted, inflate totals, and inflate risk scores.

## Scope

This change adds safe GET-based checks for reflected XSS, SQL error injection, path traversal, and open redirects.
It groups equivalent findings before scoring and renders all affected endpoints together.

State-changing POST requests, stored XSS, SSRF, command injection, authentication bypass, and destructive payloads remain out of scope.

## Finding Aggregation

A canonical aggregation step will run before prioritization and report statistics.
Findings will group by plugin, title, severity, description, and remediation.
Each grouped finding will contain:

- `affected_endpoints`: sorted unique endpoint URLs
- `endpoint_count`: number of affected endpoints
- `url`: the first sorted endpoint for backward compatibility

Findings will sort by critical, high, medium, low, and info severity.
Findings with the same severity will sort by title and first endpoint.
Risk and severity totals will count each grouped vulnerability once.

Markdown and PDF reports will render one vulnerability section followed by its affected endpoints.
JSON will expose the grouped fields directly.

## Active Plugin

A new `web_vulnerabilities` plugin will inspect every crawled HTML page.
It will discover GET query parameters from the URL and GET form controls from the page.
It will preserve other parameter values while mutating one parameter at a time.

The plugin will use the shared request handler so existing rate limits, cookies, authentication, timeouts, TLS settings, and retry behavior remain in effect.
Only same-origin HTTP and HTTPS targets will be tested.

## Reflected XSS

The plugin will inject a unique custom HTML element into one parameter.
A finding requires the response HTML parser to contain that exact injected element and token.
Escaped text does not qualify.
The baseline response must not contain the token.

## SQL Error Injection

The plugin will append a single quote to one parameter.
A finding requires a recognized database error signature that was absent from the baseline response.
Signatures will cover common PostgreSQL, MySQL, MariaDB, SQLite, Microsoft SQL Server, and Oracle errors.

## Path Traversal

The plugin will test bounded Unix and Windows traversal payloads.
A finding requires a known file signature such as a Unix passwd entry or Windows INI section that was absent from the baseline response.

## Open Redirect

The plugin will set one parameter to a unique HTTPS URL under `example.com` and disable redirect following.
A finding requires a redirect status and a `Location` header matching the unique destination.
No request will be sent to the destination.

## Request Limits

The plugin will test at most six unique parameters per page.
Each vulnerability class will send at most one payload per parameter, except traversal which may send one Unix and one Windows payload.
Duplicate form actions and parameter sets will be scanned once per page.
Non-HTML responses and pages without GET inputs will return no findings.

## Evidence

Every active finding will include:

- HTTP method
- parameter name
- payload
- response status
- detection reason
- bounded response evidence

Evidence will not include cookies, authorization headers, or full response bodies.

## Plugin Loading

`web_vulnerabilities` will be enabled in the default, standard, and full scan configurations.
The quick and infrastructure profiles will remain passive.

## Tests

Tests will use local response objects and a local HTTP fixture.
Regression coverage will include:

- grouping duplicate findings into sorted endpoint lists
- severity and title ordering
- grouped statistics and risk
- Markdown and PDF endpoint rendering
- reflected XSS detection without escaped-reflection false positives
- SQL error detection only when the error is new
- Unix and Windows traversal signatures
- exact open redirect detection without following redirects
- request caps and same-origin restrictions
- default plugin loading
- a local end-to-end scan that reports active vulnerabilities
