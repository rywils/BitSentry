# BitProbe New Components Summary

This document summarizes the recently added advanced features to BitProbe.

## 1. Vulnerability Template Engine (`scanner/template_engine.py`)

Nuclei-style YAML templates for vulnerability detection without custom Python code.

### Features
- YAML-based template format
- Variable substitution ({{BaseURL}}, {{Hostname}})
- Multiple matcher types: word, regex, status, DSL
- Extractors for data extraction (regex, JSON)
- Concurrent template execution

### Example Template
```yaml
id: exposed-git
name: Exposed Git Repository
severity: high
request:
  method: GET
  path: /.git/config
matchers:
  - type: word
    words: ["repositoryformatversion"]
    part: body
```

### Usage
```python
from scanner.template_engine import TemplateLoader, TemplateExecutor

loader = TemplateLoader("templates")
templates = loader.load_all()

executor = TemplateExecutor(request_handler)
findings = executor.execute_all(templates, "https://target.com")
```

## 2. Attack Graph Engine (`scanner/attack_graph.py`)

Graph-based attack modeling for risk path analysis and breach simulation.

### Features
- Directed graph of assets, vulnerabilities, credentials, and data
- Attack path finding (DFS-based)
- Critical path identification
- Breach simulation
- Lateral movement analysis
- Export to JSON

### Usage
```python
from scanner.attack_graph import AttackGraph

# Build from findings
graph = AttackGraph.from_findings(findings, "https://target.com")

# Find attack paths
paths = graph.find_paths("internet", "data:sensitive")

# Get critical paths
critical = graph.get_critical_paths()

# Simulate breach
breach_paths = graph.simulate_breach("internet", simulation_depth=5)

# Save graph
graph.save("attack_graph.json")
```

## 3. Event Bus (`scanner/event_bus.py`)

Decoupled event-driven architecture for feature integration.

### Features
- Sync and async event handlers
- Priority-based subscription ordering
- One-time subscriptions
- Middleware support
- Built-in helper classes

### Event Types
- `SCAN_STARTED`, `SCAN_COMPLETED`, `SCAN_FAILED`
- `FINDING_DETECTED`, `CRITICAL_FINDING`, `HIGH_RISK_DETECTED`
- `SCREENSHOT_CAPTURED`, `EVIDENCE_COLLECTED`
- `REPORT_GENERATED`

### Usage
```python
from scanner.event_bus import event_bus, EventType

# Subscribe to events
@event_bus.on(EventType.FINDING_DETECTED, priority=10)
def handle_finding(finding):
    print(f"Found: {finding['title']}")

# Emit events
event_bus.emit(EventType.FINDING_DETECTED, finding_data)

# Built-in helpers
@on_finding_detected(severity_filter="critical")
def alert_critical(finding):
    send_urgent_alert(finding)
```

## 4. Webhook Alerts (`scanner/alerts/webhook_notifier.py`)

Async webhook notifications for CI/CD and SOC integration.

### Features
- Platform-specific formatting (Slack, Discord, Teams, generic)
- Auto-platform detection from URL
- Batch and immediate modes
- Severity filtering
- Retry with exponential backoff
- Multiple webhook support

### Usage
```python
from scanner.alerts.webhook_notifier import WebhookNotifier

# Single alert
async with WebhookNotifier("https://hooks.slack.com/...") as notifier:
    await notifier.notify(finding)

# Batch mode
async with WebhookNotifier(url, mode="batch", min_severity="high") as notifier:
    for finding in findings:
        await notifier.notify(finding)
    await notifier.flush()  # Send batch

# Multiple webhooks
from scanner.alerts import MultiWebhookNotifier

notifiers = MultiWebhookNotifier([
    WebhookNotifier(slack_url),
    WebhookNotifier(discord_url),
])
```

### Environment Variables
```bash
export BITPROBE_WEBHOOK_URL="https://hooks.slack.com/..."
export BITPROBE_WEBHOOK_MODE="batch"
export BITPROBE_WEBHOOK_MIN_SEVERITY="high"
```

## 5. Screenshot Evidence (`scanner/evidence/screenshotter.py`)

Async visual evidence capture for high/critical findings.

### Features
- Playwright-based capture (primary)
- Full-page or viewport screenshots
- Concurrent capture with semaphore limiting
- Evidence collection integration
- Automatic filename generation

### Dependencies
```bash
pip install playwright
playwright install chromium
```

### Usage
```python
from scanner.evidence import Screenshotter, EvidenceCollector

# Basic capture
async with Screenshotter() as s:
    path = await s.capture("https://target.com/admin", full_page=True)

# Capture for finding
async with Screenshotter() as s:
    path = await s.capture_finding(finding)

# Evidence collection
async with EvidenceCollector(min_severity="high") as collector:
    await collector.initialize()
    for finding in findings:
        evidence = await collector.collect(finding)

# Sync convenience function
from scanner.evidence import capture_screenshot_sync
path = capture_screenshot_sync("https://target.com")
```

## Integration Example

```python
import asyncio
from scanner.event_bus import event_bus, EventType
from scanner.alerts import WebhookNotifier
from scanner.evidence import EvidenceCollector

async def main():
    # Initialize components
    webhook = WebhookNotifier("https://hooks.slack.com/...", mode="batch")
    evidence = EvidenceCollector(min_severity="high")
    await evidence.initialize()
    
    # Subscribe to events
    @event_bus.on(EventType.FINDING_DETECTED)
    async def on_finding(finding):
        await webhook.notify(finding)
        await evidence.collect(finding)
    
    @event_bus.on(EventType.SCAN_COMPLETED)
    async def on_complete(data):
        await webhook.notify_scan_complete(
            data["target"],
            data["duration"],
            data["summary"]
        )
        await webhook.close()
        await evidence.close()
    
    # Run scan...
    # Findings will trigger webhook and screenshot automatically

asyncio.run(main())
```

## Directory Structure

```
scanner/
├── alerts/
│   ├── __init__.py
│   └── webhook_notifier.py      # Webhook notifications
├── evidence/
│   ├── __init__.py
│   └── screenshotter.py         # Screenshot capture
templates/
├── exposed-git.yaml             # Git exposure template
├── exposed-env.yaml             # Environment file template
├── open-redirect.yaml           # Open redirect template
└── directory-listing.yaml       # Directory listing template
```

## CLI Integration

These components integrate with BitProbe CLI:

```bash
# Enable webhook alerts
bitprobe scan https://target.com \
    --webhook-url https://hooks.slack.com/... \
    --webhook-mode batch \
    --webhook-min-severity high

# Enable screenshots (requires playwright)
bitprobe scan https://target.com --screenshots

# Use templates
bitprobe scan https://target.com --templates-dir templates/
```
