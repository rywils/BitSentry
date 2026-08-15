# Spec: BitDesk

**Created**: 2026-08-15
**Status**: draft
**Author**: Ryan
**Epic**: none

## Problem

BitSentry only has a terminal interface (Python CLI) and a web dashboard for reading finished reports (`bitreport/dashboard`). There's no way to run a scan or browse results without either a terminal or a browser tab. Some users, including professionals doing security work, just prefer a native app when one's available, and a polished desktop client is also a better thing to put in front of a client or on a website than a terminal screenshot. Reason enough on its own: it should exist as an option.

## Goal

A native desktop app (BitDesk) that can kick off a `bitsentry.py` scan and browse its output (findings, severity/plugin breakdowns, run history) without a terminal or browser, and that reads as a real desktop application, not a wrapped website.

## User Stories

- As a BitSentry user who'd rather not touch a terminal that day, I open BitDesk, point it at a target, start a scan, and watch results come in without leaving the app.
- As someone running a client engagement, I use BitDesk to walk through findings on screen instead of pulling up raw JSON or a CLI scrollback.

## Requirements

**Must-have**
- Launch and monitor a scan (`bitsentry.py scan <target>` or equivalent) as a subprocess, same invocation pattern the Python orchestrator already uses internally.
- Read and display `report.json` / `history.json` using the same schema the web dashboard already consumes (`bitreport/dashboard/src/types.ts`: `SuiteReport`, `NormalizedFinding`, `HistoryFile`).
- Findings view: filter/sort by severity and plugin, same data the dashboard's table shows.
- Severity and plugin rollup views (chart or equivalent), matching what the dashboard's pie/bar charts show.
- Run history view when `history.json` is present.
- Native rendering (Avalonia), no embedded webview/browser control anywhere in the app.

**Nice-to-have**
- Live scan progress/log tail while a scan runs.
- Cross-launch: open a specific past run's report directly from history.

**Out of scope**
- No auth, multi-user, or cloud sync — this is a local single-user desktop client, same trust model as the CLI.
- No mobile target.
- No installer/auto-update pipeline in this pass — that's a later, separate concern once the app itself exists.
- No changes to the report schema or `bitreport/writers/*` — BitDesk is a pure consumer of the existing contract.
- No replacement of the CLI or web dashboard — this is a third option, not a migration.

## Data Model

None. No new tables, no schema changes. BitDesk deserializes the existing `report.json` / `history.json` files into C# model classes that mirror `types.ts` field-for-field (`SuiteReport`, `NormalizedFinding`, `HistoryFile`, `HistoryRun`).

## API Changes

None. BitDesk talks to the existing system two ways, both already used elsewhere in the repo:
- Subprocess: invoke `bitsentry.py` (and, transitively, `bitprobe-engine`) the same way the Python orchestrator already shells out to the Rust engine.
- File read: parse the same `report.json` / `history.json` files the web dashboard fetches over HTTP.

## UI Changes

New application, `bitdesk/` at repo root, C#/Avalonia, MVVM. Screens: Scan (target input, start/stop, progress), Findings (filterable table), Rollups (severity/plugin charts), History (past runs).

## Edge Cases

- `bitprobe-engine` binary not built / not on PATH: surface a clear error in the UI, don't crash, don't silently no-op.
- No `report.json` yet (first run, before any scan completes): show an empty/waiting state, not an error.
- Malformed or partial `report.json`: fail to that same empty/waiting or error state rather than throwing an unhandled exception into the UI.
- Scan running long: UI stays responsive (subprocess I/O off the UI thread), user can see it's still in progress.
- Scan process fails/exits non-zero: surface the failure and any stderr output to the user, not a silent dead-end.
- Second scan started while one's already running: block or queue it, matching however the CLI already handles concurrent invocations against the same target/output dir.
- Cross-platform binary/path resolution: locating `bitprobe-engine` and the Python interpreter differs on Windows vs. macOS vs. Linux.

## Testing Criteria

**Happy path**
- Start a scan against a known-good target, see it complete, see findings/rollups/history match what the web dashboard shows for the same run's `report.json`.

**Edge cases**
- Missing engine binary → clear in-app error, no crash.
- Missing/malformed `report.json` → empty/error state, no unhandled exception.
- Long-running scan → UI remains interactive (window can be resized/moved, isn't frozen).
- Failed scan (non-zero exit) → failure surfaced with stderr, not swallowed.

## Dependencies

- .NET SDK + Avalonia UI.
- Existing `bitsentry.py` CLI and `bitprobe-engine` binary (already in repo).
- Existing report schema produced by `bitreport/writers/json_writer.py` — BitDesk depends on this contract staying stable or versioned, not on any new work there.
