# Plan: BitDesk

**Spec**: .planning/specs/bitdesk.md
**Epic**: none
**Created**: 2026-08-15
**Status**: draft

## Stack

New project, not an extension of an existing detected stack — C#/.NET + Avalonia (MVVM), added as `bitdesk/` at repo root alongside `bitscope/`, `bitprobe/`, `bitreport/`. No Kotlin/Next.js in this repo; the architecture below follows the repo's own conventions instead: one product per top-level directory, shared `report.json`/`history.json` contract, engine invoked as a subprocess.

Charting needs a library Avalonia doesn't ship — using **LiveCharts2** (SkiaSharp-backed, native Avalonia support, actively maintained). Flagging this as a real decision, not a given: if you'd rather use OxyPlot or something else, swap it in Phase 6.

## Components

| Component | Type | Purpose |
|---|---|---|
| `App` / `Program` | Avalonia bootstrap | starts the app, wires DI for Core services |
| `MainWindow` / `MainWindowViewModel` | Shell view/VM | window chrome, nav between Scan/Findings/Rollups/History |
| `ScanView` / `ScanViewModel` | View/VM | target input, start/stop, live status |
| `FindingsView` / `FindingsViewModel` | View/VM | filterable findings table |
| `RollupsView` / `RollupsViewModel` | View/VM | severity/plugin charts |
| `HistoryView` / `HistoryViewModel` | View/VM | past runs list |
| `EngineRunner` | Core service | launches `bitsentry.py scan`, streams stdout/stderr, reports exit code |
| `ReportStore` | Core service | reads/deserializes `report.json` / `history.json` |
| `SuiteReport`, `NormalizedFinding`, `HistoryFile`, `HistoryRun` | Core models | mirror `bitreport/dashboard/src/types.ts` field-for-field |

## File Locations

| File | Location | Purpose |
|---|---|---|
| `BitDesk.sln` | `bitdesk/` | solution file |
| `Program.cs`, `App.axaml(.cs)` | `bitdesk/src/BitDesk.App/` | entry point, DI wiring |
| `MainWindow.axaml(.cs)` | `bitdesk/src/BitDesk.App/Views/` | shell window |
| `ScanView.axaml(.cs)`, `FindingsView.axaml(.cs)`, `RollupsView.axaml(.cs)`, `HistoryView.axaml(.cs)` | `bitdesk/src/BitDesk.App/Views/` | the four screens |
| `MainWindowViewModel.cs`, `ScanViewModel.cs`, `FindingsViewModel.cs`, `RollupsViewModel.cs`, `HistoryViewModel.cs` | `bitdesk/src/BitDesk.App/ViewModels/` | screen state/behavior |
| `SuiteReport.cs`, `NormalizedFinding.cs`, `HistoryFile.cs`, `HistoryRun.cs` | `bitdesk/src/BitDesk.Core/Models/` | data contract, mirrors `types.ts` |
| `ReportStore.cs` | `bitdesk/src/BitDesk.Core/Services/` | file read + parse |
| `EngineRunner.cs` | `bitdesk/src/BitDesk.Core/Services/` | subprocess invocation |
| `ReportStoreTests.cs`, `EngineRunnerTests.cs` | `bitdesk/tests/BitDesk.Core.Tests/` | unit tests |

## Files to Change

| File | What Changes | Why |
|---|---|---|
| `.gitignore` | add `bin/`, `obj/`, `*.user` under a `# .NET` section | keep .NET build artifacts out of git, matching how Python/Node artifacts are already excluded |

No changes to `bitreport/writers/*` or the report schema — BitDesk is a pure consumer, per spec.

## Tasks

### Phase 1: Scaffolding

| # | Task | Files |
|---|---|---|
| 1 | Create solution + 3 projects (`BitDesk.App` Avalonia MVVM template, `BitDesk.Core` classlib, `BitDesk.Core.Tests` xunit) | `bitdesk/BitDesk.sln`, `bitdesk/src/BitDesk.App/*.csproj`, `bitdesk/src/BitDesk.Core/BitDesk.Core.csproj`, `bitdesk/tests/BitDesk.Core.Tests/*.csproj` |
| 2 | Add .NET build artifacts to `.gitignore` | `.gitignore` |

### Phase 2: Report models + reading (depends on Phase 1)

| # | Task | Files |
|---|---|---|
| 3 | Add `SuiteReport`, `NormalizedFinding`, `HistoryFile`, `HistoryRun` records mirroring `types.ts` | `Models/*.cs` |
| 4 | Add `ReportStore` (parses `report.json`/`history.json`, returns null/empty on missing or malformed input rather than throwing) + tests for: valid file, missing file, malformed JSON | `Services/ReportStore.cs`, `tests/ReportStoreTests.cs` |

### Phase 3: Engine subprocess (depends on Phase 1, parallel with Phase 2)

| # | Task | Files |
|---|---|---|
| 5 | Add `EngineRunner` (async subprocess start/stream/exit-code, cross-platform resolution of the Python interpreter and `bitprobe-engine`) + tests against a stub executable covering stdout capture and non-zero exit | `Services/EngineRunner.cs`, `tests/EngineRunnerTests.cs` |

### Phase 4: App shell (depends on Phase 1, parallel with Phase 2/3)

| # | Task | Files |
|---|---|---|
| 6 | `App`/`Program` bootstrap + `MainWindow`/`MainWindowViewModel` with nav between four (initially empty) screens | `Program.cs`, `App.axaml(.cs)`, `Views/MainWindow.axaml(.cs)`, `ViewModels/MainWindowViewModel.cs` |

### Phase 5: Scan screen (depends on Phase 3, 4)

| # | Task | Files |
|---|---|---|
| 7 | `ScanView`/`ScanViewModel`: target input, start/stop bound to `EngineRunner`, surfaces missing-binary and non-zero-exit errors in the UI | `Views/ScanView.axaml(.cs)`, `ViewModels/ScanViewModel.cs` |

### Phase 6: Findings + Rollups (depends on Phase 2, 4)

| # | Task | Files |
|---|---|---|
| 8 | `FindingsView`/`FindingsViewModel`: table bound to `ReportStore` output, severity/plugin filter (same filter semantics as `bitreport/dashboard/src/App.tsx`'s `FindingsTable`) | `Views/FindingsView.axaml(.cs)`, `ViewModels/FindingsViewModel.cs` |
| 9 | `RollupsView`/`RollupsViewModel`: severity/plugin charts via LiveCharts2 | `Views/RollupsView.axaml(.cs)`, `ViewModels/RollupsViewModel.cs` |

### Phase 7: History (depends on Phase 2, 4)

| # | Task | Files |
|---|---|---|
| 10 | `HistoryView`/`HistoryViewModel`: past runs list, empty state when `history.json` absent | `Views/HistoryView.axaml(.cs)`, `ViewModels/HistoryViewModel.cs` |

## Parallel vs Sequential

| Parallel Group | Tasks | Why |
|---|---|---|
| Group A | 3, 4, 5, 6 | each depends only on Phase 1 scaffolding, touch disjoint files |

| Sequential | Depends On | Why |
|---|---|---|
| Task 7 | 5, 6 | needs `EngineRunner` and the shell/nav to exist |
| Task 8, 9 | 4, 6 | need `ReportStore`/models and the shell/nav to exist |
| Task 10 | 4, 6 | needs `ReportStore`/models and the shell/nav to exist |

## Testing Plan

- **Core unit tests** (`BitDesk.Core.Tests`, real automated tests):
  - `ReportStore`: valid `report.json` deserializes correctly (happy path) → covers spec's core data-display requirement; missing file returns empty/null state, not a throw → covers edge case "no report.json yet"; malformed JSON returns the same empty/null state → covers edge case "malformed or partial report.json".
  - `EngineRunner`: stub executable's stdout is captured → covers happy path scan monitoring; non-zero exit is surfaced as a failure result with stderr attached → covers edge case "scan process fails".
- **UI verification** (manual, against the running app — Avalonia has no established UI test harness in this repo yet, so this isn't automated):
  - Missing `bitprobe-engine` binary → clear in-app error, no crash.
  - Long-running scan → window stays interactive (resize/move works, isn't frozen).
  - Second scan started while one's running → blocked/queued, not two concurrent runs.
  - Cross-platform binary resolution → spot-check on at least Linux + one other OS before calling this done.

## Gate 2 Checklist

- [x] Follows the project's own conventions (per-product top-level dir, shared JSON contract, subprocess reuse) since there's no existing C# code to match
- [x] Views → ViewModels → Core services only; `BitDesk.Core` has no Avalonia reference
- [x] Components in the directories listed above
- [x] All files to change listed (`.gitignore`, one entry)
- [x] All new files listed with locations
- [x] Each task ≤3 files
- [x] Task dependencies stated per phase
- [x] Parallel vs sequential marked
- [x] Data-layer tests planned (`ReportStore`)
- [x] Business-logic tests planned (`EngineRunner`)
- [x] UI tests: no automated harness exists yet, so this is manual verification against spec edge cases — noted explicitly, not glossed over
- [x] All 7 spec edge cases covered somewhere in the testing plan
