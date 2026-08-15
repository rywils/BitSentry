# Project Memory

## Knowledge
- Stack, architecture, conventions, and gotchas are documented in [CLAUDE.md](../CLAUDE.md) at repo root — check there first, don't re-scan.

## Decisions
- 2026-08-15: Installed Spartan AI Toolkit (`@c0x12c/ai-toolkit`), then trimmed to the `core` pack only. Dropped backend-micronaut, frontend-react, ux-design, infrastructure, product, ops, research — none of those stacks apply to BitSentry (Python + Rust CLI security suite, small TS report dashboard). If a future session needs product-thinking or research commands back, re-run `npx @c0x12c/ai-toolkit@latest --local --packs=core,product,research` (or similar) rather than `--all`.
