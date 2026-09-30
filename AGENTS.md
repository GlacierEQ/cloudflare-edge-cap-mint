# AGENTS.md — cloudflare-edge-cap-mint

**Company:** Cloudflare
**Domain:** Cloud AI Platform Engineering

## Quick Rules
- **Test command:** `PYTHONPATH=src pytest tests/ -v`
- **Lint:** `ruff check src/ tests/`
- **No drive-by edits** — load the skill first.

## Architecture
- `src/cloudflare_edge_cap_mint/core.py` — Domain logic (Cloud AI Platform Engineering)
- `tests/` — Verified test suite
- `.github/workflows/ci.yml` — Enforced CI pipeline
