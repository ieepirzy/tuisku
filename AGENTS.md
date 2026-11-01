# Tuisku: rules for agents and contributors

## Commands

- Install: `uv sync`
- Local database: `docker compose up -d` (dev-only Postgres on 127.0.0.1:55432)
- Lint / format / types: `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright`
- Tests: `TUISKU_TEST_DATABASE_URL=postgresql://tuisku:tuisku-dev@127.0.0.1:55432/tuisku uv run pytest -q -ra`
- One file: `uv run pytest tests/test_ready.py -q`
- Database tests skip without `TUISKU_TEST_DATABASE_URL` locally; with `CI=true` any skip fails.

## Rules

- **No ORM.** Application code talks to Postgres with plain SQL through psycopg
  (`tuisku.db`). SQLAlchemy is present only because Alembic needs it; it is used
  solely in `tuisku/migrate.py` and `migrations/env.py`. No models, no sessions,
  no autogenerate, no `target_metadata`.
- **Migrations** are hand-written Alembic revisions using `op.execute()` with raw
  SQL. Every revision declares exactly one module-level `expand_only = True` or
  `expand_only = False` (the Tyyni migration-safety convention; the template
  starts at `False`). Set `True` only when the revision only adds tables,
  nullable or defaulted columns, or plain indexes. Never edit a merged revision.
- **Never migrate on boot.** The API does not run migrations; `tuisku migrate`
  runs as a separate job, under a Postgres advisory lock.
- **Epistemic separation.** Keep four kinds of knowledge apart, in storage and in
  code: raw observations (what a sensor saw), deterministic detections (what a
  fixed rule concluded), community-rule interpretations (what a third-party rule
  set says), and agent inferences (what a model believes). Each carries its
  provenance. Agent output never rewrites or deletes an observation or a
  detection; it can only add inferences that reference them.
- **This repository is public.** Never commit detection logic, thresholds,
  hostnames, IP ranges, network topology or rules tuned to a specific deployment
  or estate; those live in the deploying organisation's own infrastructure
  repository. Never commit secrets, credentials, or real telemetry or logs that
  could contain personal data; test fixtures are synthetic.
- **Tests must be able to fail.** A new test is checked by breaking the code it
  covers and watching it go red before restoring it.
- **Architecture decisions** are recorded in `docs/adr/`. Read the relevant ADRs
  before changing an architectural boundary, and add a new ADR for a new decision.
