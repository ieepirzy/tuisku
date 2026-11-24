# Tuisku: rules for agents and contributors

## Commands

- Install: `uv sync`
- Local database: `docker compose up -d` (dev-only Postgres on 127.0.0.1:55432)
- Lint / format / types: `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright`
- Tests: `TUISKU_TEST_DATABASE_URL=postgresql://tuisku:tuisku-dev@127.0.0.1:55432/tuisku uv run pytest -q -ra`
- One file: `uv run pytest tests/test_ready.py -q`
- Name guard, with the private list: `TUISKU_DENYLIST_FILE=/path/to/list python3 -I scripts/name_guard.py tree`,
  and `... commits origin/main..HEAD` for the commits of a branch; optionally as a pre-push hook:
  `ln -s ../../scripts/pre-push .git/hooks/pre-push` (ADR 0013)
- Database tests skip without `TUISKU_TEST_DATABASE_URL` locally; with `CI=true` any skip fails.

## Rules

- **No ORM.** Application code talks to Postgres with plain SQL through psycopg
  (`tuisku.db`). SQLAlchemy is present only because Alembic needs it; it is used
  solely in `tuisku/migrate.py` and `migrations/env.py`. No models, no sessions,
  no autogenerate, no `target_metadata`.
- **Migrations** are hand-written Alembic revisions using `op.execute()` with raw
  SQL. Every revision declares exactly one module-level `expand_only = True` or
  `expand_only = False` (the expand/contract migration-safety convention: an
  `expand_only` declaration; the template starts at `False`). Set `True` only
  when the revision only adds tables, nullable or defaulted columns, or plain
  indexes. Never edit a merged revision.
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
  could contain personal data; test fixtures are synthetic. The deploying
  organisation's internal service, product and project names (and its
  hostnames) never appear in code, comments, fixtures, docs, file names, commit
  messages or pull request text: name the role instead (such as "the egress
  gateway"). `scripts/name_guard.py` enforces this with a denylist
  that is not in the repository: it is read from `TUISKU_DENYLIST` (the text)
  or `TUISKU_DENYLIST_FILE` (a path); the maintainers hold a copy. CI holds it
  as the secret `TUISKU_DENYLIST_B64` (the list base64-encoded on one line, so
  log masking does not expose each entry) and decodes it into a file in the
  `name-guard-tree` job, which scans the tree and the commits (messages, added
  lines, paths); the `name-guard-pr-text` job (`pr-text.yml`) scans pull
  request titles, bodies and branch names. Jobs that hold the list run only
  `python3 -I scripts/name_guard.py` (standard library only) and install
  nothing. Never commit the list, any entry of it, or a hash of an entry
  (digests of short names are reversible by brute force). Without the list,
  `tests/test_no_internal_names.py` skips locally and CI does the check
  (ADR 0013).
- **The name guard holds only when its checks are required.** `test`,
  `name-guard-tree` and `name-guard-pr-text` must be required status checks
  on main (branch protection or a ruleset), and the guard's files need a code
  owner's review (`.github/CODEOWNERS`); until they are required, CI reports
  but does not stop a merge. A push to any branch is public at once, so run
  the guard before pushing (the pre-push hook above). To set or rotate the
  secret: `base64 -w0 list > list.b64` (GNU coreutils; on macOS
  `base64 -i list -o list.b64`), then store the file's one line as
  `TUISKU_DENYLIST_B64` in both the Actions and the Dependabot secrets, and
  delete `list.b64`.
- **Tests must be able to fail.** A new test is checked by breaking the code it
  covers and watching it go red before restoring it.
- **Architecture decisions** are recorded in `docs/adr/`. Read the relevant ADRs
  before changing an architectural boundary, and add a new ADR for a new decision.
