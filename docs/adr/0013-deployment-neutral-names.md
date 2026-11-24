# 0013. Deployment-neutral names for built-in adapters and packs

Status: Accepted (2026-11-23; revised 2026-11-24 after review: the name guard's list is kept out
of the repository, its matching and CI jobs were hardened, and it scans commits)

## Context

This repository is public ([0001](0001-service-boundary-and-principles.md), principle 6; AGENTS.md).
One built-in adapter and its rule pack were named after the deploying organisation's own egress
gateway, and the adapter matched that gateway's logger and metric names literally. The ADRs and
fixtures also named other internal services of that organisation. A service name tells a reader
what the organisation runs and how it is put together, which is the kind of estate detail the
repository already keeps out (detection logic, thresholds, hostnames, topology).

## Decision

- **Built-in adapters and packs are named for the role of the source, not for a product a
  deployment runs.** The egress gateway adapter and pack are `egress-guard`: they read an agent
  egress safety proxy (an outbound fetch gateway that agents call to fetch URLs, and that refuses
  unsafe outbound requests and destinations). Tuisku's own vocabulary for it (observation and
  detection kinds, detection identities, `caller:egress-guard/<name>` entity keys, rule names)
  uses that name.
- **A source's own names are configuration, with neutral defaults.** The adapter recognises
  refusals from `<logger_prefix>.api` and `<logger_prefix>.mcp`, and checks the label values of
  `<metric_prefix>.outbound.refused`, `<metric_prefix>.destination.refused` and
  `<metric_prefix>.content.signals`; both prefixes are adapter options defaulting to
  `egress_guard`. Metric names are stored verbatim in `metric.sample` observations (an adapter
  never rewrites what the sensor sent), so the pack matches them through the params
  `destination_refused_metric` and `content_signals_metric`, which a deployment sets in
  `TUISKU_RULE_PARAMS_FILE`. The options and the params must name the same counters; nothing
  can check that, since one belongs to a source and the other to the pack, and the README says
  what a mismatch does (rules that never fire, or counters whose labels go unchecked). A
  deployment's real names live only in its own configuration repository.
- **Bad adapter options are refused when the source is registered.** The adapter contract
  ([0005](0005-source-adapters-and-ingestion.md)) gains an optional hook,
  `validate_options(options)`, called through `tuisku.adapters.validate_options`; an adapter
  without it accepts any options at registration, so the `Adapter` protocol and the other
  adapters are unchanged. `egress-guard` implements it with the check its `parse` uses (only
  `logger_prefix` and `metric_prefix`, each a dotted name), and `tuisku source add` and
  `tuisku source ensure` call it before writing anything. A source whose options reach the
  database another way and fail the check fails every record, with a parse failure recorded per
  raw record, instead of turning refusals into generic log lines.
- **Documents name roles** ("the egress gateway", "the artifact store", "the red-team service",
  "the reference agent runtime"). The earlier ADRs were edited to do so; the edits change no
  decision and each carries a dated edit note.
- **A guard keeps names out, and its list is not in the repository.** `scripts/name_guard.py`
  scans every tracked file and every untracked file that is not ignored, the name of each file
  and directory, and each symlink's target; CI also runs it over commits and pull request text
  (below). The denylist comes only from the environment (`TUISKU_DENYLIST`, the list's text, or
  `TUISKU_DENYLIST_FILE`, a path); the maintainers hold a copy, and CI holds it as a secret. It
  is never committed, in clear text or in any derived form. A hit in contents is reported as
  `path:line`; a hit in a file or directory name, a symlink target or an unreadable file is
  reported as the path itself, which necessarily shows that path; a hit in a commit is reported
  as the commit's id, the part of it (message, added lines, paths) and a line number. A report
  never quotes the matched line or a term on its own.
  - **Matching.** A plain entry matches as a case-insensitive substring of a word (letters and
    digits joined by `-`, `_` or `.`), so inflected and joined forms are caught. `^word` matches
    a word, or a part of one, that starts with `word`; the parts of a word are split at its
    joiners and at camelCase and letter/digit boundaries, so inflections are caught but words
    that merely contain `word` are not. An entry of two words matches across spaces,
    separators and camelCase, and across the `/` between directories in a path. `!word` allows
    a word: as a whole word or as whole parts of one (`x-word`, `theWord`), never inside a part;
    it is blanked before matching (with a private-use character; one in the text itself counts
    as a separator), and a compound match that spans a blanked word does not count. Entries and
    lines alike are NFKC-normalised, stripped of format characters (zero-width characters, the
    soft hyphen), casefolded, and common Cyrillic, Greek, Armenian and Latin look-alikes are
    mapped to Latin; each line is checked again accent-folded (NFKD without nonspacing marks).
    Percent-decoded (twice), HTML-unescaped and JSON-unescaped (`\uXXXX`) copies of a line are
    checked too, at most eight forms of a line in all and only for lines of at most 4096
    characters, so crafted input cannot multiply the work; every line is checked in full as
    written. Consecutive lines are checked joined, across the line break (for a compound) and as
    a word hyphenated at the end of a line (closing and opening quotes around the break are
    allowed, for concatenated strings); the pair is decoded as one text, up to 256 characters
    either side of the join. Only a match that crosses the join counts, and it is reported on
    the first line.
  - **Files.** Read as UTF-8, as UTF-16 or UTF-32 when a BOM says so, and otherwise both as
    Latin-1 and as UTF-8 with undecodable bytes replaced, so one stray byte does not turn off
    the normalisation above. A file with NUL bytes is read as `strings` would (ASCII and
    UTF-16LE runs) and as UTF-8 with undecodable bytes replaced. A file that cannot be read is
    reported, never skipped.
  - **Git LFS.** A path whose `filter` attribute is `lfs` (as `git check-attr` reads
    `.gitattributes`), a file that is an LFS pointer, and a commit that adds one fail the guard.
    An LFS file's content is stored outside the Git tree, so the guard cannot read it, yet it is
    published with the repository; this repository has no use for LFS.
  - **Commits.** `name_guard.py commits REV...` scans each commit that `git rev-list` lists: its
    author and committer names and emails, its subject and body, every line its diff adds, and
    the path of every file it adds or changes. Renames are not detected, so a renamed file's
    lines and a new empty file's path are seen; a merge commit's diff is taken against its first
    parent. Deleted lines and paths are not scanned: removing a name is what the guard asks for.
  - **The secret.** CI holds the list as the secret `TUISKU_DENYLIST_B64`: the list
    base64-encoded on one line (`base64 -w0 list > list.b64` with GNU coreutils, or
    `base64 -i list -o list.b64` on macOS; the file's one line is the secret's value, and the
    file is deleted afterwards). GitHub masks every line of a multi-line secret in logs as a
    separate value, so a newline-separated list would turn each entry into a log mask, and a
    masked word in any log would show that it is listed. A job decodes the secret into a file
    under the runner's temporary directory (never echoing it) and passes that path as
    `TUISKU_DENYLIST_FILE` to the steps that scan. An empty or missing secret fails the job.
    `TUISKU_DENYLIST` and `TUISKU_DENYLIST_FILE` remain for local use.
  - **CI jobs.** Two jobs hold the list: `name-guard-tree` in `ci.yml`, which scans the tree and
    the commits of a pull request, or of a push to main (`before..after`; a newly created
    branch, whose `before` is all zeros, has only its head commit scanned), and
    `name-guard-pr-text` in `pr-text.yml`, which scans a pull request's title, body and branch
    name when it is opened, edited, reopened or pushed to. Intermediate commits are scanned
    because they reach main's history under merge and rebase merges. Neither job installs
    anything or runs a test runner, a dependency or the project's code: each runs only the
    scanner, which needs only the standard library, with the runner's `python3 -I`. A
    dependency's install hook, `.pth` file or test plugin therefore never runs where the list
    is, which matters because Dependabot pull requests, which change dependencies, receive the
    secret too. The `test` job needs no secret, so lint, types and tests report on every pull
    request; it deselects the tree test, which without the list would skip and so fail under
    `CI=true` (so a renamed tree test cannot pass unnoticed). The tree test and the
    `name-guard-tree` job run the same function, `scan_repo`. The job names differ because
    branch protection matches required checks by name: two jobs of one name would let a passing
    run of one stand in for a failing run of the other.
  - **Required checks.** The guarantees below hold only when `test`, `name-guard-tree` and
    `name-guard-pr-text` are required status checks on main, through branch protection or a
    ruleset, and `.github/CODEOWNERS`, which names the owner for the scanner, its tests, the
    pre-push hook and the workflows, is enforced by requiring a code owner's review. Until
    then, CI reports a hit but does not stop a merge.
  - **Before pushing.** A push to any branch of a public repository is public at once, before
    CI runs, and a CI failure points at a line in a public log. Maintainers therefore run the
    guard locally first; `scripts/pre-push` is an optional pre-push hook that runs it over the
    work tree and over the commits being pushed (`ln -s ../../scripts/pre-push
    .git/hooks/pre-push`), and refuses the push without the list.
  - **Dependabot.** A Dependabot pull request's body, and the bodies of the commits Dependabot
    authors, are upstream release notes and changelogs: text this repository does not write
    and cannot change. They are not scanned: the PR body when the pull request's author is
    `dependabot[bot]`, and a commit body whose author name is `dependabot[bot]` (`commits
    --skip-bodies-of`) in a pull request that Dependabot opened and on main. A commit author
    name can be set by anyone, so other pull requests scan every body. The title, branch name,
    commit subjects, added lines, paths and tree of a Dependabot pull request are scanned.
  - **Merged revisions.** Comments in four merged migration revisions, and the module docstring
    of revision 0003, name an internal tool (the migration-safety checker). Merged revisions are
    never edited (AGENTS.md), so those five lines are excepted exactly, by path, line number and
    the SHA-256 of the whole line. Each line is long and already in the tree, so its digest
    discloses nothing new. An exception that no longer matches its line fails the guard.
  - **Rejected: digests of the names in the repository.** The first version of this guard kept
    SHA-256 digests of the names in the test file. Digests of short names are reversible by
    brute force, so the digest list would have published the names; a salt would be public and
    does not change that. A clear-text list in the repository discloses the names directly.

## Consequences

- No revision's SQL names the gateway or any other internal service: the rename needs no schema
  change. The merged revisions' comments above keep their name, in the tree and in the published
  history; the guard stops new occurrences, it does not remove old ones. Rows already stored keep
  the kinds and entity keys they were written with; evidence is never rewritten
  ([0002](0002-epistemic-layers.md)), so queries over older history use the old kinds.
- The five pack rules changed their selects, so their `rev` is 2 and the pack is version 2.0.0;
  the adapter is version 2.0.0. A finding's fingerprint includes the rule's id and rev
  ([0007](0007-findings-and-incidents.md)), so firings of the rev 2 rules open new findings;
  findings of the old rules are not continued and expire on their own windows.
- Tuisku has no live deployment yet, so no stored source uses the old adapter name and no data
  migration is provided. A deployment that had registered a source with the old adapter would
  register the source again with the new adapter name (`tuisku source ensure` never changes an
  existing source's adapter; the old name is unknown, so its records fail to parse), set
  `logger_prefix` and `metric_prefix` and the pack params `destination_refused_metric` and
  `content_signals_metric` to its gateway's names, and key its params file by the new pack id
  (a params file naming an unknown pack stops the worker from loading packs).
- The guard runs only where the list is:
  - A contributor without the list cannot run the tree check: `tests/test_no_internal_names.py`
    skips locally, and CI does the check. The scanner's own tests use a synthetic list and run
    everywhere.
  - CI fails closed. Without the secret, the `name-guard-tree` and `name-guard-pr-text` jobs
    fail at their first step, and the tree test, if it ran without a list, would skip and so
    fail under `CI=true`. With those checks required, no pull request merges without the tree
    and its commits having been scanned with the list.
  - Pull requests from forks get no repository secrets, so their name guard fails while their
    lint, types and tests still report; a maintainer runs the guard with the list (or moves the
    branch into the repository) before merging.
  - Dependabot pull requests read Dependabot secrets, not Actions secrets, so the maintainer
    sets `TUISKU_DENYLIST_B64` in both stores; without it their name guard fails in the same way.
  - The pull request text is checked again whenever the title or body is edited.
- The guard finds only listed names, in the forms its normalisation covers, in text it can
  decode (not inside compressed or image files). It is a backstop for review, not a substitute.

## What remains public

The guard stops new occurrences; it does not remove old ones. These still disclose names or
estate detail, and are accepted or open:

- **Merged migration revisions.** The five excepted comment lines above keep one internal
  tool's name in the tree, because merged revisions are not edited. The exception list in
  `scripts/name_guard.py` points at those lines, so it confirms that this one tool's name is
  listed. The `expand_only` declaration that AGENTS.md requires of every revision is that
  tool's convention; it is in every revision, so it is public anyway.
- **History.** The history of main, earlier branches and the diffs of earlier pull requests keep
  every name that was ever committed. Removing them needs a history rewrite and a request to
  GitHub Support to purge cached views and pull request refs, and clones and forks keep their
  copies regardless.
- **Earlier pull request branches and diffs**, including those of an earlier revision of this
  change, stay readable through the pull requests that carried them. One such revision held a
  list of SHA-256 digests of the names (see "Rejected" above); digests of short names are
  reversible, so every name exposed that way should be treated as disclosed.
- **Issues, pull request titles, bodies and comments, and old CI logs** keep what they said.
  The guard scans pull request titles, bodies and branch names from this change on; it never
  scans issues or comments, and an edit to any of them leaves the earlier text in its history.
- **Guard failures in CI logs.** A failing guard reports a path and line, or a commit and line,
  in a public log; the line it points at is in the pushed commit for anyone to read. Run the
  guard before pushing (the pre-push hook above), not only in CI.
- **Container images** built before this change contain the earlier tree.
- **The egress-guard adapter's vocabulary.** Its closed sets of detectors, locations, encodings,
  stages and verdicts, and the shapes of the log messages it parses, are those of one gateway
  product. Renaming the adapter removed the product's name, but the vocabulary still identifies
  the product to someone who knows it. Open question: move the adapter out of the core into a
  plugin that the deploying organisation keeps, or make those sets configuration with neutral
  defaults.
