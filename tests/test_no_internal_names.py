"""No internal service, product or project name of a deploying organisation appears in the tree.

This repository is public (AGENTS.md). The names it must never contain are listed below as
SHA-256 digests of the lowercase name, on purpose: a clear-text list would itself disclose them.
To add a name, append ``hashlib.sha256(name.lower().encode()).hexdigest()`` to ``FORBIDDEN``;
never write the name itself anywhere in the repository, including commit messages.

Every tracked (or new, not ignored) text file is split into lowercase tokens: runs of letters
and digits, the same runs joined by hyphens (so a hyphenated name is matched whole), and the
words of camelCase runs. A token whose digest is listed fails the test with ``file:line`` and
the token, so a contributor can replace it with the role it stands for ("the egress gateway",
"the artifact store"). Binary files are skipped.
"""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
from collections.abc import Iterator
from pathlib import Path

from tests.conftest import REPO_ROOT

FORBIDDEN = frozenset(
    {
        "932233e6ad07752203466d648b150bc9639699a046c40fa32c679b780e1179ef",
        "459e5cbca346573d3b90c07e726345bc9511df45d43b1d731b66bd199ee0910f",
        "22c8741ab58afd09e13c21433164b85b6c8c11cbece8c6f315ed1a862a32d96c",
        "f197fe49e9458d272619fe54bc5a8d01151e087fa18e6e1b5ca31d17fca86280",
        "342a5e802d736718c8777595247a62112fb47387221380d7661817b16cc7d4e0",
        "ef391a550e98b754fd589ec89c32e21032034868008118639fa1c6744a348f79",
        "7cb76dd34d8fdd7356ba7be3cf92f55e6a79d2a8ad57afa29bd52c31f71608db",
        "897cbdea57f45b15cc7d06816c55d1098390f731eb4d4602ec7b60ab9de53d7e",
        "d7a256d6359d674d1e4093a92b4fc6bf1e6bd36c485e05c4183527d4718ab841",
        "2ae7c98f139cf8840f7296189ba297d073973903910532344decdc180183028e",
        "b5926c6490852d08370bcbad8d5c81124581ec41aecf1d7f4b57b9a2bc64176b",
        "8a0c44f15cb7b9cd49f633d89ff1b4f65edc0e3258d39f8ee4f64cf09b6cce01",
        "7220bf32682345a8b3d1ad5f49fbaf50fa1d3ba09744143eece0ecbb05982ef4",
        "17fcb111a7f1334b3607b32e9c4f4e0a8a01b11c4d60c9913bed25eb78e819c9",
        "0c7c53639fa7e3a0e6b00ec80e08212e4ef32d95f22fef7fd660b5133fe3f0dc",
    }
)

# Comments in merged migration revisions, which are never edited (AGENTS.md): (path, line,
# token digest). An entry that no longer matches fails the test, so the list cannot go stale.
MERGED_REVISION_EXCEPTIONS = frozenset(
    (f"migrations/versions/{name}", line, digest)
    for name, line in (
        ("20261101_0001_evidence_store.py", 28),
        ("20261102_0002_rules_findings_incidents.py", 26),
        ("20261113_0003_otlp_logs_transport.py", 13),
        ("20261113_0003_otlp_logs_transport.py", 32),
        ("20261113_0004_export_queue.py", 50),
    )
    for digest in ("f197fe49e9458d272619fe54bc5a8d01151e087fa18e6e1b5ca31d17fca86280",)
)

SKIP_DIRS = frozenset(
    {".git", ".venv", "venv", "__pycache__", ".pytest_cache", ".ruff_cache", "node_modules"}
)

_HYPHENATED = re.compile(r"[A-Za-z0-9]+(?:-[A-Za-z0-9]+)+")
_ALNUM = re.compile(r"[A-Za-z0-9]+")
_CAMEL_WORD = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+")


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def tokens(line: str) -> set[str]:
    """Lowercase tokens of one line: alphanumeric runs, hyphen-joined runs and camelCase words."""
    found: set[str] = set()
    for m in _HYPHENATED.finditer(line):
        found.add(m.group(0).lower())
    for m in _ALNUM.finditer(line):
        run = m.group(0)
        found.add(run.lower())
        found.update(word.lower() for word in _CAMEL_WORD.findall(run))
    return found


def _candidate_files(root: Path) -> Iterator[str]:
    """Tracked and new (not ignored) files, from git; a walk of the tree when git is absent."""
    try:
        out = subprocess.run(
            [
                "git",
                "-C",
                str(root),
                "ls-files",
                "-z",
                "--cached",
                "--others",
                "--exclude-standard",
            ],
            check=True,
            capture_output=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for filename in filenames:
                yield str((Path(dirpath) / filename).relative_to(root))
        return
    yield from sorted({p for p in out.decode("utf-8", "surrogateescape").split("\0") if p})


def _text(path: Path) -> str | None:
    try:
        data = path.read_bytes()
    except (FileNotFoundError, IsADirectoryError):  # deleted but still tracked, or a submodule
        return None
    if b"\0" in data:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def scan(root: Path, forbidden: frozenset[str]) -> list[tuple[str, int, str, str]]:
    """``(path, line, token, digest)`` for every forbidden token in the text files under root."""
    hits: list[tuple[str, int, str, str]] = []
    for rel in _candidate_files(root):
        text = _text(root / rel)
        if text is None:
            continue
        for number, line in enumerate(text.splitlines(), start=1):
            for token in sorted(tokens(line)):
                digest = _digest(token)
                if digest in forbidden:
                    hits.append((rel, number, token, digest))
    return hits


def test_no_internal_names_in_the_tree() -> None:
    hits = scan(REPO_ROOT, FORBIDDEN)
    excepted = {(path, line, digest) for path, line, _, digest in hits}
    offending = [
        f"{path}:{line}: {token!r}"
        for path, line, token, digest in hits
        if (path, line, digest) not in MERGED_REVISION_EXCEPTIONS
    ]
    assert not offending, (
        "internal service names in a public repository; replace each with the role it stands "
        "for (AGENTS.md, 'This repository is public'):\n" + "\n".join(offending)
    )
    stale = sorted(MERGED_REVISION_EXCEPTIONS - excepted)
    assert not stale, f"exceptions that no longer match anything; remove them: {stale}"


def test_exceptions_are_merged_revisions_only() -> None:
    for path, _, digest in MERGED_REVISION_EXCEPTIONS:
        assert path.startswith("migrations/versions/") and path.endswith(".py")
        assert digest in FORBIDDEN


def test_tokeniser() -> None:
    line = "a Foo-Bar_baz.qux FooBar HTTPServer x2y v1.2-rc3 åäö"
    assert {"a", "foo-bar", "foo", "bar", "baz", "qux", "foobar", "httpserver"} <= tokens(line)
    assert {"http", "server", "x2y", "x", "y", "2", "v1", "2-rc3", "rc3"} <= tokens(line)
    assert "foo-bar_baz" not in tokens(line)
    assert "åäö" not in tokens(line)  # non-ASCII letters separate tokens


def test_scan_reports_file_line_and_token(tmp_path: Path) -> None:
    # Runs on a scratch tree (not a git checkout), so the directory walk is exercised too.
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "a.md").write_text("fine\nthe Example-Gateway and exampleService\n")
    (tmp_path / "b.bin").write_bytes(b"example\0binary")
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "c.py").write_text("example = 1\n")
    forbidden = frozenset({_digest("example"), _digest("example-gateway")})
    hits = [(path, line, token) for path, line, token, _ in scan(tmp_path, forbidden)]
    assert sorted(hits) == [
        ("docs/a.md", 2, "example"),
        ("docs/a.md", 2, "example-gateway"),
    ]
