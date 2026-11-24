"""Find a deploying organisation's internal names in the tree or in text (AGENTS.md, ADR 0013).

The denylist is never part of this repository: it comes only from the environment, as the
list's text in ``TUISKU_DENYLIST`` or as a path in ``TUISKU_DENYLIST_FILE``. In CI it is a
repository secret, stored base64-encoded on one line and decoded into a file (ADR 0013). A
report names where a hit is and never quotes the matched line or the matched term: a hit in
contents is ``path:line``; a hit in a file or directory name, a symlink target or an unreadable
file is the path itself with the kind in brackets, so a path hit necessarily shows that path.

List format, one entry per line; blank lines and lines starting with ``#`` are ignored:

- ``term``: a case-insensitive substring of a word, so inflected and joined forms match.
- ``^word``: a word, or a part of one, that starts with ``word``. The parts of a word are the
  pieces between its joiners and its camelCase, letter-to-digit and digit-to-letter boundaries,
  so ``^frob`` is found in ``frobs``, ``x-frobbing`` and ``myFrobber`` but not in ``afrob``.
- ``word1 word2``: a compound, matched as ``word1[\\W_]*word2`` anywhere in a line, so it is found
  across spaces, hyphens, underscores, dots and camelCase.
- ``!word``: an allowed word, although it contains a term or starts with a ``^`` entry. It is
  recognised as a whole word and as one or more whole parts of a word (``x-word``,
  ``theWord``, ``Word42``), never inside a part. An allowed word is blanked before matching,
  and a compound match that spans a blanked word does not count, so the blank never acts as
  the separator that completes a compound.

A word is a maximal run of letters and digits joined by ``-``, ``_`` or ``.``, so a term is
found in ``term-x``, ``Term_Thing`` and ``term.example`` as well as in ``termthing``.

Normalisation, applied to the list's entries and to the text alike: NFKC; format characters
removed (zero-width spaces and joiners, U+2060, U+FEFF, the soft hyphen and the rest of Unicode
category Cf), and with them the characters that render as blank space (the Hangul fillers and
the blank braille pattern); casefolding; and common Cyrillic, Greek, Armenian and Latin
look-alikes mapped to Latin letters. Every line is also checked in a second, accent-folded form
(NFKD with the nonspacing marks, category Mn, removed), so an accented or decomposed spelling of
an entry is found. Each line is checked as written and as decoded: percent-decoded (twice, for
double encoding), HTML-unescaped and with JSON ``\\uXXXX`` escapes decoded, in combination. To
bound the work on crafted input, decoded forms are made only for lines of at most
``MAX_DECODED_LINE`` characters, and at most ``MAX_VARIANTS`` forms per line; every line is
still checked in full as written.

Lines are also checked in pairs, for a name split across a line break: each line joined to the
next with a line break between them (a compound spans it, as it spans any separator) and, when
a line ends with a hyphen (optionally followed by closing quotes), joined to the next without
it (``term-`` at the end of one line and the rest of the word at the start of the next; comment
markers and opening quotes that start the next line are skipped). The pair is decoded as one
text, and only the last and first ``JOIN_WINDOW`` characters of the two lines are joined. Only a
match that crosses the join counts, and it is reported on the first line of the pair.

What ``tree`` scans: every tracked file and every untracked file that is not ignored
(``git ls-files -co --exclude-standard``), the name of each such file and of every directory
above it (each name alone, and its path from the root, for a compound across directories), and
the target of each symlink (a link is never followed). Contents are decoded as UTF-8 (with or
without a BOM), UTF-16 or UTF-32 when a BOM says so, and otherwise both as Latin-1 and as UTF-8
with undecodable bytes replaced, so one stray byte does not hide look-alikes and format
characters. A file containing NUL bytes is scanned three ways: as printable ASCII and as
UTF-16LE runs of at least four characters (as ``strings`` would), and as UTF-8 with undecodable
bytes replaced. A file that cannot be read is reported, never skipped. A path stored in Git LFS
(``filter=lfs`` in its attributes) or a file that is an LFS pointer is reported too: its content
is not in the tree, so it cannot be scanned, yet it is published with the repository.

What ``commits`` scans, for each commit that ``git rev-list REV...`` lists: its author and
committer names and emails, its subject and body, every line its diff adds (renames shown as a
deletion and an addition, so a renamed or copied file's lines are seen; a merge commit's diff
against its first parent) and the path of every file it adds or changes, including empty files.
``--skip-bodies-of NAME`` leaves out the body of each commit whose author name is ``NAME``
(the CI passes ``dependabot[bot]``: such a body is upstream release notes, not this repository's
text); its subject, diff and paths are still scanned.

Usage::

    python3 -I scripts/name_guard.py tree [ROOT]             # exit 1 on a hit
    python3 -I scripts/name_guard.py commits origin/main..HEAD
    python3 -I scripts/name_guard.py text --label pr-title < title.txt

Exit status: 0 clean, 1 hits, 2 no usable denylist, or the tree or the commits could not be
listed. The script needs only the standard library, so CI runs it with ``python3 -I`` and
installs nothing in the job that holds the list.
"""

from __future__ import annotations

import argparse
import bisect
import functools
import hashlib
import html
import os
import re
import subprocess
import sys
import unicodedata
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote

ENV_TEXT = "TUISKU_DENYLIST"
ENV_FILE = "TUISKU_DENYLIST_FILE"

# Lines of merged migration revisions that still hold a name in a comment or docstring. Merged
# revisions are never edited (AGENTS.md), so each such line is excepted exactly: by path, line
# number and the SHA-256 of the whole line as decoded (without its line ending). The digest is
# of a long line that is already in the tree, so it discloses nothing; if the line moves or
# changes, the entry no longer matches and the guard reports it as stale. Only lines under
# migrations/versions/ may be listed here.
_DECLARATION_COMMENT = "917d3ef40119b35041cd120e385b86d655f9b280e96082778b6c430c3541ffdc"
TREE_EXCEPTIONS: frozenset[tuple[str, int, str]] = frozenset(
    {
        ("migrations/versions/20261101_0001_evidence_store.py", 28, _DECLARATION_COMMENT),
        ("migrations/versions/20261102_0002_rules_findings_incidents.py", 26, _DECLARATION_COMMENT),
        (  # the module docstring
            "migrations/versions/20261113_0003_otlp_logs_transport.py",
            13,
            "3cacca3e1c8466e26f30485edbe2301b6c7a4ab75ecbb0dd79aa04a4e879bd68",
        ),
        ("migrations/versions/20261113_0003_otlp_logs_transport.py", 32, _DECLARATION_COMMENT),
        ("migrations/versions/20261113_0004_export_queue.py", 50, _DECLARATION_COMMENT),
    }
)

_WORD = re.compile(r"[^\W_]+(?:[-_.][^\W_]+)*")
_ASCII_RUN = re.compile(rb"[\x20-\x7e\t]{4,}")
_UTF16LE_RUN = re.compile(rb"(?:[\x20-\x7e\t]\x00){4,}")
_JSON_ESCAPE = re.compile(r"\\u([0-9a-fA-F]{4})")
_HYPHENS = ("-", "\u00ad", "\u2010", "\u2011")  # a word broken at the end of a line
# What may start the line that continues a hyphenated word: indentation, comment and quote marks.
_CONTINUATION = re.compile(r"^[\s#/*>;+\"'`-]*")
_CLOSING_QUOTES = "\"'`"  # may follow the hyphen at the end of a line
# Private-use characters, never word characters. _BLANK stands for an allowed word (a real one in
# the text is read as a space first); _JOIN marks where two lines are joined.
_BLANK = "\ue000"
_JOIN = "\ue001"
MAX_DECODED_LINE = 4096  # longer lines are checked as written only, not decoded
MAX_VARIANTS = 8  # forms of a line, including the line as written
MAX_JOIN_VARIANTS = 4  # forms of a joined pair: as written, and each decoding applied once
JOIN_WINDOW = 256  # characters of each line kept on either side of a join
LFS_POINTERS = (
    b"version https://git-lfs.github.com/spec/",
    b"version https://hawser.github.com/spec/",
)

# Lowercase look-alikes of Latin letters (applied after casefolding).
_HOMOGLYPHS = str.maketrans(
    {
        "\u0430": "a",  # Cyrillic а
        "\u0435": "e",  # Cyrillic е
        "\u043e": "o",  # Cyrillic о
        "\u0440": "p",  # Cyrillic р
        "\u0441": "c",  # Cyrillic с
        "\u0443": "y",  # Cyrillic у
        "\u0445": "x",  # Cyrillic х
        "\u0456": "i",  # Cyrillic і
        "\u0458": "j",  # Cyrillic ј
        "\u0455": "s",  # Cyrillic ѕ
        "\u043a": "k",  # Cyrillic к
        "\u043c": "m",  # Cyrillic м
        "\u0442": "t",  # Cyrillic т
        "\u043d": "h",  # Cyrillic н
        "\u0432": "b",  # Cyrillic в
        "\u0451": "e",  # Cyrillic ё
        "\u0501": "d",  # Cyrillic ԁ
        "\u04bb": "h",  # Cyrillic һ
        "\u04af": "y",  # Cyrillic ү
        "\u03bf": "o",  # Greek ο
        "\u03b1": "a",  # Greek α
        "\u03b5": "e",  # Greek ε
        "\u03b9": "i",  # Greek ι
        "\u03ba": "k",  # Greek κ
        "\u03bd": "v",  # Greek ν
        "\u03c1": "p",  # Greek ρ
        "\u03c4": "t",  # Greek τ
        "\u03c5": "u",  # Greek υ
        "\u03c7": "x",  # Greek χ
        "\u0585": "o",  # Armenian օ
        "\u0131": "i",  # Latin dotless ı
        "\u0251": "a",  # Latin ɑ
        "\u0261": "g",  # Latin ɡ
        "\u028b": "v",  # Latin ʋ
        "\u04c0": "l",  # Cyrillic Ӏ (palochka; casefolds to ӏ, listed for clarity)
        "\u04cf": "l",  # Cyrillic ӏ
        "\u0475": "v",  # Cyrillic ѵ
    }
)
# Letters and symbols that render as blank space, dropped like format characters: the Hangul
# fillers and the blank braille pattern (NFKC maps U+3164 and U+FFA0 to U+1160).
_BLANK_FILLERS = "\u115f\u1160\u3164\uffa0\u2800"


class DenylistError(Exception):
    """No usable denylist: unset, empty or malformed. The message never quotes an entry."""


@dataclass(frozen=True)
class Denylist:
    terms: tuple[str, ...]
    compounds: tuple[re.Pattern[str], ...]
    allowed: frozenset[str]
    prefixes: tuple[str, ...] = ()


@dataclass(frozen=True, order=True)
class Hit:
    """Where a name was found, or something that cannot be scanned. ``line`` is 0 for a hit in a
    path or a symlink target, an unreadable file and a file in Git LFS."""

    path: str
    line: int
    kind: str = "content"  # "content", "path", "symlink", "unreadable" or "lfs"
    text_sha256: str = ""  # of the whole decoded line, for exceptions; empty when not a line

    def describe(self) -> str:
        if self.kind == "content":
            return f"{self.path}:{self.line}"
        return f"{self.path} ({self.kind})"


# --- normalisation ----------------------------------------------------------------------------


@functools.cache
def _category_patterns() -> dict[str, re.Pattern[str]]:
    """Character classes of what is dropped, built once per process: format characters (Cf)
    with the blank fillers, and nonspacing marks (Mn)."""
    codes: dict[str, list[int]] = {"Cf": [], "Mn": []}
    for code in range(0x110000):
        found = codes.get(unicodedata.category(chr(code)))
        if found is not None:
            found.append(code)
    codes["Cf"] = sorted({*codes["Cf"], *map(ord, _BLANK_FILLERS)})
    patterns: dict[str, re.Pattern[str]] = {}
    for category, members in codes.items():
        ranges: list[str] = []
        start = prev = members[0]
        for code in [*members[1:], -1]:
            if code != prev + 1:
                ranges.append(re.escape(chr(start)) + "-" + re.escape(chr(prev)))
                start = code
            prev = code
        patterns[category] = re.compile("[" + "".join(ranges) + "]")
    return patterns


def _drop(text: str, category: str) -> str:
    return _category_patterns()[category].sub("", text)


def _clean(text: str, fold: bool) -> str:
    """NFKC without format characters; accent-folded too when ``fold``. Case is kept, so that
    camelCase parts can still be told apart."""
    if text.isascii():  # NFKC, format characters and marks are all non-ASCII
        return text
    text = _drop(unicodedata.normalize("NFKC", text), "Cf")
    if fold:
        text = _drop(unicodedata.normalize("NFKD", text), "Mn")
    return text


def _lower_char(ch: str, fold: bool) -> str:
    out = ch.casefold()
    if fold and not out.isascii():
        out = _drop(unicodedata.normalize("NFKD", out), "Mn")
    return out.translate(_HOMOGLYPHS)


class _Text:
    """A cleaned line (``raw``, case kept) and the lowercase ``text`` that entries are matched
    in, with the positions of ``raw`` mapped to those of ``text`` (casefolding and folding can
    change lengths)."""

    def __init__(self, raw: str, fold: bool) -> None:
        self.raw = raw
        self._offsets: list[int] | None = None
        self._starts: frozenset[int] | None = None
        self._ends: frozenset[int] | None = None
        if raw.isascii():
            self.text = raw.lower()
            return
        # Casefolding maps each character to one or more, so a result of the same length maps
        # each character to exactly one, and positions are unchanged.
        whole = raw.casefold()
        if fold and len(whole) == len(raw) and not whole.isascii():
            whole = _drop(unicodedata.normalize("NFKD", whole), "Mn")
        if len(whole) == len(raw):
            self.text = whole.translate(_HOMOGLYPHS)
            return
        pieces = [_lower_char(ch, fold) for ch in raw]
        self.text = "".join(pieces)
        if len(self.text) != len(raw) or any(len(p) != 1 for p in pieces):
            offsets = [0]
            for piece in pieces:
                offsets.append(offsets[-1] + len(piece))
            self._offsets = offsets

    def at(self, index: int) -> int:
        """The position in ``text`` of position ``index`` of ``raw``."""
        return index if self._offsets is None else self._offsets[index]

    def _boundaries(self) -> None:
        raw, n = self.raw, len(self.raw)
        starts: set[int] = set()
        ends: set[int] = set()
        for i, ch in enumerate(raw):
            if not ch.isalnum():
                continue
            prev = raw[i - 1] if i else ""
            if (
                not prev.isalnum()
                or (prev.islower() and ch.isupper())
                or (prev.isupper() and ch.isupper() and i + 1 < n and raw[i + 1].islower())
                or (prev.isdigit() != ch.isdigit())
            ):
                starts.add(self.at(i))
                if prev.isalnum():
                    ends.add(self.at(i))
            if i + 1 == n or not raw[i + 1].isalnum():
                ends.add(self.at(i + 1))
        self._starts, self._ends = frozenset(starts), frozenset(ends)

    @property
    def starts(self) -> frozenset[int]:
        """Positions in ``text`` where a part of a word starts (see the module docstring)."""
        if self._starts is None:
            self._boundaries()
        assert self._starts is not None
        return self._starts

    @property
    def ends(self) -> frozenset[int]:
        """Positions in ``text`` just after a part of a word ends."""
        if self._ends is None:
            self._boundaries()
        assert self._ends is not None
        return self._ends


def normalize(text: str, fold: bool = False) -> str:
    """The form a line, or an entry, is matched in."""
    return _Text(_clean(text, fold), fold).text


def _json_unescape(text: str) -> str:
    out = _JSON_ESCAPE.sub(lambda m: chr(int(m.group(1), 16)), text)
    if any("\ud800" <= ch <= "\udfff" for ch in out):  # a surrogate pair, or a lone half
        out = out.encode("utf-16-le", "surrogatepass").decode("utf-16-le", "replace")
    return out


_DECODERS = (unquote, html.unescape, _json_unescape)


def _variants(line: str, limit: int = MAX_VARIANTS) -> list[str]:
    """The line and its decoded forms: up to three rounds of percent-decoding, HTML unescaping
    and JSON unescaping, in any order, breadth first, at most ``limit`` in all. A line longer
    than ``MAX_DECODED_LINE`` is not decoded."""
    if len(line) > MAX_DECODED_LINE or ("%" not in line and "&" not in line and "\\" not in line):
        return [line]
    found = [line]
    frontier = [line]
    for _ in range(3):
        nxt: list[str] = []
        for text in frontier:
            for decode in _DECODERS:
                out = decode(text)
                if out not in found:
                    found.append(out)
                    nxt.append(out)
                    if len(found) >= limit:
                        return found
        frontier = nxt
    return found


def _folds(*texts: str) -> tuple[bool, ...]:
    return (False,) if all(t.isascii() for t in texts) else (False, True)


# --- the list ---------------------------------------------------------------------------------


def parse_denylist(text: str) -> Denylist:
    terms: dict[str, None] = {}
    prefixes: dict[str, None] = {}
    compounds: dict[str, re.Pattern[str]] = {}
    allowed: set[str] = set()
    for number, raw in enumerate(text.splitlines(), start=1):
        entry = raw.strip()
        if not entry or entry.startswith("#"):
            continue
        marker = entry[0] if entry[0] in "!^" else ""
        body = entry[len(marker) :].strip()
        for form in dict.fromkeys(normalize(body, fold) for fold in (False, True)):
            parts = form.split()
            if marker == "!":
                if len(parts) != 1 or not _WORD.fullmatch(form):
                    raise DenylistError(f"denylist line {number}: '!' needs one word")
                allowed.add(form)
            elif marker == "^":
                if len(parts) != 1 or not _WORD.fullmatch(form):
                    raise DenylistError(f"denylist line {number}: '^' needs one word")
                prefixes[form] = None
            elif len(parts) > 1:
                if not all(_WORD.fullmatch(part) for part in parts):
                    raise DenylistError(f"denylist line {number}: a compound is words only")
                key = " ".join(parts)
                compounds[key] = re.compile(r"[\W_]*".join(re.escape(p) for p in parts))
            else:
                if not _WORD.fullmatch(form):
                    raise DenylistError(f"denylist line {number}: a term is one word")
                terms[form] = None
    if not terms and not prefixes and not compounds:
        raise DenylistError("the denylist has no entries")
    return Denylist(tuple(terms), tuple(compounds.values()), frozenset(allowed), tuple(prefixes))


def denylist_from_env(environ: dict[str, str] | None = None) -> Denylist | None:
    """The list from ``TUISKU_DENYLIST`` or ``TUISKU_DENYLIST_FILE``; None when neither is set
    to a non-empty value (an unavailable CI secret arrives as an empty string)."""
    env = os.environ if environ is None else environ
    text = env.get(ENV_TEXT, "")
    path = env.get(ENV_FILE, "").strip()
    if text.strip():
        return parse_denylist(text)
    if path:
        try:
            return parse_denylist(Path(path).read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError) as exc:
            raise DenylistError(f"{ENV_FILE} cannot be read ({type(exc).__name__})") from None
    return None


# --- matching ---------------------------------------------------------------------------------


def _occurrences(text: str, word: str) -> Iterator[int]:
    i = text.find(word)
    while i >= 0:
        yield i
        i = text.find(word, i + 1)


def _blank_allowed(line: _Text, text: str, allowed: frozenset[str]) -> str:
    """``text`` (``line.text``, without real blanks) with each allowed word that is a whole word
    or whole parts of one blanked."""
    for word in allowed:
        if word not in text:
            continue
        for i in _occurrences(line.text, word):
            j = i + len(word)
            if i in line.starts and j in line.ends:
                text = text[:i] + _BLANK * len(word) + text[j:]
    return text


def _spans(line: _Text, denylist: Denylist, compounds_only: bool = False) -> Iterator[range]:
    """Where entries match in ``line.text`` (see the module docstring)."""
    text = line.text.replace(_BLANK, " ")  # a real blank is not an allowed word
    if denylist.allowed:
        text = _blank_allowed(line, text, denylist.allowed)
    for pattern in denylist.compounds:
        pos = 0
        while m := pattern.search(text, pos):
            if _BLANK not in m.group(0):  # a blanked allowed word never completes a compound
                yield range(m.start(), m.end())
            pos = m.start() + 1
    if compounds_only:
        return
    for term in denylist.terms:
        for i in _occurrences(text, term):
            yield range(i, i + len(term))
    for prefix in denylist.prefixes:
        for i in _occurrences(text, prefix):
            if i in line.starts:
                yield range(i, i + len(prefix))


def line_matches(line: str, denylist: Denylist) -> bool:
    """Whether a line holds a listed name, in any of the forms the module docstring lists."""
    for variant in _variants(line):
        for fold in _folds(variant):
            if any(True for _ in _spans(_Text(_clean(variant, fold), fold), denylist)):
                return True
    return False


def _crosses(line: _Text, join: int, denylist: Denylist, compounds_only: bool) -> bool:
    at = line.at(join)
    return any(s.start < at < s.stop for s in _spans(line, denylist, compounds_only))


def _hyphenated(line: str) -> str | None:
    """``line`` without the hyphen (and closing quotes) it ends with, or None."""
    text = line.rstrip().rstrip(_CLOSING_QUOTES)
    return text[:-1] if text.endswith(_HYPHENS) else None


def _join_matches(head: str, tail: str, sep: str, denylist: Denylist, compounds_only: bool) -> bool:
    """Whether a match crosses the join of ``head`` and ``tail`` (with ``sep`` between them). The
    two are decoded as one text, with the join marked by ``_JOIN`` so that it is found again; a
    decoded form that holds another ``_JOIN`` is skipped."""
    head = head[-JOIN_WINDOW:].replace(_JOIN, " ")
    tail = tail[:JOIN_WINDOW].replace(_JOIN, " ")
    for joined in _variants(head + _JOIN + tail, MAX_JOIN_VARIANTS):
        parts = joined.split(_JOIN)
        if len(parts) != 2:
            continue
        for fold in _folds(*parts):
            left = _clean(parts[0], fold)
            text = _Text(left + sep + _clean(parts[1], fold), fold)
            if _crosses(text, len(left), denylist, compounds_only):
                return True
    return False


def lines_match_across(first: str, second: str, denylist: Denylist) -> bool:
    """Whether a name is split between two consecutive lines: across the line break, or as a
    word hyphenated at the end of ``first``. Matches within one line alone do not count."""
    if denylist.compounds and _join_matches(first, second, "\n", denylist, compounds_only=True):
        return True
    head = _hyphenated(first)
    if head is None:
        return False
    tail = _CONTINUATION.sub("", second, count=1)
    return _join_matches(head, tail, "", denylist, compounds_only=False)


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()


# --- files ------------------------------------------------------------------------------------


def _runs(data: bytes) -> list[list[tuple[int, str]]]:
    """A file with NUL bytes: its printable ASCII runs, its UTF-16LE runs and its UTF-8 lines."""
    newlines = [m.start() for m in re.finditer(rb"\n", data)]

    def number(offset: int) -> int:
        return bisect.bisect_left(newlines, offset) + 1

    ascii_runs = [
        (number(m.start()), m.group(0).decode("ascii")) for m in _ASCII_RUN.finditer(data)
    ]
    utf16_runs = [
        (number(m.start()), m.group(0).decode("utf-16-le")) for m in _UTF16LE_RUN.finditer(data)
    ]
    return [ascii_runs, utf16_runs, _lines(data.decode("utf-8", errors="replace"))]


def _lines(text: str) -> list[tuple[int, str]]:
    return [(n, line.removesuffix("\r")) for n, line in enumerate(text.split("\n"), start=1)]


def decode(data: bytes) -> list[list[tuple[int, str]]]:
    """A file's contents as sequences of ``(line number, text)``; consecutive entries of a
    sequence are checked as pairs too. See the module docstring."""
    for bom, codec in (
        (b"\xff\xfe\x00\x00", "utf-32"),
        (b"\x00\x00\xfe\xff", "utf-32"),
        (b"\xff\xfe", "utf-16"),
        (b"\xfe\xff", "utf-16"),
        (b"\xef\xbb\xbf", "utf-8-sig"),
    ):
        if data.startswith(bom):
            return [_lines(data.decode(codec, errors="replace"))]
    if b"\0" in data:
        return _runs(data)
    try:
        return [_lines(data.decode("utf-8"))]
    except UnicodeDecodeError:  # Latin-1, and UTF-8 around the bytes that are not
        return [_lines(data.decode("latin-1")), _lines(data.decode("utf-8", errors="replace"))]


def scan_bytes(label: str, data: bytes, denylist: Denylist) -> list[Hit]:
    """Hits in one file's contents (or in text read from standard input), reported as ``label``,
    at most one per line number."""
    found: dict[int, str] = {}
    for sequence in decode(data):
        for k, (number, line) in enumerate(sequence):
            if number in found:
                continue
            if line_matches(line, denylist) or (
                k + 1 < len(sequence) and lines_match_across(line, sequence[k + 1][1], denylist)
            ):
                found[number] = line
    return [Hit(label, number, "content", _sha256(line)) for number, line in sorted(found.items())]


def list_paths(root: Path) -> list[str]:
    """Tracked files and untracked files that are not ignored, relative to ``root``, without
    files deleted from the working tree. Raises when ``root`` is not in a git work tree."""

    def git(*args: str) -> set[str]:
        out = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z", *args],
            check=True,
            capture_output=True,
        ).stdout
        return {p for p in out.decode("utf-8", "surrogateescape").split("\0") if p}

    return sorted(git("--cached", "--others", "--exclude-standard") - git("--deleted"))


def _path_names(paths: Iterable[str]) -> Iterator[str]:
    """Every listed path and every directory above one, each once."""
    seen: set[str] = set()
    for path in paths:
        parts = path.split("/")
        for i in range(1, len(parts) + 1):
            prefix = "/".join(parts[:i])
            if prefix not in seen:
                seen.add(prefix)
                yield prefix


def lfs_paths(root: Path, paths: Iterable[str]) -> list[str]:
    """The paths whose ``filter`` attribute is ``lfs`` (``.gitattributes`` and the repository's
    own attribute files, as ``git check-attr`` reads them). Raises when git fails."""
    listed = "".join(f"{path}\0" for path in paths).encode("utf-8", "surrogateescape")
    out = subprocess.run(
        ["git", "-C", str(root), "check-attr", "-z", "--stdin", "filter"],
        input=listed,
        check=True,
        capture_output=True,
    ).stdout
    fields = out.decode("utf-8", "surrogateescape").split("\0")
    triples = zip(fields[0::3], fields[1::3], fields[2::3], strict=False)
    return sorted({path for path, _, value in triples if value == "lfs"})


def _path_hits(paths: Iterable[str], denylist: Denylist) -> list[Hit]:
    """Each file or directory whose name matches, or whose path from the root matches across a
    ``/`` where its parent's path does not (a compound split between directories)."""
    hits: list[Hit] = []
    whole: dict[str, bool] = {}
    for name in _path_names(paths):
        parent, _, last = name.rpartition("/")
        whole[name] = line_matches(name, denylist) if parent else line_matches(last, denylist)
        if line_matches(last, denylist) or (parent and whole[name] and not whole[parent]):
            hits.append(Hit(name, 0, "path"))
    return hits


def scan_tree(root: Path, paths: Iterable[str], denylist: Denylist) -> list[Hit]:
    """Hits in the names, symlink targets and contents of ``paths`` (relative to ``root``), and
    files that are Git LFS pointers. ``scan_repo`` adds the paths stored in LFS."""
    paths = list(paths)
    hits = _path_hits(paths, denylist)
    for rel in paths:
        full = root / rel
        if full.is_symlink():
            if line_matches(os.readlink(full), denylist):
                hits.append(Hit(rel, 0, "symlink"))
            continue
        if full.is_dir():  # a submodule: its name is scanned above, its tree is its own
            continue
        try:
            data = full.read_bytes()
        except OSError:
            hits.append(Hit(rel, 0, "unreadable"))
            continue
        if data.startswith(LFS_POINTERS):
            hits.append(Hit(rel, 0, "lfs"))
        hits.extend(scan_bytes(rel, data, denylist))
    return sorted(set(hits))


def scan_repo(root: Path, denylist: Denylist) -> list[Hit]:
    """``scan_tree`` over ``list_paths(root)``, plus each path stored in Git LFS. Raises when git
    fails."""
    paths = list_paths(root)
    hits = scan_tree(root, paths, denylist)
    hits.extend(Hit(path, 0, "lfs") for path in lfs_paths(root, paths))
    return sorted(set(hits))


def _git(root: Path, *args: str) -> bytes:
    return subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True).stdout


_SHOW = ("show", "--no-color", "--no-ext-diff", "--no-textconv", "--no-renames")
_SHOW += ("--diff-merges=first-parent", "--format=")


def scan_commits(
    root: Path, revs: list[str], denylist: Denylist, skip_bodies_of: frozenset[str] = frozenset()
) -> list[Hit]:
    """Hits in the commits ``git rev-list REV...`` lists, each reported under its abbreviated id
    with ``message``, ``diff`` (the added lines) or ``paths`` and a line number in that text.
    See the module docstring. Raises when git fails."""
    shas = _git(root, "rev-list", "--end-of-options", *revs).decode("ascii").split()
    hits: list[Hit] = []
    for sha in shas:
        short = sha[:12]
        meta = _git(root, "show", "-s", "--format=%an%x00%ae%x00%cn%x00%ce%x00%s%x00%b", sha)
        author, author_email, committer, committer_email, subject, body = meta.split(b"\0", 5)
        text = b"\n".join((author, author_email, committer, committer_email, subject))
        if author.decode("utf-8", "replace") not in skip_bodies_of:
            text += b"\n" + body
        hits.extend(scan_bytes(f"commit {short} message", text, denylist))
        patch = _git(root, *_SHOW, "--patch", "--text", sha)
        added = [line for line in patch.split(b"\n") if line.startswith(b"+")]
        hits.extend(scan_bytes(f"commit {short} diff", b"\n".join(added), denylist))
        if any(line[1:].startswith(LFS_POINTERS) for line in added):
            hits.append(Hit(f"commit {short} diff", 0, "lfs"))
        listed = _git(root, *_SHOW, "--name-only", "-z", "--diff-filter=d", sha)
        names = [p.decode("utf-8", "surrogateescape") for p in listed.split(b"\0") if p]
        for number, name in enumerate(names, start=1):
            if line_matches(name, denylist):
                hits.append(Hit(f"commit {short} paths", number, "content"))
    return hits


def check(
    hits: Iterable[Hit], exceptions: frozenset[tuple[str, int, str]] = frozenset()
) -> tuple[list[str], list[str]]:
    """``(offending, stale)``: hits not excepted, and exceptions that matched no hit. Each is a
    ``path:line``, or a path with its kind; neither quotes a line or a term."""
    offending: list[str] = []
    used: set[tuple[str, int, str]] = set()
    for hit in hits:
        key = (hit.path, hit.line, hit.text_sha256)
        if hit.kind == "content" and key in exceptions:
            used.add(key)
        else:
            offending.append(hit.describe())
    stale = [f"{path}:{line}" for path, line, _ in sorted(exceptions - used)]
    return offending, stale


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Find internal names in a git work tree or in standard input. The denylist "
        f"comes from {ENV_TEXT} (its text) or {ENV_FILE} (a path)."
    )
    sub = parser.add_subparsers(dest="command", required=True)
    tree = sub.add_parser("tree", help="scan the files and paths of a git work tree")
    tree.add_argument("root", nargs="?", default=".")
    commits = sub.add_parser("commits", help="scan the commits that git rev-list lists")
    commits.add_argument("revs", nargs="+", metavar="REV", help="e.g. base..head, or sha^!")
    commits.add_argument("--root", default=".", help="the repository (default: .)")
    commits.add_argument(
        "--skip-bodies-of",
        action="append",
        default=[],
        metavar="NAME",
        help="leave out the message body of commits whose author name is NAME",
    )
    text = sub.add_parser("text", help="scan standard input, e.g. a pull request title")
    text.add_argument("--label", default="stdin", help="name to report hits under")
    args = parser.parse_args(argv)

    try:
        denylist = denylist_from_env()
    except DenylistError as exc:
        print(f"name_guard: {exc}", file=sys.stderr)
        return 2
    if denylist is None:
        print(f"name_guard: set {ENV_TEXT} or {ENV_FILE}", file=sys.stderr)
        return 2

    if args.command in ("tree", "commits"):
        root = Path(args.root)
        try:
            if args.command == "tree":
                offending, stale = check(scan_repo(root, denylist), TREE_EXCEPTIONS)
            else:
                skip = frozenset(args.skip_bodies_of)
                offending, stale = check(scan_commits(root, args.revs, denylist, skip))
        except (OSError, subprocess.CalledProcessError) as exc:
            print(f"name_guard: git failed in {root} ({type(exc).__name__})", file=sys.stderr)
            return 2
    else:
        offending, stale = check(scan_bytes(args.label, sys.stdin.buffer.read(), denylist))

    for where in offending:
        lfs = where.endswith(" (lfs)")
        print(f"{'stored in Git LFS, cannot be scanned' if lfs else 'internal name'}: {where}")
    for where in stale:
        print(f"stale exception: {where}")
    if offending or stale:
        print(
            "name_guard: replace each name with the role it stands for (AGENTS.md, "
            "'This repository is public')",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
