"""No internal name of a deploying organisation appears in the tree (AGENTS.md, ADR 0013).

The scanner is ``scripts/name_guard.py``. Its denylist is never in this repository: it comes from
``TUISKU_DENYLIST`` or ``TUISKU_DENYLIST_FILE``. In CI the ``name-guard-tree`` job decodes the
secret ``TUISKU_DENYLIST_B64`` into a file and runs ``python3 -I scripts/name_guard.py tree``
(the same scan as the tree test, with only the standard library, so no dependency's code runs
where the list is). The ``test`` job, which has no list, deselects the tree test; if the test is
renamed and the deselect stops matching, it skips there and CI=true turns the skip into a
failure (tests/conftest.py). Locally, without a list, it skips.

A report never quotes a matched line or a term on its own; a hit in a file or directory name
shows that path, since the path is where the hit is. Every other test here uses a synthetic list
of made-up words.
"""

from __future__ import annotations

import hashlib
import importlib.util
import io
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

from tests.conftest import REPO_ROOT


def _load_name_guard():
    path = REPO_ROOT / "scripts" / "name_guard.py"
    spec = importlib.util.spec_from_file_location("name_guard", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["name_guard"] = module  # dataclasses look their module up
    spec.loader.exec_module(module)
    return module


ng = _load_name_guard()

SYNTHETIC = """# synthetic test list
zorblat
quux frob
!zorblatter
"""
TERMS = ("zorblat", "quux", "frob")


@pytest.fixture
def denylist():
    return ng.parse_denylist(SYNTHETIC)


# --- the tree --------------------------------------------------------------------------------


def test_tree_has_no_internal_names() -> None:
    denylist = ng.denylist_from_env()
    if denylist is None:
        pytest.skip(f"{ng.ENV_TEXT} / {ng.ENV_FILE} not set (the list is private, ADR 0013)")
    offending, stale = ng.check(ng.scan_repo(REPO_ROOT, denylist), ng.TREE_EXCEPTIONS)
    assert not offending, (
        "internal names in a public repository; replace each with the role it stands for "
        "(AGENTS.md, 'This repository is public'):\n" + "\n".join(offending)
    )
    assert not stale, "exceptions that no longer match a line; remove them:\n" + "\n".join(stale)


def test_exceptions_are_lines_of_merged_revisions_only() -> None:
    for path, line, digest in ng.TREE_EXCEPTIONS:
        assert path.startswith("migrations/versions/") and path.endswith(".py")
        assert (REPO_ROOT / path).is_file()
        assert line > 0 and len(digest) == 64


# --- matching ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "line",
    [
        "the zorblat service",
        "Zorblat",
        "ZORBLATS and more",
        "zorblatissa (inflected)",
        "zorblat-x",
        "Foo_Zorblat",
        "MyZorblat42x",
        "zorblat42x",
        "quuxfrob.example",
        "zorblatclient",
        "api.zorblat.example",
        "quux frob",
        "quux-frob",
        "Quux_Frob",
        "quux.frob",
        "QuuxFrob",
        "quux -- frob",
        "the quuxfrobber",
        "zor\u200bblat",  # zero-width space
        "zor\u00adblat",  # soft hyphen
        "zor\u2060blat",  # word joiner
        "\ufeffzorblat",
        "quux\u200dfrob",
        "z\u043erbl\u0430t",  # Cyrillic o and a
        "Z\u041eRBL\u0410T",  # Cyrillic capitals casefold, then map
        "z\u03bfrblat",  # Greek omicron
        "\uff5a\uff4f\uff52\uff42\uff4c\uff41\uff54",  # fullwidth
        "zor%62lat",
        "%7Aorblat",
        "quux%20frob",
        "zor&#98;lat",
        "zor&#x62;lat",
        "quux&nbsp;frob",
        "zorblatters",  # not the allowed word itself
        "MyZorblatters",
        "myzorblatter",  # the allowed word inside a part is not the allowed word
        # accent folding (NFKD without nonspacing marks)
        "zorbl\u00e1t",
        "zorbla\u0301t",
        "ZORBL\u00c1T",
        "z\u00f6rbl\u00e4t",
        "quux fr\u00f6b",
        # look-alikes added to the table
        "z\u0585rblat",  # Armenian oh
        "zorbl\u0251t",  # Latin alpha
        # JSON escapes and double percent-encoding
        "zor\\u0062lat",
        "\\u007Aorblat",
        "quux\\u0020frob",
        "zor%2562lat",
        "zor%26%2398%3Blat",  # an HTML escape, percent-encoded
    ],
)
def test_line_matches(denylist, line: str) -> None:
    assert ng.line_matches(line, denylist)


@pytest.mark.parametrize(
    "line",
    [
        "",
        "nothing to see",
        "zorbla t",
        "zorb-lat",
        "quux alone",
        "frob alone",
        "frob quux",
        "zorblatter",  # allowed whole word
        "the Zorblatter-x and zorblatter_y",  # allowed word as a joined part
        "zorblatter&amp;zorblatter",
        "MyZorblatter and zorblatterThing",  # allowed word as camelCase parts
        "ZORBLATTER42 and 7Zorblatter",  # and as letter/digit parts
        "zorbl\u00e4tter",  # allowed word, accent-folded
    ],
)
def test_line_does_not_match(denylist, line: str) -> None:
    assert not ng.line_matches(line, denylist)


def test_a_term_may_hold_joiners() -> None:
    joined = ng.parse_denylist("zorb.lat\n")
    assert ng.line_matches("https://api.zorb.lat.example/x", joined)
    assert ng.line_matches("ZORB.LATS", joined)
    assert not ng.line_matches("zorb lat", joined)
    assert not ng.line_matches("zorb-lat", joined)


PREFIXED = ng.parse_denylist("^frob\n!frobnicate\n")


@pytest.mark.parametrize(
    "line",
    [
        "frob",
        "the Frobs",
        "FROBBING",
        "x-frobber",
        "my_frob",
        "a.frobbed.example",
        "myFrobber",
        "HTTPFrobber",  # an acronym, then a part
        "frob42",
        "7frobs",
        "fr\u00f6bs",  # accent-folded
        "frobnicates",  # not the allowed word itself
        "frobnicate frobs",
    ],
)
def test_prefix_matches_the_start_of_a_word_or_part(line: str) -> None:
    assert ng.line_matches(line, PREFIXED)


@pytest.mark.parametrize(
    "line",
    ["", "afrob", "unfrobbed", "re-unfrob", "myfrobber", "frobnicate", "theFrobnicate-x"],
)
def test_prefix_does_not_match_inside_a_part(line: str) -> None:
    assert not ng.line_matches(line, PREFIXED)


def test_an_allowed_word_does_not_complete_a_compound() -> None:
    denylist = ng.parse_denylist("quux frob\n!qxq\n")
    assert not ng.line_matches("quux-qxq-frob", denylist)
    assert not ng.line_matches("quux qxq frob", denylist)
    assert not ng.line_matches("quuxQxqFrob", denylist)
    assert ng.line_matches("quux-qxq-frob and quux-frob", denylist)  # a later match counts


@pytest.mark.parametrize(
    "lookalike", ["\u0131", "\u0585", "\u0501", "\u04bb", "\u04af", "\u0251", "\u0261"]
)
def test_added_lookalikes(lookalike: str) -> None:
    denylist = ng.parse_denylist("dhyogai\n")
    for i, letter in enumerate("dhyogai"):
        if ng.normalize(lookalike) == letter:
            assert ng.line_matches("dhyogai"[:i] + lookalike + "dhyogai"[i + 1 :], denylist)
            return
    pytest.fail("the look-alike maps to no letter of the test word")


@pytest.mark.parametrize(
    ("lookalike", "letter"),
    [("\u04cf", "l"), ("\u04c0", "l"), ("\u0475", "v"), ("\u028b", "v")],
)
def test_more_lookalikes(lookalike: str, letter: str) -> None:
    denylist = ng.parse_denylist("zevlak\n")
    word = "zevlak".replace(letter, lookalike)
    assert word != "zevlak"
    assert ng.line_matches(word, denylist)
    assert ng.line_matches(word.upper(), denylist)


@pytest.mark.parametrize("filler", ["\u115f", "\u1160", "\u3164", "\uffa0", "\u2800"])
def test_blank_fillers_are_dropped_like_format_characters(denylist, filler: str) -> None:
    assert ng.line_matches(f"zor{filler}blat", denylist)
    assert ng.line_matches(f"quux{filler}frob", denylist)
    assert ng.normalize(f"a{filler}b") == "ab"


def test_an_accented_entry_matches_plain_and_accented_text() -> None:
    denylist = ng.parse_denylist("z\u00f6rbl\u00e4t\n")
    for line in ("zorblat", "Z\u00d6RBL\u00c4T", "zo\u0308rbla\u0308t"):
        assert ng.line_matches(line, denylist)


def test_parse_denylist_rejects_bad_prefixes() -> None:
    for text in ("^two words\n", "^\n", "^zor/blat\n"):
        with pytest.raises(ng.DenylistError) as exc:
            ng.parse_denylist(text)
        assert "line 1" in str(exc.value) and "blat" not in str(exc.value)
    assert ng.parse_denylist("^frob\n").prefixes == ("frob",)


def test_parse_denylist_rejects_bad_lists() -> None:
    for text in ("", "# only a comment\n\n", "!zorblatter\n"):
        with pytest.raises(ng.DenylistError, match="no entries"):
            ng.parse_denylist(text)
    with pytest.raises(ng.DenylistError) as exc:
        ng.parse_denylist("zorblat\n!two words\n")
    assert "line 2" in str(exc.value) and "two" not in str(exc.value)
    with pytest.raises(ng.DenylistError) as exc:
        ng.parse_denylist("zor/blat\n")
    assert "line 1" in str(exc.value) and "blat" not in str(exc.value)


def test_denylist_from_env(tmp_path: Path) -> None:
    assert ng.denylist_from_env({}) is None
    # An unavailable CI secret arrives as an empty string.
    assert ng.denylist_from_env({ng.ENV_TEXT: "", ng.ENV_FILE: "  "}) is None
    assert ng.denylist_from_env({ng.ENV_TEXT: " \n"}) is None
    assert ng.denylist_from_env({ng.ENV_TEXT: SYNTHETIC}).terms == ("zorblat",)
    listed = tmp_path / "list.txt"
    listed.write_text("frob\n", encoding="utf-8")
    assert ng.denylist_from_env({ng.ENV_FILE: str(listed)}).terms == ("frob",)
    with pytest.raises(ng.DenylistError, match=ng.ENV_FILE):
        ng.denylist_from_env({ng.ENV_FILE: str(tmp_path / "missing.txt")})


def test_a_list_file_that_is_not_utf8_is_refused(tmp_path: Path, monkeypatch, capsys) -> None:
    listed = tmp_path / "list.txt"
    listed.write_bytes(b"frob\n\xff\n")
    with pytest.raises(ng.DenylistError, match=ng.ENV_FILE) as exc:
        ng.denylist_from_env({ng.ENV_FILE: str(listed)})
    assert "frob" not in str(exc.value)
    monkeypatch.delenv(ng.ENV_TEXT, raising=False)
    monkeypatch.setenv(ng.ENV_FILE, str(listed))
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(b"frob\n")))
    assert ng.main(["text"]) == 2
    out, err = capsys.readouterr()
    assert out == "" and ng.ENV_FILE in err and "frob" not in err


def test_a_real_blank_character_does_not_hide_a_compound(denylist) -> None:
    # The scanner blanks allowed words with a private-use character; a NUL or that character in
    # the text itself is only a separator, and a compound across it still counts.
    assert ng.line_matches("quux\x00frob", denylist)
    assert ng.line_matches("quux\ue000frob", denylist)
    assert ng.line_matches("the Quux\ue000\x00Frob", denylist)
    assert not ng.line_matches("quux\ue000zorblatter\ue000frob", ng.parse_denylist("quux frob\n"))


# --- files and paths --------------------------------------------------------------------------


def _write(root: Path, rel: str, data: bytes) -> str:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return rel


def _where(hits) -> list[tuple[str, int, str]]:
    return [(h.path, h.line, h.kind) for h in hits]


def test_scan_tree_contents_in_every_encoding(tmp_path: Path, denylist) -> None:
    paths = [
        _write(tmp_path, "clean.txt", b"nothing\nto see\n"),
        _write(tmp_path, "utf8.md", "ok\n\u00e5\u00e4\u00f6 zorblat\n".encode()),
        _write(tmp_path, "latin1.txt", b"caf\xe9\nok\nquux frob\n"),
        # Cyrillic o: not an ASCII run, so only a BOM-aware decode finds it.
        _write(tmp_path, "bom16.txt", "ok\nZ\u043erblat\n".encode("utf-16")),
        _write(tmp_path, "bom16be.txt", b"\xfe\xff" + "zorblat\n".encode("utf-16-be")),
        _write(tmp_path, "bom8.txt", b"\xef\xbb\xbfzorblat\n"),
        _write(tmp_path, "crlf.txt", b"ok\r\nzorblat\r\n"),
        _write(tmp_path, "nul.bin", b"\x00\x01\x02ok\nxx\x00\x00the zorblat\x00\xff"),
        _write(tmp_path, "nul16.bin", b"\x00\x00\n" + "zorblat".encode("utf-16-le")),
        _write(tmp_path, "short.bin", b"\x00zor\x00blat\x00"),  # runs under 4 bytes
    ]
    assert _where(ng.scan_tree(tmp_path, paths, denylist)) == [
        ("bom16.txt", 2, "content"),
        ("bom16be.txt", 1, "content"),
        ("bom8.txt", 1, "content"),
        ("crlf.txt", 2, "content"),
        ("latin1.txt", 3, "content"),
        ("nul.bin", 2, "content"),
        ("nul16.bin", 2, "content"),
        ("utf8.md", 2, "content"),
    ]
    # The line ending is not part of the line an exception's digest is taken of.
    crlf = [h for h in ng.scan_tree(tmp_path, ["crlf.txt"], denylist)]
    assert [h.text_sha256 for h in crlf] == [_sha("zorblat")]


def _lines_hit(text: str, denylist) -> list[int]:
    return [h.line for h in ng.scan_bytes("t", text.encode(), denylist)]


def test_names_split_across_a_line_break(denylist) -> None:
    prefixed = ng.parse_denylist("^frob\n")
    # A compound across the break, reported on its first line.
    assert _lines_hit("ok\nthe quux\nfrob gateway\n", denylist) == [2]
    assert _lines_hit("# the quux-\n# frob gateway\n", denylist) == [1]
    # A word hyphenated at the end of a line, the next line indented or commented.
    assert _lines_hit("the zorb-\nlat service\n", denylist) == [1]
    assert _lines_hit("the zorb-\n    # > lat service\n", denylist) == [1]
    assert _lines_hit("the zorb\u00ad\nlat\n", denylist) == [1]
    assert _lines_hit("the fr-\nobs\n", prefixed) == [1]
    assert _lines_hit("the un-\nxfrobbed\n", prefixed) == []
    assert _lines_hit("see the\nfrobs-\nx\n", prefixed) == [2]  # line 2 alone
    # A match within one line is not also reported on the line before it.
    assert _lines_hit("nothing\nzorblat\n", denylist) == [2]
    assert _lines_hit("quux\nquux frob\n", denylist) == [2]
    # No join across an empty line, without a hyphen, or in the wrong order.
    assert _lines_hit("quux\n\nfrob\n", denylist) == []
    assert _lines_hit("zorb\nlat\n", denylist) == []
    assert _lines_hit("frob\nquux\n", denylist) == []
    # The allowed word, hyphenated, is still the allowed word.
    assert _lines_hit("a zorblat-\nter\n", ng.parse_denylist("zorblatter\n!zorblatter\n")) == []
    # Closing quotes after the hyphen, opening quotes before the rest (string concatenation).
    assert _lines_hit('x = ("the zorb-"\n     "lat service")\n', denylist) == [1]
    assert _lines_hit("x = 'the zorb-'\n'lat'\n", denylist) == [1]
    assert _lines_hit("`the zorb-`\n`lat`\n", denylist) == [1]


def test_a_match_that_only_touches_the_join_is_not_a_split_name(denylist) -> None:
    # Joined, "see x" + "zorblat" holds the term, but it starts exactly at the join: it is
    # line 2's own, and line 1 is not reported.
    assert _lines_hit("see x-\nzorblat\n", denylist) == [2]
    assert _lines_hit("quux\nfrob-\nzorblat\n", denylist) == [1, 3]


def test_files_with_nul_bytes_are_also_read_as_utf8(tmp_path: Path, denylist) -> None:
    paths = [
        # Neither is a printable ASCII run of the whole name.
        _write(tmp_path, "zw.bin", b"\x00\x01\nok zor\xe2\x80\x8bblat\x00\n"),
        _write(tmp_path, "cyr.bin", "\x00\nz\u043erblat\x00".encode()),
        # Found as an ASCII run and as a UTF-8 line, reported once.
        _write(tmp_path, "both.bin", b"\x00\nzorblat\x00\n"),
        _write(tmp_path, "split.bin", b"\x00the quux\nfrob\x00"),
    ]
    assert _where(ng.scan_tree(tmp_path, paths, denylist)) == [
        ("both.bin", 2, "content"),
        ("cyr.bin", 2, "content"),
        ("split.bin", 1, "content"),
        ("zw.bin", 2, "content"),
    ]


def test_one_stray_byte_does_not_turn_off_normalisation(
    tmp_path: Path, denylist, monkeypatch, capsys
) -> None:
    # Not valid UTF-8 because of one Latin-1 byte, so read as Latin-1; it is read as UTF-8 with
    # the stray byte replaced too, where the zero-width space and the Cyrillic o are seen.
    data = b"caf\xe9\nok zor\xe2\x80\x8bblat\nz\xd0\xberblat\nclean\n"
    paths = [_write(tmp_path, "stray.txt", data)]
    assert _where(ng.scan_tree(tmp_path, paths, denylist)) == [
        ("stray.txt", 2, "content"),
        ("stray.txt", 3, "content"),
    ]
    code, out, _ = _run_cli(monkeypatch, capsys, ["text", "--label", "pr-body"], data)
    assert code == 1
    assert out.splitlines() == ["internal name: pr-body:2", "internal name: pr-body:3"]


def test_crafted_escapes_are_scanned_within_a_time_budget(denylist) -> None:
    # Nested percent, HTML and JSON escapes on every line, with a non-ASCII letter (so lines are
    # also checked accent-folded) and a trailing hyphen (so each pair is joined): the decoded
    # forms of a line and of a joined pair are capped, and long lines are not decoded.
    short = "\u00e9%252525&amp;amp;\\u0025 " * 4 + "-"
    long = "%25&amp;\\u0025" * 400
    data = ((short + "\n") * 2000 + (long + "\n") * 50 + "the zor%2562lat\n").encode()
    started = time.perf_counter()
    hits = ng.scan_bytes("crafted", data, denylist)
    assert time.perf_counter() - started < 10
    assert [h.line for h in hits] == [2051]
    # A line too long to decode is still checked as written.
    assert ng.line_matches("x" * ng.MAX_DECODED_LINE + " zorblat", denylist)
    assert not ng.line_matches("x" * ng.MAX_DECODED_LINE + " zor%62lat", denylist)


def test_decoded_forms_are_capped(monkeypatch, denylist) -> None:
    # Uncapped, this line has 20 decoded forms, and a pair of such lines 20 by 20 joins.
    crafted = "%252525 &amp;amp;amp; \\u005cu005cu0041 " * 4
    assert len(ng._variants(crafted)) == ng.MAX_VARIANTS
    assert ng._variants("x" * ng.MAX_DECODED_LINE + crafted) == [
        "x" * ng.MAX_DECODED_LINE + crafted
    ]
    made: list[int] = []
    real = ng._variants

    def counted(line: str, limit: int = ng.MAX_VARIANTS) -> list[str]:
        out = real(line, limit)
        made.append(len(out))
        return out

    monkeypatch.setattr(ng, "_variants", counted)
    assert not ng.lines_match_across(crafted + "-", crafted, denylist)
    assert made and max(made) == ng.MAX_JOIN_VARIANTS < ng.MAX_VARIANTS


def test_a_large_file_with_nul_bytes_is_scanned_quickly(denylist) -> None:
    # About 1 MB of short printable runs between NUL bytes, many lines: line numbers are found
    # by bisection, not by counting newlines from the start of the file for every run.
    data = b"abcde\x00\n" * 150_000 + b"zorblat\x00"
    started = time.perf_counter()
    hits = ng.scan_bytes("big.bin", data, denylist)
    assert time.perf_counter() - started < 5
    assert [h.line for h in hits] == [150_001]


def test_scan_tree_paths_symlinks_and_unreadable_files(tmp_path: Path, denylist) -> None:
    root = tmp_path / "root"
    outside = tmp_path / "outside.txt"
    outside.write_text("zorblat\n")  # a link is never followed
    paths = [
        _write(root, "docs/zorblat-notes.md", b"clean\n"),
        _write(root, "Quux_Frob/a.txt", b"clean\n"),
        _write(root, "Quux_Frob/b.txt", b"clean\n"),
        _write(root, "ok/zor%62lat.txt", b"clean\n"),
    ]
    (root / "link-out").symlink_to(outside)
    (root / "link-named").symlink_to("../zorblat-target")
    paths += ["link-out", "link-named", "gone.txt"]
    assert _where(ng.scan_tree(root, paths, denylist)) == [
        ("Quux_Frob", 0, "path"),
        ("docs/zorblat-notes.md", 0, "path"),
        ("gone.txt", 0, "unreadable"),
        ("link-named", 0, "symlink"),
        ("ok/zor%62lat.txt", 0, "path"),
    ]


def test_a_compound_split_between_directories(tmp_path: Path, denylist) -> None:
    paths = [
        _write(tmp_path, "quux/frob/a.txt", b"clean\n"),
        _write(tmp_path, "quux/other.txt", b"clean\n"),
        _write(tmp_path, "Quux_Frob/x/b.txt", b"clean\n"),
        _write(tmp_path, "a/quux/b/frob.txt", b"clean\n"),  # not adjacent: not a compound
    ]
    assert _where(ng.scan_tree(tmp_path, paths, denylist)) == [
        ("Quux_Frob", 0, "path"),
        ("quux/frob", 0, "path"),
    ]


_GIT_ENV = {
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_AUTHOR_NAME": "Ann Example",
    "GIT_AUTHOR_EMAIL": "ann@example.org",
    "GIT_COMMITTER_NAME": "Cid Example",
    "GIT_COMMITTER_EMAIL": "cid@example.org",
}


def _git(root: Path, *args: str, **env: str) -> str:
    out = subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        capture_output=True,
        env=os.environ | _GIT_ENV | env,
    )
    return out.stdout.decode()


def _commit(root: Path, message: str, **env: str) -> str:
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "--allow-empty", "-m", message, **env)
    return _git(root, "rev-parse", "HEAD").strip()


def test_files_in_git_lfs_are_reported(tmp_path: Path, denylist, monkeypatch, capsys) -> None:
    # Their content is not in the tree, so it cannot be scanned, but it is published.
    _git(tmp_path, "init", "-q")
    _write(tmp_path, ".gitattributes", b"*.bin filter=lfs diff=lfs merge=lfs -text\n")
    _write(tmp_path, "data/blob.bin", b"\x00\x01")
    pointer = b"version https://git-lfs.github.com/spec/v1\noid sha256:" + b"0" * 64 + b"\n"
    _write(tmp_path, "pointer.txt", pointer)
    _write(tmp_path, "ok.txt", b"clean\n")
    assert _where(ng.scan_repo(tmp_path, denylist)) == [
        ("data/blob.bin", 0, "lfs"),
        ("pointer.txt", 0, "lfs"),
    ]
    offending, _ = ng.check(ng.scan_repo(tmp_path, denylist))
    assert offending == ["data/blob.bin (lfs)", "pointer.txt (lfs)"]
    monkeypatch.setattr(ng, "TREE_EXCEPTIONS", frozenset())
    code, out, _ = _run_cli(monkeypatch, capsys, ["tree", str(tmp_path)])
    assert code == 1
    assert out.splitlines() == [
        "stored in Git LFS, cannot be scanned: data/blob.bin (lfs)",
        "stored in Git LFS, cannot be scanned: pointer.txt (lfs)",
    ]
    (tmp_path / ".gitattributes").unlink()
    (tmp_path / "pointer.txt").unlink()
    assert ng.scan_repo(tmp_path, denylist) == []


def _commit_hits(root: Path, revs: list[str], denylist, **kw) -> list[str]:
    return ng.check(ng.scan_commits(root, revs, denylist, **kw))[0]


def test_commits_messages_and_skipped_bodies(tmp_path: Path, denylist) -> None:
    _git(tmp_path, "init", "-q")
    base = _commit(tmp_path, "Start")
    bot = {"GIT_AUTHOR_NAME": "dependabot[bot]"}
    notes = _commit(tmp_path, "Bump a library\n\nUpstream notes: zorblat\n", **bot)
    subject = _commit(tmp_path, "Bump zorblat\n\nclean notes\n", **bot)
    person = _commit(tmp_path, "Fix a thing\n\nThe quux\nfrob path broke.\n")
    named = _commit(tmp_path, "Plain", GIT_COMMITTER_NAME="Zorblat Bot")
    revs = [f"{base}..HEAD"]
    skip = frozenset({"dependabot[bot]"})
    assert sorted(_commit_hits(tmp_path, revs, denylist)) == sorted(
        [
            f"commit {notes[:12]} message:6",
            f"commit {subject[:12]} message:5",
            f"commit {person[:12]} message:6",
            f"commit {named[:12]} message:3",
        ]
    )
    # A skipped body is only the body: the subject of the same author is still scanned.
    assert sorted(_commit_hits(tmp_path, revs, denylist, skip_bodies_of=skip)) == sorted(
        [
            f"commit {subject[:12]} message:5",
            f"commit {person[:12]} message:6",
            f"commit {named[:12]} message:3",
        ]
    )


def test_commits_added_lines_renames_empty_files_and_merges(tmp_path: Path, denylist) -> None:
    _git(tmp_path, "init", "-q", "-b", "main")
    _write(tmp_path, "old/zorblat.txt", b"the zorblat\n")
    _write(tmp_path, "a.txt", b"clean\n")
    base = _commit(tmp_path, "Start")
    (tmp_path / "new").mkdir()
    _git(tmp_path, "mv", "old/zorblat.txt", "new/zorblat.txt")  # a pure rename
    renamed = _commit(tmp_path, "Move")
    (tmp_path / "new" / "zorblat.txt").unlink()
    deleted = _commit(tmp_path, "Delete")
    _write(tmp_path, "empty/quux-frob", b"")
    empty = _commit(tmp_path, "Add an empty file")
    _write(tmp_path, "a.txt", b"clean\nmore\nzorblat\n")
    changed = _commit(tmp_path, "Change")
    assert (
        sorted(_commit_hits(tmp_path, [f"{base}..HEAD"], denylist))
        == sorted(
            [
                f"commit {renamed[:12]} diff:1",  # the +++ line names the path
                f"commit {renamed[:12]} diff:2",
                f"commit {renamed[:12]} paths:1",
                f"commit {empty[:12]} paths:1",
                f"commit {changed[:12]} diff:3",
            ]
        )
    )
    assert _commit_hits(tmp_path, [f"{deleted}^!"], denylist) == []  # deletions are not scanned
    # A merge commit's diff against its first parent: what the merge brings in.
    _git(tmp_path, "checkout", "-q", "-b", "side", base)
    _write(tmp_path, "side.txt", b"ok\nzorblat\n")
    _write(tmp_path, "side/quux.frob", b"")
    _commit(tmp_path, "Side")
    _git(tmp_path, "checkout", "-q", "main")
    _git(tmp_path, "merge", "-q", "--no-ff", "--no-edit", "side")
    merge = _git(tmp_path, "rev-parse", "HEAD").strip()
    assert _commit_hits(tmp_path, [f"{merge}^!"], denylist) == [
        f"commit {merge[:12]} diff:3",
        f"commit {merge[:12]} paths:2",  # after side.txt
    ]


def test_commits_lfs_pointers_are_reported(tmp_path: Path, denylist) -> None:
    _git(tmp_path, "init", "-q")
    base = _commit(tmp_path, "Start")
    _write(tmp_path, "p.bin", b"version https://git-lfs.github.com/spec/v1\nsize 1\n")
    added = _commit(tmp_path, "Add")
    assert _commit_hits(tmp_path, [f"{base}..{added}"], denylist) == [
        f"commit {added[:12]} diff (lfs)"
    ]


def test_commits_report_the_path_of_a_modified_file(tmp_path: Path, denylist) -> None:
    # A file that is changed, not added, still has its path published by the commit.
    _git(tmp_path, "init", "-q")
    _write(tmp_path, "docs/zorblat.txt", b"clean\n")
    base = _commit(tmp_path, "Start")
    _write(tmp_path, "docs/zorblat.txt", b"clean\nmore\n")
    changed = _commit(tmp_path, "Change")
    hits = _commit_hits(tmp_path, [f"{base}..{changed}"], denylist)
    assert f"commit {changed[:12]} paths:1" in hits


def test_list_paths_tracked_untracked_not_ignored_not_deleted(tmp_path: Path) -> None:
    # A repository of its own, so the result does not depend on where tmp_path lives.
    _git(tmp_path, "init", "-q")
    _write(tmp_path, ".gitignore", b"*.ignored\n")
    _write(tmp_path, "tracked.txt", b"x\n")
    _write(tmp_path, "deleted.txt", b"x\n")
    _write(tmp_path, "sub/new.txt", b"x\n")
    _write(tmp_path, "skip.ignored", b"x\n")
    _git(tmp_path, "add", ".gitignore", "tracked.txt", "deleted.txt")
    (tmp_path / "deleted.txt").unlink()
    assert ng.list_paths(tmp_path) == [".gitignore", "sub/new.txt", "tracked.txt"]


def test_list_paths_fails_outside_a_work_tree(tmp_path: Path, monkeypatch) -> None:
    plain = tmp_path / "plain"
    plain.mkdir()
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))  # whatever encloses tmp_path
    with pytest.raises(subprocess.CalledProcessError):
        ng.list_paths(plain)


# --- reports and exceptions -------------------------------------------------------------------


def _sha(line: str) -> str:
    return hashlib.sha256(line.encode()).hexdigest()


def test_report_names_where_and_never_quotes_the_line(tmp_path: Path, denylist) -> None:
    # A hit in a name necessarily shows that path; a hit in contents shows only path:line.
    paths = [
        _write(tmp_path, "a/zorblat.txt", b"ok\nthe Quux-Frob gateway\n"),
        _write(tmp_path, "b.txt", "x\ny\nz\u043erblat\n".encode()),
    ]
    offending, stale = ng.check(ng.scan_tree(tmp_path, paths, denylist))
    assert offending == ["a/zorblat.txt (path)", "a/zorblat.txt:2", "b.txt:3"]
    assert stale == []


def test_content_hits_never_show_a_term(tmp_path: Path, denylist) -> None:
    paths = [_write(tmp_path, "c.txt", b"ok\nquux frob and zorblat\n")]
    offending, _ = ng.check(ng.scan_tree(tmp_path, paths, denylist))
    assert offending == ["c.txt:2"]
    for text in offending:
        assert not any(term in text.lower() for term in TERMS)


def test_exceptions_match_exactly_and_stale_ones_are_reported(tmp_path: Path, denylist) -> None:
    line = "# a long comment in a merged revision that mentions zorblat once"
    paths = [_write(tmp_path, "m.py", f"x = 1\n{line}\n{line}\n".encode())]
    hits = ng.scan_tree(tmp_path, paths, denylist)
    assert ng.check(hits, frozenset({("m.py", 2, _sha(line)), ("m.py", 3, _sha(line))})) == (
        [],
        [],
    )
    # Line 3 not excepted; an exception for a moved line, and one whose text changed, are stale.
    offending, stale = ng.check(
        hits,
        frozenset({("m.py", 2, _sha(line)), ("m.py", 1, _sha(line)), ("m.py", 3, _sha("x"))}),
    )
    assert offending == ["m.py:3"]
    assert stale == ["m.py:1", "m.py:3"]


# --- the command line -------------------------------------------------------------------------


def _run_cli(monkeypatch, capsys, argv: list[str], stdin: bytes = b"", env: str | None = SYNTHETIC):
    monkeypatch.delenv(ng.ENV_FILE, raising=False)
    if env is None:
        monkeypatch.delenv(ng.ENV_TEXT, raising=False)
    else:
        monkeypatch.setenv(ng.ENV_TEXT, env)
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(stdin)))
    code = ng.main(argv)
    out, err = capsys.readouterr()
    return code, out, err


def test_cli_text_reports_label_and_line_only(monkeypatch, capsys) -> None:
    message = b"Fix the parser\n\nThe quux-frob path broke.\nTouches Zorblat too.\n"
    code, out, err = _run_cli(monkeypatch, capsys, ["text", "--label", "commits"], message)
    assert code == 1
    assert out.splitlines() == ["internal name: commits:3", "internal name: commits:4"]
    assert not any(term in (out + err).lower() for term in TERMS)
    code, out, _ = _run_cli(monkeypatch, capsys, ["text"], b"Fix the parser\n")
    assert (code, out) == (0, "")


def test_cli_fails_closed_without_a_list(monkeypatch, capsys) -> None:
    for env in (None, "", "# comments only\n"):
        code, out, err = _run_cli(monkeypatch, capsys, ["text"], b"zorblat\n", env=env)
        assert code == 2 and out == ""
        assert ng.ENV_TEXT in err or "no entries" in err


def test_cli_commits(monkeypatch, capsys, tmp_path: Path) -> None:
    _git(tmp_path, "init", "-q")
    base = _commit(tmp_path, "Start")
    _write(tmp_path, "a.txt", b"clean\nzorblat\n")
    head = _commit(tmp_path, "Add")
    root = ["--root", str(tmp_path)]
    assert _run_cli(monkeypatch, capsys, ["commits", *root, f"{base}^!"])[:2] == (0, "")
    code, out, _ = _run_cli(monkeypatch, capsys, ["commits", *root, f"{base}..{head}"])
    assert (code, out) == (1, f"internal name: commit {head[:12]} diff:3\n")
    # An option where a revision belongs is a revision git cannot find, not an option.
    code, out, err = _run_cli(monkeypatch, capsys, ["commits", *root, "--", "--all"])
    assert (code, out) == (2, "") and "git failed" in err


def test_cli_tree(monkeypatch, capsys, tmp_path: Path) -> None:
    _git(tmp_path, "init", "-q")
    _write(tmp_path, "ok.txt", b"clean\n")
    monkeypatch.setattr(ng, "TREE_EXCEPTIONS", frozenset())
    assert _run_cli(monkeypatch, capsys, ["tree", str(tmp_path)])[:2] == (0, "")
    _write(tmp_path, "new.txt", b"clean\nzorblat\n")
    code, out, _ = _run_cli(monkeypatch, capsys, ["tree", str(tmp_path)])
    assert (code, out) == (1, "internal name: new.txt:2\n")


# --- the pre-push hook ------------------------------------------------------------------------


def _hooked_clone(tmp_path: Path) -> tuple[Path, Path]:
    """A bare remote and a clone of it with ``scripts/pre-push`` installed as ADR 0013 says.
    The scripts are copied in and excluded, so they are neither committed nor scanned; the
    copied scanner has no exceptions, since this repository's migrations are not there."""
    remote, work = tmp_path / "remote.git", tmp_path / "work"
    _git(tmp_path, "init", "-q", "--bare", "-b", "main", str(remote))
    _git(tmp_path, "clone", "-q", str(remote), str(work))
    _git(work, "checkout", "-q", "-b", "main")
    (work / "scripts").mkdir()
    scanner = (REPO_ROOT / "scripts" / "name_guard.py").read_text()
    main = 'if __name__ == "__main__":'
    assert scanner.count(main) == 1
    scanner = scanner.replace(main, f"TREE_EXCEPTIONS = frozenset()\n\n\n{main}")
    (work / "scripts" / "name_guard.py").write_text(scanner)
    shutil.copy2(REPO_ROOT / "scripts" / "pre-push", work / "scripts")
    (work / ".git" / "info" / "exclude").write_text("/scripts/\n")
    (work / ".git" / "hooks" / "pre-push").symlink_to("../../scripts/pre-push")
    return remote, work


def _push(work: Path, *args: str, denylist: str | None = SYNTHETIC) -> tuple[int, str]:
    env = {k: v for k, v in (os.environ | _GIT_ENV).items() if k not in (ng.ENV_TEXT, ng.ENV_FILE)}
    if denylist is not None:
        env[ng.ENV_TEXT] = denylist
    run = subprocess.run(
        ["git", "-C", str(work), "push", "-q", *args], capture_output=True, env=env
    )
    out = (run.stdout + run.stderr).decode()
    hook_lines = [line for line in out.splitlines() if line.startswith("internal name: ")]
    assert not any(term in "\n".join(hook_lines).lower() for term in TERMS)
    return run.returncode, out


def test_pre_push_new_branch(tmp_path: Path) -> None:
    _, work = _hooked_clone(tmp_path)
    _write(work, "a.txt", b"clean\n")
    _commit(work, "Start")
    assert _push(work, "origin", "main")[0] == 0
    _git(work, "checkout", "-q", "-b", "feature")
    _write(work, "b.txt", b"ok\nzorblat\n")
    bad = _commit(work, "Add b")
    code, out = _push(work, "origin", "feature")
    assert code != 0 and f"internal name: commit {bad[:12]} diff:" in out
    _write(work, "b.txt", b"ok\n")
    _git(work, "add", "-A")
    _git(work, "commit", "-q", "--amend", "-m", "Add b")
    assert _push(work, "origin", "feature")[0] == 0
    _write(work, "c.txt", b"ok\n")
    _commit(work, "Add c")
    assert _push(work, "origin", "feature", denylist=None)[0] != 0  # no list, no push


def test_pre_push_already_public_history_does_not_refuse(tmp_path: Path) -> None:
    # The remote's main holds a commit that added a name and one that removed it again: public
    # history from before the guard. A branch created before them, brought up to date with main
    # and pushed, sends that range again, which must not refuse the push.
    remote, work = _hooked_clone(tmp_path)
    _write(work, "a.txt", b"clean\n")
    _commit(work, "Start")
    assert _push(work, "origin", "main")[0] == 0
    _git(work, "checkout", "-q", "-b", "old")
    _write(work, "o.txt", b"old work\n")
    _commit(work, "Old work")
    assert _push(work, "origin", "old")[0] == 0
    _git(work, "checkout", "-q", "main")
    _write(work, "b.txt", b"the zorblat\n")
    _commit(work, "Add b")
    _write(work, "b.txt", b"the gateway\n")
    _commit(work, "Generalise b")
    assert _push(work, "--no-verify", "origin", "main")[0] == 0
    _git(work, "checkout", "-q", "old")
    _git(work, "merge", "-q", "--no-ff", "--no-edit", "main")
    _write(work, "o.txt", b"old work, updated\n")
    _commit(work, "Update old work")
    assert _push(work, "origin", "old") == (0, "")
    # The same to a URL, with no remote name: every remote-tracking ref counts as public.
    assert _push(work, str(remote), "old:refs/heads/copy")[0] == 0
    _write(work, "o.txt", b"old work\nquux frob\n")
    bad = _commit(work, "Bad")
    for target in ("origin", str(remote)):
        code, out = _push(work, target, "old")
        assert code != 0 and f"internal name: commit {bad[:12]} diff:" in out
        assert out.count("internal name: commit ") == 1  # the public commits are not reported
        assert "internal name: o.txt:2" in out  # and the work tree is scanned too


def test_pre_push_excludes_the_old_value_of_the_ref(tmp_path: Path) -> None:
    # Public history that no remote-tracking ref holds (one deleted, or never fetched) is still
    # excluded when it is the old value of the ref being pushed.
    _, work = _hooked_clone(tmp_path)
    _write(work, "a.txt", b"the zorblat\n")
    _commit(work, "Start")
    _write(work, "a.txt", b"the gateway\n")
    _commit(work, "Generalise a")
    assert _push(work, "--no-verify", "origin", "main")[0] == 0
    _git(work, "update-ref", "-d", "refs/remotes/origin/main")
    _write(work, "b.txt", b"ok\n")
    _commit(work, "Add b")
    assert _push(work, "origin", "main") == (0, "")


def test_pre_push_deleting_a_ref_is_not_checked(tmp_path: Path) -> None:
    _, work = _hooked_clone(tmp_path)
    _commit(work, "Start")
    assert _push(work, "--no-verify", "origin", "main", "main:refs/heads/zorblat-x")[0] == 0
    assert _push(work, "origin", "--delete", "zorblat-x") == (0, "")


def test_pre_push_annotated_tags(tmp_path: Path) -> None:
    _, work = _hooked_clone(tmp_path)
    _commit(work, "Start")
    assert _push(work, "origin", "main")[0] == 0
    _git(work, "tag", "-a", "v1", "-m", "Release\n\nFor the zorblat cluster.")
    code, out = _push(work, "origin", "v1")
    assert code != 0 and "internal name: tag:" in out
    _git(work, "tag", "-a", "v2", "-m", "Release", GIT_COMMITTER_NAME="Quux Frob")
    code, out = _push(work, "origin", "v2")
    assert code != 0 and "internal name: tag:" in out
    _git(work, "tag", "-a", "v3", "-m", "Release")
    _git(work, "tag", "-a", "v3-signed-off", "-m", "Release of v3", "v3")  # a tag of a tag
    assert _push(work, "origin", "v3", "v3-signed-off") == (0, "")
    # The tag a pushed tag points at is published with it, though no pushed ref names it.
    _git(work, "tag", "-a", "v4", "-m", "Zorblat release")
    _git(work, "tag", "-a", "v4-again", "-m", "Release of v4", "v4")
    code, out = _push(work, "origin", "v4-again")
    assert code != 0 and out.count("internal name: tag:") == 1


def test_pre_push_ref_names(tmp_path: Path) -> None:
    _, work = _hooked_clone(tmp_path)
    _commit(work, "Start")
    assert _push(work, "origin", "main")[0] == 0
    for ref in ("refs/heads/fix-zorblat", "refs/heads/QuuxFrob", "refs/tags/zorblat-1"):
        code, out = _push(work, "origin", f"main:{ref}")
        assert code != 0 and "internal name: ref:1" in out
    assert _push(work, "origin", "main:refs/heads/fix-gateway") == (0, "")
